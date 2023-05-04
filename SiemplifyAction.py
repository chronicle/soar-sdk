import json
import sys
import signal
from SiemplifyDataModel import CyberCase, InsightSeverity, InsightType, CustomList
from SiemplifyLogger import ActionsFileLogsCollector
from ScriptResult import ScriptResult, EXECUTION_STATE_FAILED
from Siemplify import Siemplify, INSIGHT_DEFAULT_THREAT_SOURCE
import SiemplifyUtils
from SiemplifyUtils import unix_now, extract_script_param, is_python_37, is_old_entities_format, is_json_result_size_valid
from SiemplifyBase import SiemplifyBase

# CONSTS
LOG_LOCATION = "SDK_Actions"
CASE_DATA_FILE = 'case_data.json'
SIGNAL_CODES = {signal.SIGTERM: 143, signal.SIGINT: 130}


class SiemplifyAction(Siemplify):

    def __init__(self, mock_stdin = None, get_source_file = False):
        super(SiemplifyAction, self).__init__()
        self._case = None
        self._current_alert = None
        self._target_entities = None
        self.get_source_file = get_source_file
        if is_python_37():
            raw_context_data = mock_stdin if mock_stdin else sys.stdin.buffer.read()
        else:
            raw_context_data = mock_stdin if mock_stdin else sys.stdin.read()

        if not mock_stdin:
            self.context_data = json.loads(raw_context_data.decode("utf-8-sig"))
        else:
            self.context_data = json.loads(raw_context_data)

        # Deserialize entity id and type
        if is_old_entities_format(self.context_data['target_entities']):
            self.target_entity_ids = self.context_data['target_entities']
            self.support_old_entities = True
        else:
            self.target_entity_ids = [(entity["item1"], entity["item2"]) for entity in self.context_data['target_entities']]
            self.support_old_entities = False

        self._result = ScriptResult(self.target_entity_ids, self.support_old_entities)
        self.case_id = self.context_data['case_id']
        self.alert_id = self.context_data['alert_id']
        self._environment = self.context_data['environment']
        self.workflow_id = self.context_data['workflow_id']
        self.parameters = self._fix_parameters(self.context_data['parameters'])
        self.integration_identifier = self.context_data['integration_identifier']
        self.integration_instance = self.context_data['integration_instance']
        self.action_definition_name = self.context_data['action_definition_name']
        self.original_requesting_user = self.context_data['original_requesting_user']
        self.execution_deadline_unix_time_ms = self.context_data.get('execution_deadline_unix_time_ms', 0)
        self.async_polling_interval_in_sec = self.context_data.get('async_polling_interval_in_sec', 0)
        self.async_total_duration_deadline = self.context_data.get('async_total_duration_deadline', 0)
        self.script_timeout_deadline = self.context_data.get('script_timeout_deadline', self.execution_deadline_unix_time_ms)
        self.default_result_value = self.context_data['default_result_value']
        self.use_proxy_settings = self.context_data.get('use_proxy_settings', False)
        self.max_json_result_size = self.context_data.get('max_json_result_size', 15)
        self.vault_settings = self.context_data.get('vault_settings', None)
    
        if self.use_proxy_settings and not self.sdk_config.is_remote_publisher_sdk:
            self.init_proxy_settings()

        if self.sdk_config.is_remote_publisher_sdk:
            self.set_logs_collector(
                ActionsFileLogsCollector(
                    self.sdk_config.run_folder_path,
                    self.context_data
                )
            )

        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    @property
    def is_timeout_reached(self):
        if not self.execution_deadline_unix_time_ms:
            raise Exception("execution_deadline_unix_time_ms is None")

        is_timeout_reached = unix_now() >= self.execution_deadline_unix_time_ms
        return is_timeout_reached

    @property
    def log_location(self):
        return LOG_LOCATION

    def _get_case(self, get_source_file=False):
        """
        get case object
        :return: {dict} case data
        """
        # Publisher mode load directly case data file
        if self.is_remote:
            return json.loads(open(CASE_DATA_FILE, 'r').read())
        return self._get_case_by_id(self.case_id, get_source_file)

    def _load_current_alert(self):
        for alert in self.case.alerts:
            if alert.identifier == self.alert_id:
                self._current_alert = alert
                return
        self._current_alert = None

    def _load_target_entities(self):
        """
        load target entities
        if in alert context - run only on alert entities. if not - run on all case entities.
        :return: {dict} target_entities
        """
        target_entities = {}
        all_entities = []

        if self.current_alert == None:
            #no current alert context
            all_entities = [entity for alert in self.case.alerts for entity in alert.entities]
        else:
            #current alert context
            all_entities = self.current_alert.entities
        
        if not self.support_old_entities:
            for entity in all_entities:
                if (entity.identifier, entity.entity_type) in self.target_entity_ids and (entity.identifier, entity.entity_type) not in target_entities:
                    target_entities[(entity.identifier, entity.entity_type)] = entity
        else:
             for entity in all_entities:
                if entity.identifier in self.target_entity_ids and entity.identifier not in target_entities:
                    target_entities[entity.identifier] = entity
                    
        self._target_entities = list(target_entities.values())

    @property
    def environment(self):
        if self.case_id is not None and int(self.case_id) > 0:
            return self.case.environment

        return self._environment

    @property
    def case(self):
        if not self._case:
            self.load_case_data()
        return self._case

    @property
    def current_alert(self):
        if not self._current_alert:
            self.load_case_data()
        return self._current_alert

    @property
    def target_entities(self):
        if not self._target_entities:
            self.load_case_data()
        return self._target_entities

    def load_case_data(self):
        """
        load case data
        """
        case_json = self._get_case(self.get_source_file)
        self._case = CyberCase(**case_json)
        self._load_current_alert()
        self._load_target_entities()

    def add_attachment(self, file_path, case_id=None, alert_identifier=None, description=None, is_favorite=False):
        """
        add attachment
        :param file_path: {string} file path
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        :param description: {string} attachment description
        :param is_favorite: {boolean} is attachment favorite
        :return: {dict} attachment_id
        """
        return super(SiemplifyAction, self).add_attachment(file_path, self.case_id, self.alert_id,
                                                           description=None, is_favorite=False)

    def get_attachments(self, case_id=None):
        """
        get attachments from case
        :param case_id: {string} case identifier
        :return: {dict} attachments
        """
        return super(SiemplifyAction, self).get_attachments(self.case_id)

    def assign_case(self, user, case_id=None, alert_identifier=None):
        """
        Assign case to user
        :param user: {string} user/role (e.g. Admin, @Tier1)
        :param case_id: {string} case identifier
        :param alert_identifier:
        """
        return super(SiemplifyAction, self).assign_case(user, case_id or self.case_id, alert_identifier or self.alert_id)

    def add_comment(self, comment, case_id=None, alert_identifier=None):
        """
        Add new comment to specific case
        :param comment: {string} comment to be added to case wall
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        return super(SiemplifyAction, self).add_comment(comment, case_id or self.case_id, alert_identifier or self.alert_id)

    def add_tag(self, tag, case_id=None, alert_identifier=None):
        """
        Add new tag to specific case
        :param tag: {string} tag to be added
        :param case_id: {string} case identifier
        :param alert_identifier: alert identifier
        :return:
        """
        return super(SiemplifyAction, self).add_tag(tag, case_id or self.case_id, alert_identifier or self.alert_id)

    def attach_workflow_to_case(self, workflow_name, cyber_case_id=None, indicator_identifier=None):
        """
        attach workflow to case
        :param workflow_name: {string} workflow name
        :param cyber_case_id: {string} case identifier
        :param indicator_identifier: {string} alert_identifier
        """
        return super(SiemplifyAction, self).attach_workflow_to_case(workflow_name, self.case_id,
                                                                    self.alert_id)

    def get_similar_cases(self,
                          consider_ports,
                          consider_category_outcome,
                          consider_rule_generator,
                          consider_entity_identifiers,
                          days_to_look_back, case_id=None, end_time_unix_ms=None):

        """
        get similar cases
        :param case_id: {string} case identifier
        :param consider_ports: {boolean} true/false use port filter
        :param consider_category_outcome:  {boolean} true/false use category_outcome filter
        :param consider_rule_generator:  {boolean} true/false use rule_generator filter
        :param consider_entity_identifiers: {boolean} true/false use entity_identifiers filter
        :param days_to_look_back: {int} e.g. 365
        :param end_time_unix_ms
        :return: {dict}
        """
        current_alert = self.current_alert
        ports_filter = []
        category_outcome_filter = []
        rule_generator_filter = []
        entity_identifiers_filter = []

        for relation in current_alert.relations:
            if str(consider_ports) == "True":
                ports_filter.append(relation.destination_port)
            if str(consider_category_outcome) == "True":
                category_outcome_filter.append(relation.category_outcome)

        if str(consider_rule_generator) == "True":
            rule_generator_filter.append(current_alert.rule_generator)

        if str(consider_entity_identifiers) == "True":
            for entity in self.target_entities:
                if entity.entity_type != "ALERT":
                    entity_identifiers_filter.append(entity.identifier)

        end_time_unix_ms = current_alert.detected_time
        start_time_unix_ms = end_time_unix_ms - int(days_to_look_back) * 24 * 60 * 60 * 1000
        return super(SiemplifyAction, self).get_similar_cases(self.case_id,
                                                              ports_filter,
                                                              category_outcome_filter,
                                                              rule_generator_filter,
                                                              entity_identifiers_filter,
                                                              str(start_time_unix_ms),
                                                              str(end_time_unix_ms))

    def get_ticket_ids_for_alerts_dismissed_since_timestamp(self, timestamp_unix_ms):
        """
        Not supported
        get ticket ids for alerts dismissed since timestamp
        :param timestamp_unix_ms: {long} (e.g. 1550409785000L)
        :return: {list} alerts
        """
        return super(SiemplifyAction, self).get_ticket_ids_for_alerts_dismissed_since_timestamp(timestamp_unix_ms)

    def get_alerts_ticket_ids_from_cases_closed_since_timestamp(self, timestamp_unix_ms, rule_generator):
        """
        Get alerts from cases that were closed since timestamp
        :param timestamp_unix_ms: {long} (e.g. 1550409785000L)
        :param rule_generator: {string} (e.g. 'Phishing email detector')
        :return: {list} alerts
        """
        return super(SiemplifyAction, self).get_alerts_ticket_ids_from_cases_closed_since_timestamp(timestamp_unix_ms,
                                                                                                    rule_generator)

    def change_case_stage(self, stage, case_id=None, alert_identifier=None):
        """
        Change case stage
        :param stage: {string} (e.g. Incident)
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        return super(SiemplifyAction, self).change_case_stage(stage, self.case_id, self.alert_id)

    def change_case_priority(self, priority, case_id=None, alert_identifier=None):
        """
        Change case priority
        :param priority: {int} {"Low": 40, "Medium": 60, "High": 80, "Critical": 100}
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        return super(SiemplifyAction, self).change_case_priority(priority, self.case_id, self.alert_id)

    def close_case(self, root_cause, comment, reason, case_id=None, alert_identifier=None):
        """
        Close case
        :param root_cause: {string} close case root cause
        :param comment: {string} comment
        :param reason: {string} close case reason
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        return super(SiemplifyAction, self).close_case(root_cause, comment, reason, self.case_id,
                                                       self.alert_id)

    def dismiss_alert(self, alert_group_identifier, should_close_case_if_all_alerts_were_dismissed, case_id=None):
        # Not supported
        return super(SiemplifyAction, self).dismiss_alert(alert_group_identifier,
                                                          should_close_case_if_all_alerts_were_dismissed, self.case_id)

    def close_alert(self, root_cause, comment, reason, case_id=None, alert_id=None):
        """
        close alert
        :param root_cause: {string} close case root cause
        :param comment: {string} comment
        :param reason: {string} close case reason
        :param case_id: {string} case identifier
        :param alert_id: {string} alert identifier
        """
        return super(SiemplifyAction, self).close_alert(root_cause, comment, reason, self.case_id,
                                                        self.alert_id)

    def add_entity_insight(self, domain_entity_info, message, triggered_by=None, original_requesting_user=None):
        """
        add insight
        :param domain_entity_info: {entity}
        :param message: {string} insight message
        :param triggered_by: {string} integration name
        :param original_requesting_user: {string}
        :return: {boolean} True if success
        """
        if not triggered_by:
            if "ThreatSource" in domain_entity_info.additional_properties:
                triggered_by = domain_entity_info.additional_properties["ThreatSource"]
            elif self.integration_identifier:
                triggered_by = self.integration_identifier
            else:
                triggered_by = INSIGHT_DEFAULT_THREAT_SOURCE
        return super(SiemplifyAction, self).create_case_insight_internal(self.case_id,
                                                                         self.alert_id if self.current_alert else None,
                                                                         triggered_by, "Entity insight", message,
                                                                         domain_entity_info.identifier,
                                                                         InsightSeverity.WARN, InsightType.Entity,
                                                                         original_requesting_user=original_requesting_user,
                                                                         entity_type=domain_entity_info.entity_type)

    def escalate_case(self, comment, case_id=None, alert_identifier=None):
        """
        escalate case
        :param comment: {string} escalate comment
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        return super(SiemplifyAction, self).escalate_case(comment, self.case_id, self.alert_id)

    def mark_case_as_important(self, case_id=None, alert_identifier=None):
        """
        mark case as important
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        return super(SiemplifyAction, self).mark_case_as_important(self.case_id, self.alert_id)

    def get_case_context_property(self, property_key):
        return super(SiemplifyAction, self).get_context_property(1, self.case_id, property_key)

    def set_case_context_property(self, property_key, property_value):
        return super(SiemplifyAction, self).set_context_property(1, self.case_id, property_key,property_value)

    def try_set_case_context_property(self, property_key, property_value):
        return super(SiemplifyAction, self).try_set_context_property(1, self.case_id, property_key,property_value)


    def get_alert_context_property(self, property_key):
        return super(SiemplifyAction, self).get_context_property(2, self.current_alert.alert_group_identifier, property_key)

    def set_alert_context_property(self, property_key, property_value):
        return super(SiemplifyAction, self).set_context_property(2, self.current_alert.alert_group_identifier, property_key,property_value)
    
    def try_set_alert_context_property(self, property_key, property_value):
        return super(SiemplifyAction, self).try_set_context_property(2, self.current_alert.alert_group_identifier, property_key,property_value)
        
    def save_timestamp(self, datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now()):
        return super(SiemplifyAction, self).save_timestamp(datetime_format, timezone, new_timestamp, 2, self.current_alert.alert_group_identifier)
            
    def fetch_timestamp(self, datetime_format=False, timezone=False):
        return super(SiemplifyAction, self).fetch_timestamp(datetime_format, timezone, 2, self.current_alert.alert_group_identifier)
    
    def fetch_and_save_timestamp(self, datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now()):
        last_run_time = self.fetch_timestamp(datetime_format=False, timezone=False)
        self.save_timestamp(datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now())
        return last_run_time



    def raise_incident(self, case_id=None, alert_identifier=None):
        """
        raise incident
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        return super(SiemplifyAction, self).raise_incident(self.case_id, self.alert_id)

    def add_entity_to_case(self, entity_identifier, entity_type, is_internal, is_suspicous, is_enriched, is_vulnerable,
                           properties, case_id=None, alert_identifier=None, environment=None):
        """
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        :param entity_identifier: {string} entity identifier (1.1.1.1, google.com)
        :param entity_type: {string} "ADDRESS"
        :param is_internal: {boolean} internal/external
        :param is_suspicous: {boolean} suspicous/not suspicous
        :param is_enriched: {boolean} default is false
        :param is_vulnerable: {boolean} default is false
        :param properties: {dict}
        :param environment: {string}
        """
        if not self.current_alert:
            raise Exception("Cannot Create Entity without given alert identifier.")

        return super(SiemplifyAction, self).add_entity_to_case(self.case_id, self.alert_id,
                                                               entity_identifier, entity_type, is_internal,
                                                               is_suspicous, is_enriched, is_vulnerable, properties,
                                                               self.case.environment)

    def get_case_comments(self, case_id=None):
        """
        get case comments
        :param case_id: {string} case identifier
        :return:
        """
        return super(SiemplifyAction, self).get_case_comments(self.case_id)

    # dictionary of indicatorIdentifier - string data
    def update_alerts_additional_data(self, alerts_additional_data, case_id=None):
        """
        update alerts additional data
        :param case_id: {string} case identifier
        :param alerts_additional_data: {dict}
        """
        return super(SiemplifyAction, self).update_alerts_additional_data(self.case_id, alerts_additional_data)

    def create_case_insight(self, triggered_by, title, content, entity_identifier, severity, insight_type,
                            additional_data=None,
                            additional_data_type=None, additional_data_title=None):
        """
        add insight
        :param triggered_by: {string} integration name
        :param title: {string} insight title
        :param content: {string} insight message
        :param entity_identifier: {string} entity identifier
        :param severity: {int}  0=info, 1 = warning, 2 = error
        :param insight_type: {int} 0 = general, 1 = Entity
        :param additional_data:
        :param additional_data_type:
        :param additional_data_title:
        :return: {boolean} True if success
        """
        return super(SiemplifyAction, self).create_case_insight_internal(self.case_id, self.alert_id,
                                                                         triggered_by, title, content,
                                                                         entity_identifier, severity, insight_type,
                                                                         additional_data, additional_data_type,
                                                                         additional_data_title)

    def get_configuration(self, provider, environment=None, integration_instance=None):
        """
        Get integration configuration
        :param provider: {string} integration name (e.g. "VirusTotal")
        :param environment: {string} configuration for specific environment or 'all'
        :param integration_instance: {string} the identifier of the integration instance.
        :return: {dict} configuration details
        """
        return super(SiemplifyAction, self).get_configuration(provider, self.environment, self.integration_instance)

    def _get_custom_list_items(self, category_name, entities):
        """
        Get a list of custom list items from category and entities list.
        :param category_name: the custom list category
        :param entities: a list of entities
        :return: a list of custom list item objects
        """

        custom_list_items = []
        for entity in entities:
            custom_list_items.append(
                CustomList(identifier=entity.identifier, category=category_name, environment=self.environment))
        return custom_list_items

    def any_alert_entities_in_custom_list(self, category_name):
        """
        Check if any of the alert's entities has a custom list record
        with the given category.
        :param category_name: the custom list category
        :return: True if there is, false otherwise
        """

        custom_list_items = self._get_custom_list_items(category_name, self.target_entities)
        return self.any_entity_in_custom_list(custom_list_items)

    def add_alert_entities_to_custom_list(self, category_name):
        """
        Add the alert's entities to the custom list record
        with the given category.
        :param category_name: the custom list category
        :return: list of the added objects
        """

        custom_list_items = self._get_custom_list_items(category_name, self.target_entities)
        return self.add_entities_to_custom_list(custom_list_items)

    def remove_alert_entities_from_custom_list(self, category_name):
        """
        Remove the alert's entities to the custom list record
        with the given category.
        :param category_name: the custom list category
        :return: list of the removed objects
        """

        custom_list_items = self._get_custom_list_items(category_name, self.target_entities)
        return self.remove_entities_from_custom_list(custom_list_items)

    def extract_action_param(self, param_name, default_value=None, input_type=str, is_mandatory=False, print_value=False):
        return extract_script_param(siemplify=self,
                                    input_dictionary=self.parameters,
                                    param_name=param_name,
                                    default_value=default_value,
                                    input_type=input_type,
                                    is_mandatory=is_mandatory,
                                    print_value=print_value)
                                    
                                    
    def _build_output_object(self):
            """
            This method is override of _build_output_object in Siemplify.py which does not contain handling of max_json_result_size
            Kept for backwards compatibility with old scripts
            """
            if self.result.support_old_entities:
                result = self.result._result_object
            else:
                result = self._remap_keys(self.result._result_object)
            if not is_json_result_size_valid(json.dumps(result), self.max_json_result_size):
                error_output = "Action failed as JSON result exceeded maximum size {}MB".format(self.max_json_result_size)
                output_object = {"Message": error_output,
                                            "ResultObjectJson": None,
                                            "ResultValue": None,
                                            "DebugOutput": error_output,
                                            "ExecutionState": EXECUTION_STATE_FAILED}
            else:
                output_object = {"Message": self.result.message,
                                "ResultObjectJson": json.dumps(result),
                                "ResultValue": self.result.result_value,
                                "DebugOutput": SiemplifyUtils.my_stdout.getvalue(),
                                "ExecutionState": self.result.execution_state}
            return output_object


    def signal_handler(self, sig, frame):
        self.remove_temp_folder()        
        sys.exit(-SIGNAL_CODES[sig])

    def set_case_sla(self, period_time, period_type, critical_period_time, critical_period_type, case_id = None):
        """
        Sets the SLA of the given @case_id if given, otherwise sets the SLA of the current case. SLA being set using
        this API should surpass all other case SLA types.
        :param period_time: {int/string} Represents the total SLA period. period_time > 0.
        :param period_type: {string} Represents the time units of @period_time, represented by ApiPeriodTypeEnum.
        :param critical_period_time: {int/string} Represents the critical SLA period. critical_period_time > 0.
        : Critical period (after scaling with its time units) should be smaller than the total period.
        :param critical_period_type: {string} Represents the time units of @critical_period_time, represented by
        : ApiPeriodTypeEnum.
        :param case_id: {long}
        """
        return super(SiemplifyAction, self).set_case_sla(
                                                period_time,
                                                period_type,
                                                critical_period_time,
                                                critical_period_type,
                                                case_id or self.case_id
        )
        
        
    def set_alert_sla(self, period_time, period_type, critical_period_time, critical_period_type, case_id = None, alert_id = None):
        """
        Sets the SLA of the given @alert_identifier of @case_id. SLA being set using this API should surpass all other alert SLA types.
        :param period_time: {int/str} Represents the total SLA period. period_time > 0.
        :param period_type: {str} Represents the time units of @period_time, represented by ApiPeriodTypeEnum.
        :param critical_period_time: {int/str} Represents the critical SLA period. critical_period_time >= 0.
        : Critical period (after scaling with its time units) should be smaller than the total period.
        :param critical_period_type: {str} Represents the time units of @critical_period_time, represented by
        : ApiPeriodTypeEnum.
        :param case_id: {long}
        :param alert_id: {str}
        """
        return super(SiemplifyAction, self).set_alert_sla(
                                                period_time,
                                                period_type,
                                                critical_period_time,
                                                critical_period_type,
                                                case_id or self.case_id,
                                                alert_id or self.alert_id
        )
