# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import base64
import logging
import os

import SiemplifyUtils

logger = logging.getLogger("simple_example")


class EntityTypes:
    ALERT = "ALERT"
    HOSTNAME = "HOSTNAME"
    USER = "USERUNIQNAME"
    ADDRESS = "ADDRESS"
    MACADDRESS = "MacAddress"
    PROCESS = "PROCESS"
    PARENTPROCESS = "PARENTPROCESS"
    CHILDPROCESS = "CHILDPROCESS"
    FILENAME = "FILENAME"
    FILEHASH = "FILEHASH"
    PARENTHASH = "PARENTHASH"
    CHILDHASH = "CHILDHASH"
    URL = "DestinationURL"
    THREATSIGNATURE = "THREATSIGNATURE"
    EMAILMESSAGE = "EMAILSUBJECT"
    USB = "USB"
    EVENT = "EVENT"
    CVEID = "CVEID"
    DEPLOYMENT = "DEPLOYMENT"
    CREDITCARD = "CREDITCARD"
    PHONENUMBER = "PHONENUMBER"
    CVE = "CVE"
    THREATACTOR = "THREATACTOR"
    THREATCAMPAIGN = "THREATCAMPAIGN"
    GENERIC = "GENERICENTITY"
    SOURCEDOMAIN = "SOURCEDOMAIN"
    DESTINATIONDOMAIN = "DESTINATIONDOMAIN"
    IPSET = "IPSET"
    CLUSTER = "CLUSTER"
    APPLICATION = "APPLICATION"
    DATABASE = "DATABASE"
    POD = "POD"
    CONTAINER = "CONTAINER"
    SERVICE = "SERVICE"
    DOMAIN = "DOMAIN"


class CaseStatus:
    OPEN = "OPEN"
    CLOSE = "CLOSE"


class InsightSeverity:
    INFO = 0
    WARN = 1
    ERROR = 2


class InsightType:
    General = 0
    Entity = 1


class Base:
    def __init__(
        self,
        identifier,
        creation_time=None,
        modification_time=None,
        additional_properties=None,
    ):
        logger.info("Creating Base model object")
        if self.is_identifier_mandatory:
            if not identifier:
                logger.error("Missing mandatory field: Identifier")
                raise Exception("Identifier is required")

        self.identifier = identifier
        self.creation_time = creation_time
        self.modification_time = modification_time
        self.additional_properties = additional_properties
        logger.info("Base model created successfully")

    @property
    def is_identifier_mandatory(self):
        return True


class CyberCaseInfo(Base):
    def __init__(
        self,
        identifier,
        creation_time,
        modification_time,
        alert_count,
        priority,
        is_touched,
        is_merged,
        is_important,
        assigned_user,
        title,
        description,
        status,
        environment,
        is_incident,
        stage,
        has_suspicious_entity,
        high_risk_products,
        is_locked,
        has_workflow,
        sla_expiration_unix_time,
        additional_properties,
    ):
        logger.info("Creating CyberCaseInfo model object")
        super(CyberCaseInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.environment = environment
        self.priority = priority
        self.is_touched = is_touched
        self.is_merged = is_merged
        self.is_important = is_important
        self.assigned_user = assigned_user
        self.title = title
        self.description = description
        self.status = status
        self.stage = stage
        self.alert_count = alert_count
        self.has_suspicious_entity = has_suspicious_entity
        self.has_workflow = has_workflow
        self.is_locked = is_locked
        self.high_risk_products = high_risk_products
        self.start_time = 0
        self.sla_expiration_unix_time = sla_expiration_unix_time
        self.is_incident = is_incident
        logger.info("CyberCaseInfo model created successfully")

    @property
    def end_time(self):
        return (
            int(self.additional_properties.get("EndTime", 0))
            if self.additional_properties
            else 0
        )


class AlertInfo(Base):
    def __init__(
        self,
        identifier,
        alert_group_identifier,
        creation_time,
        modification_time,
        case_identifier,
        reporting_vendor,
        reporting_product,
        environment,
        name,
        description,
        external_id,
        severity,
        rule_generator,
        tags,
        detected_time,
        additional_properties,
        additional_data,
    ):
        logger.info("Creating AlertInfo model object")
        super(AlertInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.identifier = identifier
        self.alert_group_identifier = alert_group_identifier
        self.additional_data = additional_data
        self.case_identifier = case_identifier
        self.reporting_vendor = reporting_vendor
        self.reporting_product = reporting_product
        self.environment = environment
        self.name = name
        self.description = description
        self.external_id = external_id
        self.severity = severity
        self.rule_generator = rule_generator
        self.tags = tags
        self.detected_time = detected_time
        logger.info("AlertInfo model created successfully")


class Attachment(Base):
    def __init__(
        self,
        case_identifier,
        alert_identifier,
        base64_blob,
        attachment_type,
        name,
        description,
        is_favorite,
        orig_size,
        size,
    ):
        super(Attachment, self).__init__(case_identifier)
        logger.info("Creating AlertInfo model object")
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.base64_blob = base64_blob
        self.type = attachment_type
        self.name = name
        self.description = description
        self.is_favorite = is_favorite
        self.orig_size = orig_size
        self.size = size
        logger.info("Attachment model created successfully")

    @staticmethod
    def fromfile(
        path,
        case_id=None,
        alert_identifier=None,
        description=None,
        is_favorite=False,
    ):
        path = path.replace("\\", "/")
        if not os.path.isfile(path):
            raise OSError("File not found")
        name, file_type = os.path.splitext(os.path.split(path)[1])
        with open(path, "rb") as in_file:
            content = in_file.read()

            if SiemplifyUtils.is_python_37():
                base64_blob = base64.b64encode(content).decode()
            else:
                base64_blob = base64.b64encode(content)

        return Attachment(
            case_id,
            alert_identifier,
            base64_blob,
            file_type,
            name,
            description,
            is_favorite,
            len(content),
            len(base64_blob),
        )

    @property
    def is_identifier_mandatory(self):
        return False


class SecurityEventInfo(Base):
    def __init__(
        self,
        identifier=None,
        creation_time=None,
        modification_time=None,
        case_identifier=None,
        alert_identifier=None,
        name=None,
        description=None,
        event_id=None,
        device_severity=None,
        device_product=None,
        device_vendor=None,
        device_version=None,
        event_class_id=None,
        severity=None,
        start_time=None,
        end_time=None,
        event_type=None,
        rule_generator=None,
        is_correlation=None,
        device_host_name=None,
        device_address=None,
        source_dns_domain=None,
        source_nt_domain=None,
        source_host_name=None,
        source_address=None,
        source_user_name=None,
        source_user_id=None,
        source_process_name=None,
        destination_dns_domain=None,
        destination_nt_domain=None,
        destination_host_name=None,
        destination_address=None,
        destination_user_name=None,
        destination_url=None,
        destination_port=None,
        destination_process_name=None,
        file_name=None,
        file_hash=None,
        file_type=None,
        email_subject=None,
        usb=None,
        application_protocol=None,
        transport_protocol=None,
        category_outcome=None,
        signature=None,
        deployment=None,
        additional_properties=None,
        threat_actor=None,
        source_mac_address=None,
        destination_mac_address=None,
        credit_card=None,
        phone_number=None,
        cve=None,
        threat_campaign=None,
        generic_entity=None,
        process=None,
        parent_process=None,
        parent_hash=None,
        child_process=None,
        child_hash=None,
        source_domain=None,
        destination_domain=None,
        ipset=None,
        cluster=None,
        application=None,
        database=None,
        pod=None,
        container=None,
        service=None,
    ):
        logger.info("Creating SecurityEventInfo model object")
        super(SecurityEventInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.description = description
        self.name = name
        self.event_id = event_id
        self.source_mac_address = source_mac_address
        self.destination_mac_address = destination_mac_address
        self.credit_card = credit_card
        self.phone_number = phone_number
        self.cve = cve
        self.threat_campaign = threat_campaign
        self.generic_entity = generic_entity
        self.threat_actor = threat_actor
        self.device_product = device_product
        self.device_vendor = device_vendor
        self.device_version = device_version
        self.device_severity = device_severity
        self.event_class_id = event_class_id
        self.severity = severity
        self.start_time = start_time
        self.end_time = end_time
        self.event_type = event_type
        self.file_type = file_type
        self.rule_generator = rule_generator
        self.is_correlation = is_correlation
        self.device_host_name = device_host_name
        self.device_address = device_address
        self.source_dns_domain = source_dns_domain
        self.source_nt_domain = source_nt_domain
        self.source_host_name = source_host_name
        self.source_address = source_address
        self.source_user_name = source_user_name
        self.source_user_id = source_user_id
        self.source_process_name = source_process_name
        self.destination_dns_domain = destination_dns_domain
        self.destination_nt_domain = destination_nt_domain
        self.destination_host_name = destination_host_name
        self.destination_address = destination_address
        self.destination_user_name = destination_user_name
        self.destination_url = destination_url
        self.destination_port = destination_port
        self.destination_process_name = destination_process_name
        self.filename = file_name
        self.file_hash = file_hash
        self.email_subject = email_subject
        self.usb = usb
        self.parent_process = parent_process
        self.parent_hash = parent_hash
        self.child_process = child_process
        self.child_hash = child_hash
        self.application_protocol = application_protocol
        self.transport_protocol = transport_protocol
        self.category_outcome = category_outcome
        self.signature = signature
        self.deployment = deployment
        self.process = process
        self.source_domain = source_domain
        self.destination_domain = destination_domain
        self.ipset = ipset
        self.cluster = cluster
        self.application = application
        self.database = database
        self.pod = pod
        self.container = container
        self.service = service

        logger.info("SecurityEventInfo model created successfully")

    @property
    def is_identifier_mandatory(self):
        return False


class DomainRelationInfo(Base):
    def __init__(
        self,
        identifier,
        creation_time,
        modification_time,
        case_identifier,
        alert_identifier,
        security_event_identifier,
        relation_type,
        event_id,
        from_identifier,
        to_identifier,
        device_product,
        device_vendor,
        event_class_id,
        severity,
        start_time,
        end_time,
        destination_port,
        category_outcome,
        additional_properties,
        to_type=None,
        from_type=None,
    ):
        logger.info("Creating DomainRelationInfo model object")
        super(DomainRelationInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.security_event_identifier = security_event_identifier
        self.type = relation_type
        self.event_id = event_id
        self.from_identifier = from_identifier
        self.to_identifier = to_identifier
        self.device_product = device_product
        self.device_vendor = device_vendor
        self.event_class_id = event_class_id
        self.severity = severity
        self.start_time = start_time
        self.end_time = end_time
        self.destination_port = destination_port
        self.category_outcome = category_outcome
        self.to_type = to_type
        self.from_type = from_type
        logger.info("DomainRelationInfo model created successfully")


class DomainEntityInfo(Base):
    def __init__(
        self,
        identifier,
        creation_time,
        modification_time,
        case_identifier,
        alert_identifier,
        entity_type,
        is_internal,
        is_suspicious,
        is_artifact,
        is_enriched,
        is_vulnerable,
        is_pivot,
        additional_properties,
    ):
        logger.info("Creating DomainEntityInfo model object")
        super(DomainEntityInfo, self).__init__(
            identifier,
            creation_time,
            modification_time,
            additional_properties,
        )
        self.case_identifier = case_identifier
        self.alert_identifier = alert_identifier
        self.entity_type = entity_type
        self.is_internal = is_internal
        self.is_suspicious = is_suspicious
        self.is_artifact = is_artifact
        self.is_enriched = is_enriched
        self.is_vulnerable = is_vulnerable
        self.is_pivot = is_pivot
        logger.info("DomainEntityInfo model created successfully")

    def to_dict(self):
        return self.__dict__

    def _update_internal_properties(self):
        self.additional_properties["IsInternalAsset"] = str(self.is_internal)
        self.additional_properties["IsEnriched"] = str(self.is_enriched)
        self.additional_properties["IsSuspicious"] = str(self.is_suspicious)
        self.additional_properties["IsVulnerable"] = str(self.is_vulnerable)

    def __repr__(self):
        return self.identifier

    def __str__(self):
        return self.identifier


class Alert(AlertInfo):
    def __init__(
        self,
        identifier,
        alert_group_identifier,
        creation_time,
        modification_time,
        case_identifier,
        reporting_vendor,
        reporting_product,
        environment,
        name,
        description,
        external_id,
        severity,
        rule_generator,
        tags,
        detected_time,
        security_events,
        domain_relations,
        domain_entities,
        additional_properties,
        additional_data,
    ):
        logger.info("Creating Alert model object")
        super(Alert, self).__init__(
            identifier,
            alert_group_identifier,
            creation_time,
            modification_time,
            case_identifier,
            reporting_vendor,
            reporting_product,
            environment,
            name,
            description,
            external_id,
            severity,
            rule_generator,
            tags,
            detected_time,
            additional_properties,
            additional_data,
        )

        self.security_events = []
        self.relations = []
        self.entities = []
        self.tags = tags

        for security_event in security_events:
            self.security_events.append(SecurityEventInfo(**security_event))
        for relation in domain_relations:
            self.relations.append(DomainRelationInfo(**relation))
        for entity in domain_entities:
            self.entities.append(DomainEntityInfo(**entity))

        self.start_time = self.get_alert_start_time(creation_time, security_events)

        logger.info("Alert model created successfully")

    def get_alert_start_time(self, creation_time, security_events):
        min_time = 0

        for sec in security_events:
            sec_start_time = self.get_prop_if_exists(sec, "start_time", 0)
            is_correlation = self.get_prop_if_exists(sec, "is_correlation", False)
            if not is_correlation and sec_start_time != 0:
                if min_time == 0 or sec_start_time < min_time:
                    min_time = sec_start_time

        if min_time == 0:
            min_time = creation_time

        minimum_time = SiemplifyUtils.convert_unixtime_to_datetime(min_time)

        return minimum_time

    @staticmethod
    def get_prop_if_exists(dictionary, prop_name, default_value):
        result = default_value
        if prop_name in dictionary:
            result = dictionary[prop_name]

        return result


class CyberCase(CyberCaseInfo):
    def __init__(
        self,
        identifier,
        creation_time,
        modification_time,
        alert_count,
        priority,
        is_touched,
        is_merged,
        is_important,
        environment,
        assigned_user,
        title,
        description,
        status,
        is_incident,
        stage,
        has_suspicious_entity,
        high_risk_products,
        is_locked,
        has_workflow,
        sla_expiration_unix_time,
        cyber_alerts,
        additional_properties,
    ):
        logger.info("Creating CyberCase model object")
        super(CyberCase, self).__init__(
            identifier,
            creation_time,
            modification_time,
            alert_count,
            priority,
            is_touched,
            is_merged,
            is_important,
            assigned_user,
            title,
            description,
            status,
            environment,
            is_incident,
            stage,
            has_suspicious_entity,
            high_risk_products,
            is_locked,
            has_workflow,
            sla_expiration_unix_time,
            additional_properties,
        )
        self.alerts = []
        for alert in cyber_alerts:
            self.alerts.append(Alert(**alert))

        logger.info("CyberCase model created successfully")

    def has_alerts_loaded(self):
        # Alerts always loaded for CyberCase instance
        return True


class CyberCaseLazy(CyberCaseInfo):
    def __init__(
        self,
        alerts_provider,
        identifier,
        creation_time,
        modification_time,
        alert_count,
        priority,
        is_touched,
        is_merged,
        is_important,
        environment,
        assigned_user,
        title,
        description,
        status,
        is_incident,
        stage,
        has_suspicious_entity,
        high_risk_products,
        is_locked,
        has_workflow,
        sla_expiration_unix_time,
        additional_properties,
    ):
        logger.info("Creating CyberCaseLazy model object")
        super(CyberCaseLazy, self).__init__(
            identifier,
            creation_time,
            modification_time,
            alert_count,
            priority,
            is_touched,
            is_merged,
            is_important,
            assigned_user,
            title,
            description,
            status,
            environment,
            is_incident,
            stage,
            has_suspicious_entity,
            high_risk_products,
            is_locked,
            has_workflow,
            sla_expiration_unix_time,
            additional_properties,
        )
        self._alerts = None
        self.__alerts_provider = alerts_provider
        logger.info("CyberCaseLazy model created successfully")

    @property
    def alerts(self):
        if self._alerts is None:
            loaded_alerts = self.__alerts_provider.get_alerts()
            self._alerts = [Alert(**alert) for alert in loaded_alerts]

        return self._alerts

    def has_alerts_loaded(self):
        return self._alerts is not None


class CaseFilterValue:
    def __init__(self, value, title):
        self.value = value
        self.title = title


class CasesFilter:
    def __init__(
        self,
        environments=None,
        analysts=None,
        statuses=None,
        case_names=None,
        tags=None,
        priorities=None,
        stages=None,
        case_types=None,
        products=None,
        networks=None,
        ticked_ids_free_search="",
        case_ids_free_search="",
        wall_data_free_search="",
        entities_free_search="",
        start_time_unix_time_in_ms=-1,
        end_time_unix_time_in_ms=-1,
    ):
        self.ticked_ids_free_search = ticked_ids_free_search
        self.environments = environments or []
        self.case_ids_free_search = case_ids_free_search
        self.products = products or []
        self.analysts = analysts or []
        self.status = statuses or []
        self.tags = tags or []
        self.start_time_unix_time_in_ms = start_time_unix_time_in_ms
        self.end_time_unix_time_in_ms = end_time_unix_time_in_ms
        self.case_names = case_names or []
        self.priorities = priorities or []
        self.wall_data_free_search = wall_data_free_search
        self.stages = stages or []
        self.networks = networks or []
        self.case_types = case_types or []
        self.entities_free_search = entities_free_search


class Task(Base):
    def __init__(
        self,
        case_id,
        content,
        creator_user_id,
        due_date_unix_time_ms=None,
        is_important=False,
        is_favorite=False,
        owner_comment=None,
        priority=0,
        owner=None,
        status=0,
        completion_comment=None,
        completion_date_time_unix_time_in_ms=None,
        alert_identifier=None,
        id=0,
        title=None,
        creator_full_name=None,
        owner_full_name=None,
        creation_time_unix_time_in_ms=0,
        modification_time_unix_time_in_ms=0,
        last_modifier=None,
        last_modifier_full_name=None,
        completor=None,
        completor_full_name=None,
    ):
        """Task init
        :param case_id: {int}
        :param title: {str}
        :param content: {str}
        :param creator_user_id: {str}
        :param creator_full_name: {str}
        :param owner_full_name: {str}
        :param last_modifier: {str}
        :param last_modifier_full_name: {str}
        :param completor: {str}
        :param completor_full_name: {str}
        :param creation_time_unix_time_in_ms: {long} #unixtime
        :param due_date_unix_time_ms: {long} #unixtime
        :param is_important: {bool}
        :param is_favorite: {bool}
        :param owner_comment: {str}
        :param priority: {int}
        :param owner: {str}
        :param status: {int}
        :param completion_comment: {str}
        :param completion_date_time_unix_time_in_ms: {long} #unixtime
        :param alert_identifier: {int}
        :param id: {int}
        """
        super(Task, self).__init__(case_id)
        self.case_id = case_id
        self.creation_time_unix_time_in_ms = creation_time_unix_time_in_ms
        self.modification_time_unix_time_in_ms = modification_time_unix_time_in_ms
        self.title = title
        self.content = content
        self.creator_user_id = creator_user_id
        self.creator_full_name = creator_full_name
        self.owner_full_name = owner_full_name
        self.last_modifier = last_modifier
        self.last_modifier_full_name = last_modifier_full_name
        self.completor = completor
        self.completor_full_name = completor_full_name

        # Optional used parameters
        self.due_date_unix_time_ms = due_date_unix_time_ms
        self.is_important = is_important
        self.is_favorite = is_favorite

        # Not used yet (here for later development)
        self.priority = priority
        self.owner_comment = owner_comment

        # Fixed values for first creation
        self.owner = owner if owner else creator_user_id
        self.status = status
        self.completion_comment = completion_comment
        self.completion_date_time_unix_time_in_ms = completion_date_time_unix_time_in_ms

        # DB properties
        self.alert_identifier = alert_identifier
        self.id = id

    @property
    def is_identifier_mandatory(self):
        return False


class CustomList(Base):
    def __init__(self, identifier, category, environment):
        """CustomList init
        :param identifier: {string}
        :param category: {string}
        :param environment: {string}
        """
        super(CustomList, self).__init__(identifier)
        self.identifier = identifier
        self.category = category
        self.environment = environment

    def __str__(self):
        return f"Identifier: {self.identifier}, Category: {self.category}, Environment: {self.environment}"

    @property
    def is_identifier_mandatory(self):
        return False


class LogRecordTypeEnum:
    KEEP_ALIVE = 2
    ERROR = 1
    INFO = 0


class ConnectorLogRecord:
    def __init__(
        self,
        record_type,
        message,
        connector_identifier,
        result_data_type,
        original_source_file_name=None,
        result_package_items_count=None,
        environment=None,
        source_system_name=None,
        exception_message=None,
        integration=None,
        connector_definition_name=None,
        timestamp=None,
    ):
        self.RecordType = record_type
        self.Message = message
        self.ConnectorIdentifier = connector_identifier
        self.ResultDataType = result_data_type
        self.OriginalSourceFileName = original_source_file_name
        self.ResultPackageItemsCount = result_package_items_count
        self.Environment = environment
        self.SourceSystemName = source_system_name
        self.ExceptionMessage = exception_message
        self.TimestampUnixMs = timestamp
        self.ConnectorDefinitionName = connector_definition_name
        self.Integration = integration


class ActionLogRecord:
    def __init__(
        self,
        record_type,
        message,
        original_source_file_name=None,
        case_id=None,
        alert_id=None,
        workflow_id=None,
        environment=None,
        source_system_name=None,
        exception_message=None,
        integration=None,
        action_definition_name=None,
        timestamp=None,
    ):
        self.RecordType = record_type
        self.Message = message
        self.CaseId = case_id
        self.AlertId = alert_id
        self.WorkflowId = workflow_id
        self.OriginalSourceFileName = original_source_file_name
        self.Environment = environment
        self.SourceSystemName = source_system_name
        self.ExceptionMessage = exception_message
        self.TimestampUnixMs = timestamp
        self.ActionDefinitionName = action_definition_name
        self.Integration = integration


class LogRow:
    def __init__(self, message, log_level, timestamp):
        self.message = message
        self.log_level = log_level
        self.timestamp = timestamp


class CaseFilterOperatorEnum:
    OR = "OR"
    AND = "AND"


class CaseFilterStatusEnum:
    OPEN = "OPEN"
    CLOSE = "CLOSE"
    BOTH = "BOTH"


class CaseFilterSortOrderEnum:
    ASC = "ASC"
    DESC = "DESC"


class CaseFilterSortByEnum:
    START_TIME = "START_TIME"
    CLOSE_TIME = "CLOSE_TIME"
    UPDATE_TIME = "UPDATE_TIME"


class ApiSyncCasePriorityEnum:
    INFORMATIVE = 0
    UNCHANGED = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ApiSyncCaseStatusEnum:
    OPENED = 0
    CLOSED = 1
    ALL = 2
    MERGED = 3
    CREATION_PENDING = 4


class ApiSyncAlertPriorityEnum:
    INFORMATIVE = 0
    UNCHANGED = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class ApiSyncAlertStatusEnum:
    OPENED = 0
    CLOSED = 1


class ApiSyncAlertCloseReasonEnum:
    MALICIOUS = 0
    NOT_MALICIOUS = 1
    MAINTENANCE = 2
    INCONCLUSIVE = 3
    UNKNOWN = 4


class ApiSyncAlertUsefulnessEnum:
    NONE = 0
    NOT_USEFUL = 1
    USEFUL = 2


class SyncCase:
    def __init__(
        self,
        case_id,
        environment,
        priority,
        stage,
        status,
        external_case_id,
        title,
    ):
        """:param case_id: {int}
        :param environment: {string}
        :param priority: {int} represented by ApiSyncCasePriorityEnum values.
        :param stage: {string}
        :param status: {int} represented by ApiSyncAlertStatusEnum values.
        :param external_case_id: {string}
        :param title: {string}
        """
        self.case_id = case_id
        self.environment = environment
        self.priority = priority
        self.stage = stage
        self.status = status
        self.external_case_id = external_case_id
        self.title = title


class SyncCaseMetadata:
    def __init__(self, case_id, tracking_time):
        """:param case_id: {int}
        :param tracking_time: {int} UTC tracking time in ms.
        """
        self.case_id = case_id
        self.tracking_time = tracking_time


class SyncAlert:
    # When an alert's siem_alert_id is set with this value, then, it will not be synced
    # to the SIEM.
    AVOID_ALERT_SYNC = "-1"

    def __init__(
        self,
        alert_group_id,
        alert_id,
        case_id,
        environment,
        priority,
        status,
        ticket_id,
        creation_time,
        close_comment,
        close_reason,
        close_root_cause,
        close_usefulness,
        siem_alert_id=None,
    ):
        """:param alert_group_id: {string}
        :param alert_id: {string}
        :param case_id: {int}
        :param environment: {string}
        :param priority: {int} represented by ApiSyncAlertPriorityEnum values.
        :param status: {int} represented by ApiSyncAlertStatusEnum values.
        :param ticket_id: {string}
        :param creation_time: {int} UTC creation time in ms.
        :param close_comment: {string} Usable if status ==
        ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param close_reason: {int} represented by ApiSyncAlertCloseReasonEnum values.
        Usable if
            status == ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param close_root_cause: {string} Usable if status ==
        ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param close_usefulness: {int} represented by ApiSyncAlertUsefulnessEnum
        values. Usable if
            status == ApiSyncAlertStatusEnum.CLOSED, otherwise, None.
        :param siem_alert_id: {string} Corresponding Chronicle SIEM alert identifier
        """
        self.alert_group_id = alert_group_id
        self.alert_id = alert_id
        self.case_id = case_id
        self.environment = environment
        self.priority = priority
        self.status = status
        self.ticket_id = ticket_id
        self.creation_time = creation_time
        self.close_comment = close_comment
        self.close_reason = close_reason
        self.close_root_cause = close_root_cause
        self.close_usefulness = close_usefulness
        self.siem_alert_id = siem_alert_id


class SyncAlertMetadata:
    def __init__(self, alert_group_id, tracking_time):
        """:param alert_group_id: {string}
        :param tracking_time: {int} UTC tracking time in ms.
        """
        self.alert_group_id = alert_group_id
        self.tracking_time = tracking_time


class SyncCaseIdMatch:
    """This object represents a matching between a Siemplify internal case id and an
    external case id in an
    external system.
    """

    def __init__(self, case_id, external_case_id):
        """:param case_id: {int}
        :param external_case_id: {string}
        """
        self.case_id = case_id
        self.external_case_id = external_case_id


class ApiPeriodTypeEnum:
    """This object represents the time units of an SLA period."""

    MINUTES = "Minutes"
    HOURS = "Hours"
    DAYS = "Days"

    @classmethod
    def values(cls):
        return [cls.MINUTES, cls.HOURS, cls.DAYS]

    @classmethod
    def validate(cls, value):
        value_lower = value.lower()
        return (
            value_lower == cls.MINUTES.lower()
            or value_lower == cls.HOURS.lower()
            or value_lower == cls.DAYS.lower()
        )
