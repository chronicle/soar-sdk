import SiemplifyUtils
import SiemplifyVaultUtils
from SiemplifyConnectorsDataModel import ConnectorContext, CaseInfo
from SiemplifyUtils import my_stdout, real_stdout, extract_script_param, is_python_37, is_str_instance
from OverflowManager import OverflowManager, OverflowAlertDetails
from SiemplifyLogger import ConnectorsFileLogsCollector
from SiemplifyBase import SiemplifyBase
import os
import sys
import json

SiemplifyUtils.override_stdout()


class SiemplifyConnectorExecution(SiemplifyBase):

    MAX_NUM_LOG_ROWS = 5000

    def __init__(self, mock_stdin = None):
        super(SiemplifyConnectorExecution, self).__init__(is_connector=True)

        if is_python_37():
            raw_context_data = mock_stdin if mock_stdin else sys.stdin.buffer.read()
        else: # aka if legacy 2.7:
            raw_context_data = mock_stdin if mock_stdin else sys.stdin.read()
            if not mock_stdin:
                raw_context_data = raw_context_data.decode("utf-8-sig")
        
        data = json.loads(raw_context_data)
        self.context = ConnectorContext(**data)

        if self.sdk_config.is_remote_publisher_sdk:
            self.set_logs_collector(ConnectorsFileLogsCollector(self.sdk_config.run_folder_path, self.context))

        self.LOGGER.module = "%s_%s_%s" % (self.context.connector_info.integration,
                                           self.context.connector_info.connector_definition_name,
                                           self.context.connector_info.identifier)

        self.overflow_manager = OverflowManager(
            manager_cache_folder_path=self.run_folder, logger=self.LOGGER,
            is_test_run=self.is_test_run, connector_instance=self)

        # NOTICE - ignore_addresses is supported in SDK but currently not supported by the connectors.
        # To add support to the connectors, add the Proxy Ignored Address parameter to each connector.
        proxy_settings = {
            "proxy_server_address": self.parameters.get("Proxy Server Address"),
            "username": self.parameters.get("Proxy Username"),
            "password": self.parameters.get("Proxy Password"),
            "ignore_addresses": str(self.parameters.get("Proxy Ignored Addresses", "")).split(",") if self.parameters.get(
                "Proxy Ignored Addresses") else []
        }
        #add default values to ignore_addresses
        if "localhost" not in proxy_settings["ignore_addresses"]:
            proxy_settings["ignore_addresses"].append("localhost")
        if "127.0.0.1" not in proxy_settings["ignore_addresses"]:
            proxy_settings["ignore_addresses"].append("127.0.0.1")

        SiemplifyUtils.set_proxy_state(proxy_settings)

    @property
    def log_location(self):
        return "SDK_Connectors"

    @property
    def run_folder(self):
        """
        build run_folder base on script name
        :return: {string} full path (e.g. C:\Siemplify_Server\Scripting\SiemplifyAction\<script name>)
        """
        path = os.path.join(self.RUN_FOLDER, self.__class__.__name__)

        script_name = "%s_%s" % (self.context.connector_info.display_name,
                                 self.context.connector_info.identifier)

        if not script_name:
            raise Exception(
                "Cannot build run_folder when script_name has not been defined first. Try addind: siemplify.script_name='name'")

        path = os.path.join(path, script_name)

        if not os.path.exists(path):
            os.makedirs(path)

        return path

    @property
    def parameters(self):
        connector_parameters = dict()

        if self.context and self.context.connector_info and self.context.connector_info.params:
            for param in self.context.connector_info.params:
                if param['param_name'] not in connector_parameters:
                    connector_parameters[param['param_name']] = param['param_value']

        return connector_parameters

    @property
    def whitelist(self):
        if self.context and self.context.connector_info:
            return self.context.connector_info.white_list
        return

    @property
    def is_test_run(self):
        if len(sys.argv) >= 2 and sys.argv[1] == 'False':
            return True
        return False

    def is_overflowed_alert(self, environment, alert_identifier, ingestion_time=SiemplifyUtils.unix_now(),
                            original_file_path=None, original_file_content=None, alert_name=None, product=None,
                            source_ip=None, source_host=None, destination_ip=None, destination_host=None,
                            siem_alert_id=None, source_system_url=None, source_rule_identifier=None):

        """
        check if alert is overflowed
        :param environment: {string} environment
        :param alert_identifier: {string} alert identifier
        :param ingestion_time: {long} unix time - alert ingestion time
        :param original_file_path:  {string}
        :param original_file_content: {string}
        :param alert_name: {string} alert name
        :param product: {string} device_product
        :param source_ip: {string} source ip
        :param source_host: {string} source host
        :param destination_ip: {string} destination ip
        :param destination_host: {string} destination host
        :param siem_alert_id: {string} corresponding alert identifier in SIEM
        :param source_system_url: {string} The base URL of the system which is the source for the alert
        :param source_rule_identifier: {string} The Chronicle SIEM rule identifier which generated this alert
        :return: {boolean} true/false
        """
        alert_overflow_details = OverflowAlertDetails(environment=environment,
                                                      source_system_name=self.context.connector_info.integration,
                                                      alert_identifier=alert_identifier,
                                                      connector_identifier=self.context.connector_info.identifier,
                                                      original_file_path=original_file_path,
                                                      original_file_content=original_file_content,
                                                      ingestion_time=ingestion_time,
                                                      alert_name=alert_name,
                                                      product=product,
                                                      source_ip=source_ip,
                                                      source_host=source_host,
                                                      destination_ip=destination_ip,
                                                      destination_host=destination_host,
                                                      siem_alert_id=siem_alert_id,
                                                      source_system_url=source_system_url,
                                                      source_rule_identifier=source_rule_identifier)

        is_overflowed = self.overflow_manager.check_is_alert_overflowed(
            alert_overflow_details)

        return is_overflowed

    def return_package(self, cases, output_variables={}, log_items=[]):
        """
        Return data
        :param cases: {list} of cases {CaseInfo}
        :param output_variables: {list}
        :param log_items: {list}
        """
        connector_output = {}
        connector_output['cases'] = cases
        connector_output['overflow_cases'] = self.overflow_manager.reported_overflows

        connector_output['log_items'] = log_items
        connector_output['variables'] = output_variables
        connector_output['log_rows'] = self.LOGGER.log_rows[:self.MAX_NUM_LOG_ROWS]

        output_object = {}
        output_object["ResultObjectJson"] = json.dumps(connector_output, default=lambda o: o.__dict__)
        output_object["DebugOutput"] = SiemplifyUtils.my_stdout.getvalue()

        SiemplifyUtils.real_stdout.write(json.dumps(output_object, default=lambda o: o.__dict__))

    def return_test_result(self, is_success, result_params_dictionary):
        """
        In case of testing, return
        :param is_success: {boolean}
        :param result_params_dictionary: {dict}
        """
        connector_test_output = {}
        connector_test_output['is_success'] = is_success
        connector_test_output['result_params'] = result_params_dictionary

        output_object = {}
        output_object["ResultObjectJson"] = json.dumps(connector_test_output, default=lambda o: o.__dict__)
        output_object["DebugOutput"] = my_stdout.getvalue()

        real_stdout.write(json.dumps(output_object, default=lambda o: o.__dict__))

    def extract_connector_param(self, param_name, default_value=None, input_type=str, is_mandatory=False, print_value=False):
        script_param = extract_script_param(siemplify=self,
                                    input_dictionary=self.parameters,
                                    param_name=param_name,
                                    default_value=default_value,
                                    input_type=input_type,
                                    is_mandatory=is_mandatory,
                                    print_value=print_value)
        if not self.context.vault_settings:
            return script_param
        return SiemplifyVaultUtils.extract_vault_param(script_param, self.context.vault_settings)
                                    
    def get_connector_context_property(self, identifier, property_key):
        return super(SiemplifyConnectorExecution, self).get_context_property(4, identifier, property_key)
    
    def set_connector_context_property(self, identifier, property_key, property_value):
        return super(SiemplifyConnectorExecution, self).set_context_property(4, identifier, property_key, property_value)
        
    def save_timestamp(self, datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now()):
            return super(SiemplifyConnectorExecution, self).save_timestamp(datetime_format, timezone, new_timestamp, 4, self.context.connector_info.identifier)
        
    def fetch_timestamp(self, datetime_format=False, timezone=False):
        return super(SiemplifyConnectorExecution, self).fetch_timestamp(datetime_format, timezone, 4, self.context.connector_info.identifier)
    
    def fetch_and_save_timestamp(self, datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now()):
        last_run_time = self.fetch_timestamp(datetime_format=False, timezone=False)
        self.save_timestamp(datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now())
        return last_run_time