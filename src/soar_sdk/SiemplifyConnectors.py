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

import json
import os
import sys

from . import SiemplifyUtils
from .OverflowManager import OverflowAlertDetails, OverflowManager
from .SiemplifyBase import SiemplifyBase
from .SiemplifyConnectorsDataModel import ConnectorContext
from .SiemplifyLogger import ConnectorsFileLogsCollector
from .SiemplifyUtils import extract_script_param, is_python_37, my_stdout, real_stdout

SiemplifyUtils.override_stdout()


class SiemplifyConnectorExecution(SiemplifyBase):
    MAX_NUM_LOG_ROWS: int = 5_000
    CONTEXT_TYPE: int = 4

    def __init__(self, mock_stdin: str | None = None) -> None:
        super(SiemplifyConnectorExecution, self).__init__(is_connector=True)

        self.context = self._get_connector_context(mock_stdin)
        self.is_locally_scheduled_remote_connector = (
            self.context.connector_info.is_locally_scheduled_remote_connector
        )

        if self.sdk_config.is_remote_publisher_sdk:
            self.set_logs_collector(
                ConnectorsFileLogsCollector(
                    self.sdk_config.run_folder_path,
                    self.context,
                ),
            )

        self.LOGGER.module = "%s_%s_%s" % (
            self.context.connector_info.integration,
            self.context.connector_info.connector_definition_name,
            self.context.connector_info.identifier,
        )

        self.overflow_manager = self.create_overflow_manager()

        if (
            self.API_ROOT
            and self.context.connector_api_key
            and self.is_locally_scheduled_remote_connector
        ):
            self._init_remote_session(self.context.connector_api_key)

        # NOTICE - ignore_addresses is supported in SDK but currently not supported
        # by the connectors.
        # To add support to the connectors, add the Proxy Ignored Address parameter
        # to each connector.
        proxy_settings = {
            "proxy_server_address": self.parameters.get("Proxy Server Address"),
            "username": self.parameters.get("Proxy Username"),
            "password": self.parameters.get("Proxy Password"),
            "ignore_addresses": str(
                self.parameters.get("Proxy Ignored Addresses", ""),
            ).split(",")
            if self.parameters.get("Proxy Ignored Addresses")
            else [],
        }
        # add default values to ignore_addresses
        if "localhost" not in proxy_settings["ignore_addresses"]:
            proxy_settings["ignore_addresses"].append("localhost")
        if "127.0.0.1" not in proxy_settings["ignore_addresses"]:
            proxy_settings["ignore_addresses"].append("127.0.0.1")

        SiemplifyUtils.set_proxy_state(proxy_settings)

    @property
    def log_location(self) -> str:
        return "SDK_Connectors"

    @property
    def run_folder(self) -> str:
        r"""Build run_folder base on script name
        :return: {string} full path (e.g.
        C:\Siemplify_Server\Scripting\SiemplifyAction\<script name>)
        """
        path = os.path.join(self.RUN_FOLDER, self.__class__.__name__)

        script_name = "%s_%s" % (
            self.context.connector_info.display_name,
            self.context.connector_info.identifier,
        )

        if not script_name:
            raise Exception(
                "Cannot build run_folder when script_name has not been defined first. "
                "Try addind: siemplify.script_name='name'",
            )

        path = os.path.join(path, script_name)

        if not os.path.exists(path):
            os.makedirs(path)

        return path

    @property
    def parameters(self) -> dict[str, str]:
        connector_parameters = dict()

        if (
            self.context
            and self.context.connector_info
            and self.context.connector_info.params
        ):
            for param in self.context.connector_info.params:
                if param["param_name"] not in connector_parameters:
                    connector_parameters[param["param_name"]] = param["param_value"]

        return connector_parameters

    @property
    def whitelist(self) -> dict | list | None:
        if self.context and self.context.connector_info:
            return self.context.connector_info.white_list
        return None

    @property
    def is_test_run(self) -> bool:
        if len(sys.argv) >= 2 and sys.argv[1] == "False":
            return True
        return False

    def create_overflow_manager(self) -> OverflowManager:
        return OverflowManager(
            manager_cache_folder_path=self.run_folder,
            logger=self.LOGGER,
            is_test_run=self.is_test_run,
            connector_instance=self,
        )

    def is_overflowed_alert(
        self,
        environment: str,
        alert_identifier: str,
        ingestion_time: int = SiemplifyUtils.unix_now(),
        original_file_path: str | None = None,
        original_file_content: str | None = None,
        alert_name: str | None = None,
        product: str | None = None,
        source_ip: str | None = None,
        source_host: str | None = None,
        destination_ip: str | None = None,
        destination_host: str | None = None,
        siem_alert_id: str | None = None,
        source_system_url: str | None = None,
        source_rule_identifier: str | None = None,
    ) -> bool:
        """Check if alert is overflowed
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
        :param source_system_url: {string} The base URL of the system which is the
        source for the alert
        :param source_rule_identifier: {string} The Chronicle SIEM rule identifier
        which generated this alert
        :return: {boolean} true/false
        """
        alert_overflow_details = OverflowAlertDetails(
            environment=environment,
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
            source_rule_identifier=source_rule_identifier,
        )

        is_overflowed = self.overflow_manager.check_is_alert_overflowed(
            alert_overflow_details,
        )

        return is_overflowed

    def return_package(
        self,
        cases: list,
        output_variables: dict = {},
        log_items: list = [],
    ) -> None:
        """Return data
        :param cases: {list} of cases {CaseInfo}
        :param output_variables: {list}
        :param log_items: {list}
        """
        connector_output = {}
        connector_output["cases"] = cases
        connector_output["overflow_cases"] = self.overflow_manager.reported_overflows

        connector_output["log_items"] = log_items
        connector_output["variables"] = output_variables
        connector_output["log_rows"] = self.LOGGER.log_rows[: self.MAX_NUM_LOG_ROWS]

        output_object = {}
        output_object["ResultObjectJson"] = json.dumps(
            connector_output,
            default=lambda o: o.__dict__,
        )
        output_object["DebugOutput"] = SiemplifyUtils.my_stdout.getvalue()

        SiemplifyUtils.real_stdout.write(
            json.dumps(output_object, default=lambda o: o.__dict__),
        )

    def return_test_result(
        self,
        is_success: bool,
        result_params_dictionary: dict,
    ) -> None:
        """In case of testing, return
        :param is_success: {boolean}
        :param result_params_dictionary: {dict}
        """
        connector_test_output = {}
        connector_test_output["is_success"] = is_success
        connector_test_output["result_params"] = result_params_dictionary

        output_object = {}
        output_object["ResultObjectJson"] = json.dumps(
            connector_test_output,
            default=lambda o: o.__dict__,
        )
        output_object["DebugOutput"] = my_stdout.getvalue()

        real_stdout.write(json.dumps(output_object, default=lambda o: o.__dict__))

    def extract_connector_param(
        self,
        param_name: str,
        default_value: any = None,
        input_type: type = str,
        is_mandatory: bool = False,
        print_value: bool = False,
    ) -> any:
        script_param = extract_script_param(
            siemplify=self,
            input_dictionary=self.parameters,
            param_name=param_name,
            default_value=default_value,
            input_type=input_type,
            is_mandatory=is_mandatory,
            print_value=print_value,
        )
        if not self.context.vault_settings:
            return script_param

        # we import SiemplifyVaultUtils only when needed, in order to not import
        # dependencies which are not needed
        import SiemplifyVaultUtils

        return SiemplifyVaultUtils.extract_vault_param(
            script_param,
            self.context.vault_settings,
        )

    def get_context_property(
        self,
        context_type: int,
        identifier: str,
        property_key: str,
    ) -> any:
        if self.is_locally_scheduled_remote_connector:
            context_type = self.CONTEXT_TYPE
            identifier = self.context.connector_info.identifier
        return super(SiemplifyConnectorExecution, self).get_context_property(
            context_type,
            identifier,
            property_key,
        )

    def get_connector_context_property(self, identifier: str, property_key: str) -> any:
        return self.get_context_property(self.CONTEXT_TYPE, identifier, property_key)

    def set_context_property(
        self,
        context_type: int,
        identifier: str,
        property_key: str,
        property_value: any,
    ) -> any:
        if self.is_locally_scheduled_remote_connector:
            context_type = self.CONTEXT_TYPE
            identifier = self.context.connector_info.identifier
        return super(SiemplifyConnectorExecution, self).set_context_property(
            context_type,
            identifier,
            property_key,
            property_value,
        )

    def try_set_context_property(
        self,
        context_type: int,
        identifier: str,
        property_key: str,
        property_value: any,
    ) -> bool:
        if self.is_locally_scheduled_remote_connector:
            context_type = self.CONTEXT_TYPE
            identifier = self.context.connector_info.identifier
        return super(SiemplifyConnectorExecution, self).try_set_context_property(
            context_type,
            identifier,
            property_key,
            property_value,
        )

    def set_connector_context_property(
        self,
        identifier: str,
        property_key: str,
        property_value: any,
    ) -> any:
        return self.set_context_property(
            self.CONTEXT_TYPE,
            identifier,
            property_key,
            property_value,
        )

    def save_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool = False,
        new_timestamp: int = SiemplifyUtils.unix_now(),
    ) -> any:
        return super(SiemplifyConnectorExecution, self).save_timestamp(
            datetime_format,
            timezone,
            new_timestamp,
            4,
            self.context.connector_info.identifier,
        )

    def fetch_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool = False,
    ) -> any:
        return super(SiemplifyConnectorExecution, self).fetch_timestamp(
            datetime_format,
            timezone,
            4,
            self.context.connector_info.identifier,
        )

    def fetch_and_save_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool = False,
        new_timestamp: int = SiemplifyUtils.unix_now(),
    ) -> any:
        last_run_time = self.fetch_timestamp(datetime_format=False, timezone=False)
        self.save_timestamp(
            datetime_format=False,
            timezone=False,
            new_timestamp=SiemplifyUtils.unix_now(),
        )
        return last_run_time

    def get_case_status_by_id(self, case_id: str) -> int:
        """Get case status by case id
        :param case_id: {string} case identifier
        :return: {int} case status, Opened = 1, Closed = 2
        TODO: replace with an api that returns only case status b/300393767
        """
        address = self.address_provider.provide_get_case_metadata_address(case_id)
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json().get("status")

    def _get_connector_context(self, mock_stdin: str | None) -> ConnectorContext:
        """Get the connector's context

        Args:
            mock_stdin: Mock input for the context

        Returns:
            A ConnectorContext object

        """
        raw_context_data = mock_stdin
        if not mock_stdin:
            raw_context_data = self.get_script_context()
            if not is_python_37():
                raw_context_data = raw_context_data.decode("utf-8-sig")

        data = json.loads(raw_context_data)
        connector_info = data["connector_info"]
        vault_settings = data.get("vault_settings")
        environment_api_key = data.get("environment_api_key")
        connector_api_key = data.get("connector_api_key")
        return ConnectorContext(
            connector_info,
            vault_settings,
            environment_api_key,
            connector_api_key,
        )
