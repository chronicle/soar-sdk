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
from typing import Any, TypeVar

import SiemplifyUtils
from Siemplify import Siemplify
from SiemplifyBase import MaximumContextLengthException
from SiemplifyUtils import extract_script_param

T = TypeVar("T")


class SiemplifyJob(Siemplify):
    def __init__(self) -> None:
        super(SiemplifyJob, self).__init__()

        raw_context_data = self.get_script_context()

        context_data = json.loads(raw_context_data.decode("utf-8-sig"))
        self.parameters = self._fix_parameters(context_data["parameters"])
        self.unique_identifier = context_data.get("unique_identifier")
        self.use_proxy_settings = context_data.get("use_proxy_settings", False)
        self.vault_settings = context_data.get("vault_settings", None)
        self.job_api_key = context_data.get("job_api_key")

        if self.job_api_key and self.API_ROOT:
            self._init_remote_session(self.job_api_key)

        if self.use_proxy_settings:
            self.init_proxy_settings()

    def get_configuration_by_provider(self, identifier: str) -> dict[str, Any]:
        return self.get_configuration_from_server(None, identifier)

    def get_system_info(self, start_time_unixtime_ms: int) -> dict[str, Any]:
        return super(SiemplifyJob, self).get_system_info(start_time_unixtime_ms)

    def get_job_context_property(self, identifier: str, property_key: str) -> Any:
        return self.get_context_property_from_server(3, identifier, property_key)

    def set_job_context_property(
        self,
        identifier: str,
        property_key: str,
        property_value: Any,
    ) -> Any:
        if not SiemplifyUtils.validate_property_value(property_value):
            raise MaximumContextLengthException(
                "Exception was thrown in set_context_property: property value has "
                "reached maximum length",
            )
        return self.set_context_property_in_server(
            3,
            identifier,
            property_key,
            property_value,
        )

    def get_context_property(
        self,
        context_type: int,
        identifier: str,
        property_key: str,
    ) -> Any:
        return self.get_context_property_from_server(
            context_type,
            identifier,
            property_key,
        )

    def set_context_property(
        self,
        context_type: int,
        identifier: str,
        property_key: str,
        property_value: Any,
    ) -> Any:
        if not SiemplifyUtils.validate_property_value(property_value):
            raise MaximumContextLengthException(
                "Exception was thrown in set_context_property: property value has "
                "reached maximum length",
            )
        return self.set_context_property_in_server(
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
        property_value: Any,
    ) -> Any:
        if not SiemplifyUtils.validate_property_value(property_value):
            raise MaximumContextLengthException(
                "Exception was thrown in try_set_context_property: property value has "
                "reached maximum length",
            )

        return self.try_set_context_property_in_server(
            context_type,
            identifier,
            property_key,
            property_value,
        )

    def get_scoped_job_context_property(self, property_key: str) -> Any:
        """Get scoped job context property, uses the unique identifier of a job
        :param property_key: {string} key of the context property of the job
        :return: value of a specific key
        """
        return self.get_job_context_property(self.unique_identifier, property_key)

    def set_scoped_job_context_property(
        self,
        property_key: str,
        property_value: Any,
    ) -> Any:
        """Set scoped job context property, uses the unique identifier of a job
        :param property_key: {string} key of the context property of the job
        :param property_value: {string} value of the context property of the job
        :return:
        """
        return self.set_job_context_property(
            self.unique_identifier,
            property_key,
            property_value,
        )

    def save_publisher_logs(self, records: list[dict[str, Any]]) -> None:
        """Save publisher log records
        :param records: {list} records to be saved
        :return:
        """
        address = self.address_provider.provide_add_agent_logs_address()
        response = self.session.post(address, json=records)
        self.validate_siemplify_error(response)

    @property
    def log_location(self) -> str:
        return "SDK_Jobs"

    def get_failed_actions(self, number_of_hours: int) -> dict[str, Any]:
        """Get all the etl jobs that had failed in the last hours
        :return: {dict} failed jobs
        """
        address = self.address_provider.provide_get_failed_actions_address(
            number_of_hours,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_failed_etljobs(self, number_of_hours: int) -> dict[str, Any]:
        """Get all the etl jobs that had failed in the last hours
        :return: {dict} failed jobs
        """
        address = self.address_provider.provide_get_failed_etl_operations_address(
            number_of_hours,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_faulted_jobs(self, number_of_hours: int) -> dict[str, Any]:
        """Get all the jobs that had failed in the last hours
        :return: {dict} failed jobs
        """
        address = self.address_provider.provide_get_failed_jobs_address(number_of_hours)
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_faulted_connectors(
        self,
        start_unix_time: int,
        end_unix_time: int,
    ) -> dict[str, Any]:
        """Get all the connectors that had failed in the last hours
        :return: {dict} failed connectors
        """
        request = {
            "start_unix_time": start_unix_time,
            "end_unix_time": end_unix_time,
        }
        address = self.address_provider.provide_get_failed_connectors_address()
        response = self.session.post(address, json=request)
        self.validate_siemplify_error(response)
        return response.json()

    def send_mail(
        self,
        subject: str,
        message: str,
        recipients: list[str],
        attachment_file_name: str,
        attachment_content: str,
    ) -> None:
        request = {
            "subject": subject,
            "message": message,
            "recipients": recipients,
            "attachment_file_name": attachment_file_name,
            "attachment_content": attachment_content,
        }
        address = self.address_provider.provide_send_email_with_attachment_address()
        response = self.session.post(address, json=request)
        self.validate_siemplify_error(response)

    def extract_job_param(
        self,
        param_name: str,
        default_value: Any = None,
        input_type: type[T] = str,
        is_mandatory: bool = False,
        print_value: bool = False,
    ) -> T:
        script_param = extract_script_param(
            siemplify=self,
            input_dictionary=self.parameters,
            param_name=param_name,
            default_value=default_value,
            input_type=input_type,
            is_mandatory=is_mandatory,
            print_value=print_value,
        )
        if not self.vault_settings:
            return script_param

        # we import SiemplifyVaultUtils only when needed, in order to not import
        # dependencies which are not needed
        import SiemplifyVaultUtils

        return SiemplifyVaultUtils.extract_vault_param(
            script_param,
            self.vault_settings,
        )

    def save_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool = False,
        new_timestamp: int = SiemplifyUtils.unix_now(),
    ) -> int | str:
        return super(SiemplifyJob, self).save_timestamp(
            datetime_format,
            timezone,
            new_timestamp,
            3,
            self.script_name,
        )

    def fetch_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool = False,
    ) -> int | str:
        return super(SiemplifyJob, self).fetch_timestamp(
            datetime_format,
            timezone,
            3,
            self.script_name,
        )

    def fetch_and_save_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool = False,
        new_timestamp: int = SiemplifyUtils.unix_now(),
    ) -> int | str:
        last_run_time = self.fetch_timestamp(datetime_format, timezone)
        self.save_timestamp(datetime_format, timezone, new_timestamp)
        return last_run_time

    def set_configuration_property(
        self,
        integration_instance_identifier: str,
        property_name: str,
        property_value: str,
    ) -> dict[str, Any]:
        """Set integration configuration property
        :param integration_instance_identifier: {string} the identifier of the
        integration instance.
        :param property_name: {string} the name of the integration instance property
        to be updated.
        :param property_value: {string} the value of the integration instance
        property to be updated.

        :return: {dict} property details
        """
        address = self.address_provider.provide_set_configuration_property_address(
            integration_instance_identifier,
            property_name,
        )

        request_dict = {"property_value": property_value}
        response = self.session.put(address, json=request_dict)
        self.validate_siemplify_error(response)
        configurations = response.json()

        return configurations

    def set_connector_parameter(
        self,
        connector_instance_identifier: str,
        parameter_name: str,
        parameter_value: str,
    ) -> dict[str, Any]:
        """Set connector parameter value
        :param connector_instance_identifier: {string} the identifier of the
        connector instance.
        :param parameter_name: {string} the name of the connector instance parameter
        to be updated.
        :param parameter_value: {string} the value of the connector instance
        parameter to be updated.

        :return: {dict} parameter details
        """
        address = self.address_provider.provide_set_connector_parameter_address(
            connector_instance_identifier,
            parameter_name,
        )
        request_dict = {"parameter_value": parameter_value}
        response = self.session.put(address, json=request_dict)
        self.validate_siemplify_error(response)
        configurations = response.json()

        return configurations

    def get_connector_parameters(
        self,
        connector_instance_identifier: str,
    ) -> dict[str, Any]:
        """Get connector parameters
        :param connector_instance_identifier: {string} the identifier of the
        connector instance.
        :return: {dict} parameters details
        """
        address = self.address_provider.provide_get_connector_parameters_address(
            connector_instance_identifier,
        )

        response = self.session.get(address)
        self.validate_siemplify_error(response)
        configurations = response.json()

        return configurations
