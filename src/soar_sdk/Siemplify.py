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

import io
import json
import os
import shutil
import sys
import tempfile
import urllib
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import requests
import SiemplifyUtils
from ScriptResult import EXECUTION_STATE_COMPLETED, ScriptResult
from SiemplifyBase import SiemplifyBase
from SiemplifyDataModel import (
    ApiPeriodTypeEnum,
    Attachment,
    CaseFilterOperatorEnum,
    CaseFilterSortByEnum,
    CaseFilterSortOrderEnum,
    CaseFilterStatusEnum,
    CaseFilterValue,
    CasesFilter,
    CustomList,
    InsightSeverity,
    InsightType,
    SyncAlert,
    SyncAlertMetadata,
    SyncCase,
    SyncCaseMetadata,
    Task,
)
from SiemplifyUtils import convert_datetime_to_unix_time, unix_now, utc_now

SiemplifyUtils.override_stdout()

# Consts
EXTERNAL_CONFIG_PROVIDER_FILE: str = "external_providers.json"
INSIGHT_DEFAULT_THREAT_SOURCE: str = "Siemplify System"
HEADERS: dict[str, str] = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}
REQUEST_CA_BUNDLE: str = "REQUESTS_CA_BUNDLE"
JSON_RESULT_KEY: str = "JsonResult"
CASE_FILTER_MAX_RESULTS: int = 10_000
SYSTEM_NOTIFICATION_CUSTOM_MESSAGE_ID: str = "SDK_CUSTOM_NOTIFICATION"
SYSTEM_NOTIFICATION_MESSAGE_CHAR_LIMIT: int = 500
SYSTEM_NOTIFICATION_MESSAGE_ID_CHAR_LIMIT: int = 50
FORMAT_SNAKE: str = "?format=snake"


class Siemplify(SiemplifyBase):
    def __init__(self) -> None:
        super(Siemplify, self).__init__()
        self._result = ScriptResult([])
        self.API_ROOT = self.sdk_config.api_root_uri
        self.is_remote = self.sdk_config.is_remote_publisher_sdk
        self.ignore_ca_bundle = self.sdk_config.ignore_ca_bundle
        self.temp_folder_path = None
        self.vault_settings = None

    @staticmethod
    def _fix_parameters(parameters: dict[Any, Any | None]) -> dict[Any, Any]:
        """Remove empty values from the parameters dict
        :param parameters: {dict}
        :return: {dict}
        """
        if parameters:
            return {k: v for k, v in parameters.items() if v != "" or v is not None}

        return {}

    def _get_err_message(self, exception: Exception) -> str:
        """Get error message from exception object
        :param exception: {Exception} exception object
        :return: {str} exception message
        """
        return exception.message if hasattr(exception, "message") else str(exception)

    def _get_case_by_id(
        self,
        case_id: str | int,
        get_source_file: bool = False,
    ) -> dict[str, Any]:
        """Get a case object by case id
        :param case_id: {string} case identifier
        :return: {dict} case data
        """
        address = self.address_provider.provide_get_case_full_details_address(
            case_id, get_source_file,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def _get_case_metadata_by_id(self, case_id: str | int) -> dict[str, Any]:
        """Get case metadata object by case id (alerts aren't included)
        :param case_id: {string} case identifier
        :return: {dict} case data
        """
        address = self.address_provider.provide_get_case_metadata_address(case_id)
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def _get_current_alert_by_id(
        self, case_id, alert_id, get_source_file=False,
    ) -> dict[str, Any]:
        """Get Alert object by case and alert id
        :param case_id: {string} case identifier
        :param alert_id: {string} alert identifier
        :param get_source_file: optional parameter to indicate whether to include the
        source file data. Default is false
        :return: {dict} alert data
        """
        request_dict = {
            "case_id": case_id,
            "alert_id_str": alert_id,
            "populate_original_file": get_source_file,
        }
        address = self.address_provider.provide_get_alert_full_details_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

        return response.json()

    @property
    def result(self):
        return self._result

    def _get_proxy_settings(self) -> dict[str, Any]:
        """Get proxy settings
        :return: {dict} proxy settings
        """
        address = self.address_provider.provide_get_proxy_settings_address()
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def init_proxy_settings(self):
        proxy_settings = self._get_proxy_settings()
        SiemplifyUtils.set_proxy_state(proxy_settings)

    def update_entities(self, updated_entities):
        """Update entities
        :param updated_entities: {list of entities}
        """
        for entity in updated_entities:
            entity._update_internal_properties()
        address = self.address_provider.provide_update_entities_address()
        entity_data = []
        for entity in updated_entities:
            entity_data.append(entity.to_dict())

        response = self.session.post(address, json=entity_data)
        self.validate_siemplify_error(response)

    def add_attachment(
        self,
        file_path: str,
        case_id: str,
        alert_identifier: str,
        description: str | None = None,
        is_favorite: bool | None = False,
    ) -> dict[str, Any]:
        """Add attachment
        :param file_path: {string} file path
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        :param description: {string} attachment description
        :param is_favorite: {boolean} is attachment favorite
        :return: {dict} attachment_id
        """
        attachment = Attachment.fromfile(
            file_path, case_id, alert_identifier, description, is_favorite,
        )
        attachment.case_identifier = case_id
        attachment.alert_identifier = alert_identifier

        address = self.address_provider.provide_add_attachment_address()
        response = self.session.post(address, json=attachment.__dict__)
        try:
            self.validate_siemplify_error(response)
        except Exception as e:
            if "Attachment size" in self._get_err_message(e):
                raise Exception(
                    f"Attachment size should be < 5MB. Original file size: {attachment.orig_size}. Size after encoding: {attachment.size}.",
                )
            self.LOGGER.error(f"Could not add attachment: {e}")
        return response.json()

    def get_attachments(self, case_id: str) -> dict[str, Any]:
        """Get attachments from case
        :param case_id: {string} case identifier
        :return: {dict} attachments
        """
        address = self.address_provider.provide_get_case_attachments_address(case_id)
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_attachment(self, attachment_id):
        """Get attachment data by identifier
        :param attachment_id: {string} attachment identifier
        :return: {BytesIO} attachment data
        """
        address = self.address_provider.provide_get_attachment_data_address(
            attachment_id,
        )
        self.session.stream = True
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        self.session.stream = False
        return io.BytesIO(response.content)

    def assign_case(self, user, case_id, alert_identifier):
        """Assign case to user
        :param user: {string} user/role (e.g. Admin, @Tier1)
        :param case_id: {string} case identifier
        :param alert_identifier:
        """
        request_dict = {
            "case_id": str(case_id),
            "alert_identifier": alert_identifier,
            "user_id": user,
        }
        address = self.address_provider.provide_assign_user_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def add_comment(self, comment, case_id, alert_identifier):
        """Add new comment to specific case
        :param comment: {string} comment to be added to case wall
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "comment": comment,
        }
        address = "{0}/{1}".format(
            self.API_ROOT, "external/v1/cases/comments?format=snake",
        )
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def add_tag(self, tag, case_id, alert_identifier):
        """Add new tag to specific case
        :param tag: {string} tag to be added
        :param case_id: {string} case identifier
        :param alert_identifier: alert identifier
        :return:
        """
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "tag": tag,
        }
        address = self.address_provider.provide_add_tag_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def update_alerts_additional_data(self, case_id, alerts_additional_data):
        """Update alerts additional data
        :param case_id: {string} case identifier
        :param alerts_additional_data: {dict}
        """
        request_dict = {
            "case_id": case_id,
            "alerts_additional_data": alerts_additional_data,
        }
        address = self.address_provider.provide_update_alert_additional_data_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def get_similar_cases(
        self,
        case_id,
        ports_filter,
        category_outcome_filter,
        rule_generator_filter,
        entity_identifiers_filter,
        start_time_unix_ms,
        end_time_unix_ms,
    ):
        """Get similar cases
        :param case_id: {string} case identifier
        :param ports_filter: {boolean} true/false use port filter
        :param category_outcome_filter:  {boolean} true/false use category_outcome filter
        :param rule_generator_filter:  {boolean} true/false use rule_generator filter
        :param entity_identifiers_filter: {boolean} true/false use entity_identifiers filter
        :param start_time_unix_ms:
        :param end_time_unix_ms:
        :return: {dict}
        """
        request_dict = {
            "case_id": case_id,
            "ports_filter": ports_filter,
            "category_outcome_filter": category_outcome_filter,
            "rule_generator_filter": rule_generator_filter,
            "entity_identifiers_filter": entity_identifiers_filter,
            "start_time_unix_ms": start_time_unix_ms,
            "end_time_unix_ms": end_time_unix_ms,
        }
        address = self.address_provider.provide_get_similar_cases_ids_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return response.json()

    def get_ticket_ids_for_alerts_dismissed_since_timestamp(self, timestamp_unix_ms):
        """Get ticket ids for alerts dismissed since timestamp
        :param timestamp_unix_ms: {long} (e.g. 1550409785000L)
        :return: {list} alerts
        """
        # Not supported
        request_dict = {"time_stamp_unix_ms": str(timestamp_unix_ms)}
        address = self.address_provider.provide_dismissed_alerts_ticket_ids_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return response.json()

    def get_alerts_ticket_ids_from_cases_closed_since_timestamp(
        self, timestamp_unix_ms, rule_generator,
    ):
        """Get alerts from cases that were closed since timestamp
        :param timestamp_unix_ms: {long} (e.g. 1550409785000L)
        :param rule_generator: {string} (e.g. 'Phishing email detector')
        :return: {list} alerts
        """
        request_dict = {
            "time_stamp_unix_ms": str(timestamp_unix_ms),
            "rule_generator": rule_generator,
            "include_dismissed_alerts": False,
        }
        address = self.address_provider.provide_close_case_alerts_ticket_ids_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return response.json()

    def get_alerts_ticket_ids_by_case_id(self, case_id):
        """Get alert ticket ids for a specific case (distinct)
        :param case_id: {long} (e.g. 1201)
        :return: {list} alert ticket ids
        """
        address = self.address_provider.provide_case_alerts_ticket_ids_address(case_id)
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def change_case_stage(self, stage, case_id, alert_identifier):
        """Change case stage
        :param stage: {string} (e.g. Incident)
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "stage": stage,
        }
        address = self.address_provider.provide_change_case_stage_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def change_case_priority(self, priority, case_id, alert_identifier):
        """Change case priority
        :param priority: {int} {"Low": 40, "Medium": 60, "High": 80, "Critical": 100}
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "priority": priority,
        }
        address = self.address_provider.provide_change_case_priority_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def close_case(self, root_cause, comment, reason, case_id, alert_identifier):
        """Close case
        :param root_cause: {string} close case root cause
        :param comment: {string} comment
        :param reason: {string} close case reason
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "root_cause": root_cause,
            "comment": comment,
            "reason": reason,
        }
        address = self.address_provider.provide_close_case_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def get_case_closure_details(self, case_id_list):
        """Get case closure details
        :param case_id_list: {list} of case ids {string}
        :return: {list| of case closure details {dict}
        """
        address = self.address_provider.provide_get_case_closure_details_address()
        response = self.session.post(address, json=case_id_list)
        self.validate_siemplify_error(response)
        return response.json()

    def dismiss_alert(
        self,
        alert_group_identifier,
        should_close_case_if_all_alerts_were_dismissed,
        case_id,
    ):
        """Dismiss alert
        :param alert_group_identifier:
        :param should_close_case_if_all_alerts_were_dismissed:
        :param case_id: {string/int} case identifier
        """
        # Not supported
        request_dict = {
            "case_id": str(case_id),
            "alert_group_identifier": alert_group_identifier,
            "should_close_case_if_all_alerts_were_dismissed": should_close_case_if_all_alerts_were_dismissed,
        }
        address = self.address_provider.provide_dismiss_alert_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def close_alert(self, root_cause, comment, reason, case_id, alert_id):
        """Close alert
        :param root_cause: {string} close case root cause
        :param comment: {string} comment
        :param reason: {string} close case reason
        :param case_id: {string} case identifier
        :param alert_id: {string} alert identifier
        """
        request_dict = {
            "source_case_id": str(case_id),
            "alert_identifier": alert_id,
            "root_cause": root_cause,
            "reason": reason,
            "comment": comment,
        }
        address = self.address_provider.provide_close_alert_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return response.json()

    def add_entity_insight(self, domain_entity_info, message, case_id, alert_id):
        """Add insight
        :param domain_entity_info: {entity}
        :param message: {string} insight message
        :param case_id: {string} case identifier
        :param alert_id: {string} alert identifier
        :return: {boolean} True if success
        """
        if "ThreatSource" in domain_entity_info.additional_properties:
            threat_source = domain_entity_info.additional_properties["ThreatSource"]
        else:
            threat_source = INSIGHT_DEFAULT_THREAT_SOURCE

        # severity: 0=info, 1 = warning, 2 = error
        # types: #0 = general, 1 = Entity
        return self.create_case_insight_internal(
            case_id=case_id,
            alert_identifier=alert_id,
            triggered_by=threat_source,
            title="Entity insight",
            content=message,
            entity_identifier=domain_entity_info.identifier,
            severity=InsightSeverity.WARN,
            insight_type=InsightType.Entity,
        )

    def create_case_insight_internal(
        self,
        case_id,
        alert_identifier,
        triggered_by,
        title,
        content,
        entity_identifier,
        severity,
        insight_type,
        additional_data=None,
        additional_data_type=None,
        additional_data_title=None,
        original_requesting_user=None,
        entity_type=None,
    ):
        """Add insight
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        :param triggered_by: {string} integration name
        :param title: {string} insight title
        :param content: {string} insight message
        :param entity_identifier: {string} entity identifier
        :param severity: {int}  0=info, 1 = warning, 2 = error
        :param insight_type: {int} 0 = general, 1 = Entity
        :param additional_data:
        :param additional_data_type:
        :param additional_data_title:
        :param original_requesting_user:
        :param entity_type: {string} "ADDRESS"
        :return: {boolean} True if success
        """
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "triggered_by": triggered_by,
            "title": title,
            "content": content,
            "entity_identifier": entity_identifier,
            "severity": severity,
            "type": insight_type,
            "entity_type": entity_type,
            "additional_data": additional_data,
            "additional_data_type": additional_data_type,
            "additional_data_title": additional_data_title,
            "original_requesting_user": original_requesting_user,
        }
        address = self.address_provider.provide_create_case_insight_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return True

    def escalate_case(self, comment, case_id, alert_identifier):
        """Escalate case
        :param comment: {string} escalate comment
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "comment": comment,
        }
        # This endpoint in not mapped in the server
        address = "{0}/{1}".format(
            self.API_ROOT, "external/v1/sdk/Escalate?format=snake",
        )
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return json.loads(response.text)

    def mark_case_as_important(self, case_id, alert_identifier):
        """Mark case as important
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        request_dict = {"case_id": case_id, "alert_identifier": alert_identifier}
        address = self.address_provider.provide_mark_case_as_important_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def raise_incident(self, case_id, alert_identifier):
        """Raise incident
        :param case_id: {string} case identifier
        :param alert_identifier: {string} alert identifier
        """
        request_dict = {"case_id": case_id, "alert_identifier": alert_identifier}
        address = self.address_provider.provide_raise_incident_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def end(self, message, result_value, execution_state=EXECUTION_STATE_COMPLETED):
        """Ends the script
        :param message: output message to be displayed to the client
        :param result_value: return value (can be int/string/dict)
        :param execution_state: {int} default - 0 (completed)
        :return: returning the result data to the host process.
        """
        self.result.message = message
        self.result.result_value = result_value
        self.result.execution_state = execution_state
        self.remove_temp_folder()
        self.end_script()

    def end_script(self):
        """Deprecated - do not use. Kept for backwards compatibility with old scripts
        """
        output_object = self._build_output_object()
        SiemplifyUtils.real_stdout.write(json.dumps(output_object))
        sys.exit(0)

    @staticmethod
    def _remap_keys(result_object):
        """Maps result object to result object json serializable
        :param result_object: {dict} dict of entities and results, keys are tuple (identifier, type)
        """
        result_object_remaped = {}
        for result_key, result_val in result_object.items():
            # Check if the json result is not a tuple and is a JsonResult, therefore is from a remote action(string)
            if not isinstance(result_key, tuple) and result_key == JSON_RESULT_KEY:
                k = result_key
            # In case the key is not a Json result;
            elif result_key[0] != JSON_RESULT_KEY:
                k = f"{result_key[0]}_{result_key[1]}"
            # In case the key is a json result
            else:
                k = result_key[0]
            result_object_remaped[k] = result_val
        return result_object_remaped

    def _build_output_object(self):
        """Kept for backwards compatibility with old scripts
        """
        if self.result.support_old_entities:
            result = self.result._result_object
        else:
            result = self._remap_keys(self.result._result_object)
        output_object = {
            "Message": self.result.message,
            "ResultObjectJson": json.dumps(result),
            "ResultValue": self.result.result_value,
            "DebugOutput": SiemplifyUtils.my_stdout.getvalue(),
            "ExecutionState": self.result.execution_state,
        }
        return output_object

    def get_configuration(self, provider, environment=None, integration_instance=None):
        """Get integration configuration
        :param provider: {string} integration name (e.g. "VirusTotal")
        :param environment: {string} configuration for specific environment or 'all'
        :param integration_instance: {string} the identifier of the integration instance.
        :return: {dict} configuration details
        """
        configuration = self.get_configuration_from_server(
            integration_instance, provider,
        )
        if self.vault_settings is None:
            return configuration

        return self.load_vault_settings(configuration)

    def load_vault_settings(self, configurations):
        # we import SiemplifyVaultUtils only when needed, in order to not import dependencies which are not needed
        self.LOGGER.info("Importing SiemplifyVaultUtils to extract vault params")
        import SiemplifyVaultUtils

        for key, value in list(configurations.items()):
            configurations[key] = SiemplifyVaultUtils.extract_vault_param(
                value, self.vault_settings,
            )
        return configurations

    def get_configuration_from_server(self, integration_instance, provider):
        # if we have the instance identifier, we will use it (integration_instance).
        # If not we will use the instance name instead (provider)
        self.LOGGER.info("Reading configuration from Server")
        identifier = integration_instance if integration_instance else provider
        address = self.address_provider.provide_get_integration_configuration_address(
            identifier,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        configurations = response.json()
        return configurations

    def get_configuration_by_provider(self, identifier):
        """Get integration configuration
        :param provider: {string} integration name (e.g. "VirusTotal")
        :return: {dict} configuration details
        """
        return self.get_configuration_from_server(
            integration_instance=None, provider=identifier,
        )

    def get_system_info(self, start_time_unixtime_ms):
        address = self.address_provider.provide_get_system_info_address(
            start_time_unixtime_ms,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        system_info = response.json()

        return system_info

    def get_system_version(self):
        address = self.address_provider.provide_get_system_version_address()
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        system_version = response.json()

        return system_version

    def get_external_configuration(self, config_provider, config_name):
        """Get external integration configuration
        :param config_provider: {string}
        :param config_name: {string}
        """
        with open(
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                EXTERNAL_CONFIG_PROVIDER_FILE,
            ),
        ) as f:
            external_providers = json.loads(f.read())

        if config_provider not in external_providers:
            raise Exception(
                f"Config provider {config_provider} is not configured as an"
                " external config provider in Siemplify SDK.",
            )

        try:
            import imp

            SiemplifyUtils.link_brother_envrionment(self, config_provider)
            integration_name = f"{config_provider}_V{self.get_integration_version(config_provider)!s}"
            module_name = external_providers[config_provider]["manager_module_name"]
            module_path = os.path.join(
                *[
                    os.path.dirname(os.path.abspath(__file__)),
                    "IntegrationsVirtualEnvironment",
                    integration_name,
                    f"{module_name}.py",
                ],
            )
            mod = imp.load_source(module_name, module_path)
        except ImportError:
            raise Exception(
                f"Module not found. Integration of {config_provider} might not be installed.",
            )
        try:
            manager_class = getattr(
                mod, external_providers[config_provider]["manager_class_name"],
            )
        except AttributeError:
            raise Exception(
                f"Incorrect manager class name for provider {config_provider}",
            )

        provider_integration_config = self.get_configuration_by_provider(
            config_provider,
        )
        return manager_class.get_config_siemplify(
            config_name, **provider_integration_config,
        )

    def create_case(self, case_info):
        """Create case
        :param case_info: {dict} case details
        """
        address = self.address_provider.provide_create_case_address()
        response = self.session.post(address, json=case_info)
        self.validate_siemplify_error(response)

    def add_entity_to_case(
        self,
        case_id,
        alert_identifier,
        entity_identifier,
        entity_type,
        is_internal,
        is_suspicous,
        is_enriched,
        is_vulnerable,
        properties,
        environment,
    ):
        """:param case_id: {string} case identifier
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
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "entity_identifier": entity_identifier,
            "entity_type": entity_type,
            "is_internal": is_internal,
            "is_suspicious": is_suspicous,
            "is_enriched": is_enriched,
            "is_vulnerable": is_vulnerable,
            "properties": properties,
            "environment": environment,
        }

        address = self.address_provider.provide_create_entity_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def attach_workflow_to_case(
        self, workflow_name, cyber_case_id, indicator_identifier,
    ):
        """Attach workflow to case
        :param workflow_name: {string} workflow name
        :param cyber_case_id: {string} case identifier
        :param indicator_identifier: {string} alert_identifier
        """
        request_dict = {
            "wf_name": workflow_name,
            "should_run_automatic": True,
            "cyber_case_id": str(cyber_case_id),
            "alert_identifier": indicator_identifier,
        }
        address = self.address_provider.provide_attach_workflow_to_case_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return json.loads(response.text)

    def send_system_notification(
        self, message, message_id=SYSTEM_NOTIFICATION_CUSTOM_MESSAGE_ID,
    ):
        """Send system notification with optional message id
        :param message: {string} notification message
        :param message_id: {string} notification message identifier
        """
        request_dict = {
            "message": str(message)[:SYSTEM_NOTIFICATION_MESSAGE_CHAR_LIMIT],
            "message_id": str(message_id)[:SYSTEM_NOTIFICATION_MESSAGE_ID_CHAR_LIMIT],
        }
        address = self.address_provider.provide_send_system_notification_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def send_system_notification_message(self, message, message_id):
        self.send_system_notification(message, message_id)

    def get_cases_by_ticket_id(self, ticket_id):
        """Get case by ticket identifier
        :param ticket_id: {string} ticket identifier
        :return case_ids
        """
        cases_filter = CasesFilter(ticked_ids_free_search=ticket_id)
        address = self.address_provider.provide_get_cases_by_filter_address()
        response = self.session.post(address, json=cases_filter.__dict__)
        self.validate_siemplify_error(response)
        return json.loads(response.text)

    @staticmethod
    def generate_serialized_object(object_filter):
        lists_to_edit = [
            attr
            for attr in dir(object_filter)
            if not isinstance(getattr(object_filter, attr), Callable)
            and not attr.startswith("__")
            and isinstance(object_filter.__getattribute__(attr), list)
        ]
        for filter_list_attr in lists_to_edit:
            filter_list = object_filter.__getattribute__(filter_list_attr)
            case_filter_list = []
            for value in filter_list:
                case_filter_value = CaseFilterValue(value, value)
                case_filter_list.append(case_filter_value)
            object_filter.__setattr__(filter_list_attr, case_filter_list)
        return eval(json.dumps(object_filter, default=lambda a: a.__dict__))

    def get_cases_by_filter(
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
        """Get cases by filter (environment, tag, assigned user, status, priority, case name.
        :param environments: {list} of strings (environment)
        :param analysts: {list} of strings (case assigned user/role)
        :param statuses: {list} of ints (1=open, 2=close)
        :param case_names: {list} of strings (case names)
        :param tags: {list} of case tags(strings)
        :param priorities: {list} of priorities (ints)
        :param stages: {list} of stages (strings)
        :param case_types: {list} of types (strings)
        :param products: {list} of products (strings)
        :param networks: {list} of network (strings)
        :param ticked_ids_free_search: {string} ticket identifier
        :param case_ids_free_search: {string} case identifier
        :param wall_data_free_search:
        :param entities_free_search: {string} entity identifier
        :param start_time_unix_time_in_ms: {long}
        :param end_time_unix_time_in_ms: {long}
        :return: case_ids
        """
        case_filter = CasesFilter(
            environments,
            analysts,
            statuses,
            case_names,
            tags,
            priorities,
            stages,
            case_types,
            products,
            networks,
            ticked_ids_free_search,
            case_ids_free_search,
            wall_data_free_search,
            entities_free_search,
            start_time_unix_time_in_ms,
            end_time_unix_time_in_ms,
        )
        address = self.address_provider.provide_get_cases_by_filter_address()
        obj = self.generate_serialized_object(case_filter)
        response = self.session.post(address, json=obj)
        self.validate_siemplify_error(response)
        return json.loads(response.text)

    def get_case_comments(self, case_id):
        """Get case comments
        :param case_id: {string} case identifier
        :return:
        """
        address = self.address_provider.provide_get_case_comments_address(case_id)
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return json.loads(response.text)

    def fetch_case_comments(self, case_id, time_filter_type=None, from_timestamp=None):
        """Fetches case comments
        :param case_id: {string} case identifier
        :param time_filter_type: {int} specify the creation or modification time to apply search from a specific time.
        options are "Creation=0" or "Modification=1"
        :param from_timestamp: {int} time filter from comment creation/modification, in unix timestamp
        :return:
        """
        # TODO (b/392402216): This is not part of the SDK controller
        # Need to map it to the 1P comments url
        address = "{0}/{1}{2}".format(
            self.API_ROOT,
            "external/v1/cases/comments",
            "?format=snake&caseId=" + str(case_id),
        )
        if time_filter_type is not None:
            address += "&spec.timeFilterType=" + str(time_filter_type)

        if from_timestamp is not None:
            address += "&spec.fromTimestamp=" + str(from_timestamp)

        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return json.loads(response.text)

    def check_marketpalce_status(self):
        """Check marketplace status
        :return:
        """
        address = self.address_provider.provide_check_marketplace_status_address()
        response = self.session.get(address)
        self.validate_siemplify_error(response)

    def add_or_update_case_task(self, task):
        """Add or update a task case: if there's a task id - update, if not - create.
        :param task: {Task} the task object which should be added to the case or updated
        :return: {int} the id of the new/updated task
        """
        address = self.address_provider.provide_add_or_update_case_task_address()
        response = self.session.post(address, json=task.__dict__)
        self.validate_siemplify_error(response)
        return int(response.content)

    def get_case_tasks(self, case_id):
        """Retrieve all tasks by case id
        :param case_id: {int/str} the case id, the function can receive either int or str
        :return: {list} the list of tasks belonging to the case
        """
        # Allow the user the pass the case_id as either int or str, and convert any to int
        case_id = int(case_id)

        address = self.address_provider.provide_get_case_tasks_address(case_id)
        response = self.session.get(address)
        self.validate_siemplify_error(response)

        task_dicts = json.loads(response.text)

        # Create Task objects from the task dicts
        tasks = [Task(**task_dict) for task_dict in task_dicts]

        return tasks

    def any_entity_in_custom_list(self, custom_list_items):
        """Check if there's any entity from the given list, which has
        a custom list record with the given category.
        :param custom_list_items: a list of custom list items
        :return: True if there's an entity found, false otherwise
        """
        custom_list_items_data = []
        for cli in custom_list_items:
            custom_list_items_data.append(cli.__dict__)

        address = self.address_provider.provide_any_entity_in_list_address()
        response = self.session.post(address, json=custom_list_items_data)
        self.validate_siemplify_error(response)
        return response.text.lower() == "true"

    def add_entities_to_custom_list(self, custom_list_items):
        """Add the entities to the custom list with the given category.
        :param custom_list_items: a list of custom list items
        :return: {list}
        """
        custom_list_items_data = []
        for cli in custom_list_items:
            custom_list_items_data.append(cli.__dict__)

        address = self.address_provider.provide_add_entities_to_list_address()
        response = self.session.post(address, json=custom_list_items_data)
        self.validate_siemplify_error(response)

        custom_list_dicts = response.json()

        # Create CustomList objects from the custom list dicts
        custom_lists = [
            CustomList(**custom_list_dict) for custom_list_dict in custom_list_dicts
        ]
        return custom_lists

    def remove_entities_from_custom_list(self, custom_list_items):
        """Remove the entities from the custom list with the given category.
        :param custom_list_items: a list of custom list items
        :return: None
        """
        custom_list_items_data = []
        for cli in custom_list_items:
            custom_list_items_data.append(cli.__dict__)

        address = self.address_provider.provide_remove_entities_from_list_address()
        response = self.session.post(address, json=custom_list_items_data)
        self.validate_siemplify_error(response)

        custom_list_dicts = response.json()

        # Create CustomList objects from the custom list dicts
        custom_lists = [
            CustomList(**custom_list_dict) for custom_list_dict in custom_list_dicts
        ]
        return custom_lists

    def get_existing_custom_list_categories(self):
        """Get all existing custom list categories
        :return: {list} list of existing categories
        """
        address = self.address_provider.provide_get_custom_categories_address()
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def is_existing_category(self, category):
        """Check if the given category exists
        :param category: category to check
        :return: True if exists, False otherwise
        """
        categories = self.get_existing_custom_list_categories()
        return category in categories

    def get_remote_connector_keys_map(self, publisher_id):
        """Get remote connectors encryption keys by publisher id
        :param publisher_id: {str} The id of the publisher
        :return: {dict} The keys map
        """
        address = self.address_provider.provide_get_remote_connectors_keys_map_address(
            publisher_id,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_publisher_by_id(self, publisher_id):
        """Get publisher details by id
        :param publisher_id: {str} The id of the publisher
        :return: {dict} The publisher details
        """
        address = self.address_provider.provide_get_publisher_by_id_address(
            publisher_id,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_agent_by_id(self, agent_id):
        """Get agent details by id
        :param agent_id: {str} The id of the agent
        :return: {dict} The publisher details
        """
        address = self.address_provider.provide_get_agent_by_id_address(agent_id)
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_integration_version(self, integration_identifier):
        """Get integration version
        :param integration_identifier: {string} integration identifier
        :return: {float| integration version
        """
        address = self.address_provider.provide_get_integration_version_address(
            integration_identifier,
        )
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def extract_configuration_param(
        self,
        provider_name,
        param_name,
        default_value=None,
        input_type=str,
        is_mandatory=False,
        print_value=False,
    ):
        if not provider_name:
            raise Exception(r"provider_name cannot be None\empty")

        configuration = self.get_configuration(provider_name)
        return SiemplifyUtils.extract_script_param(
            siemplify=self,
            input_dictionary=configuration,
            param_name=param_name,
            default_value=default_value,
            input_type=input_type,
            is_mandatory=is_mandatory,
            print_value=print_value,
        )

    def create_connector_package(self, connector_package):
        """Create connector package in system
        :param connector_package: {string} Connector package as a json
        """
        address = self.address_provider.provide_create_connector_package_address()

        response = self.session.post(address, json=connector_package)
        self.validate_siemplify_error(response)

    def add_agent_connector_logs(self, agent_id, connector_id, logs_package):
        """Add logs of the remote agent's @connector_id connector
        :param agent_id: {string} Agent's identifier
        :param connector_id: {string} Connector instance identifier
        :param logs_package: {dict} ConnectorLogPackage
        """
        address = self.address_provider.provide_add_agent_connector_logs_address(
            agent_id, connector_id,
        )
        response = self.session.post(address, json=logs_package)
        self.validate_siemplify_error(response)

    def get_cases_ids_by_filter(
        self,
        status,
        start_time_from_unix_time_in_ms=None,
        start_time_to_unix_time_in_ms=None,
        close_time_from_unix_time_in_ms=None,
        close_time_to_unix_time_in_ms=None,
        update_time_from_unix_time_in_ms=None,
        update_time_to_unix_time_in_ms=None,
        operator=None,
        sort_by=CaseFilterSortByEnum.START_TIME,
        sort_order=CaseFilterSortOrderEnum.DESC,
        max_results=1000,
        environments=None,
        tags=None,
    ):
        """Get cases ids by filter
        :param status: {str} Case status to retrieve. Possible values: OPEN, CLOSE, BOTH - Mandatory
        :param start_time_from_unix_time_in_ms: {int} Case start time start range inclusive. Default is 30 days backwards
        :param start_time_to_unix_time_in_ms: {int} Case start time end range inclusive. Default is time now
        :param close_time_from_unix_time_in_ms: {int} Case close time start range inclusive. Default is 30 days backwards
        :param close_time_to_unix_time_in_ms: {int} Case close time end range inclusive. Default is time now
        :param update_time_from_unix_time_in_ms: {int} Case modification time start range inclusive. Default is start time
        :param update_time_to_unix_time_in_ms: {int} Case modification time end range inclusive. Default is time now
        :param operator: {str} Operator for time filters. Possible values: OR, AND
        :param sort_by: {str} Sort results by time. Possible values: START_TIME, UPDATE_TIME, CLOSE_TIME
        :param sort_order: {str} Sort order. Possible values: ASC, DESC. Default is descending order
        :param max_results: {int} Max results to return. Default value is 1000, maximum value is 10000
        :param environments: {str[]} One or more environment filter. e.g ['Environment A', 'Environment B']
        :param tags: {str[]} One or more tags to filter. e.g ['Tag A', 'Tag B']

        Notes:
              - Sort order of type CLOSE_TIME must be provided with 'CLOSE' status only
              - Close time range filter is disregarded with 'BOTH' and 'OPEN' statues

        """
        max_results = min(max_results, CASE_FILTER_MAX_RESULTS)

        if max_results <= 0:
            raise Exception("'max_results' must be positive")

        # case start time validation
        if start_time_from_unix_time_in_ms is None:
            start_time_from_unix_time_in_ms = convert_datetime_to_unix_time(
                utc_now() - timedelta(days=30),
            )  # 30 days backwards
        elif not SiemplifyUtils.is_unixtimestamp_valid(start_time_from_unix_time_in_ms):
            raise Exception("'start_time_from_unix_time_in_ms' timestamp is invalid")

        if start_time_to_unix_time_in_ms is None:
            start_time_to_unix_time_in_ms = unix_now()
        elif not SiemplifyUtils.is_unixtimestamp_valid(start_time_to_unix_time_in_ms):
            raise Exception("'start_time_to_unix_time_in_ms' timestamp is invalid")
        elif start_time_to_unix_time_in_ms < start_time_from_unix_time_in_ms:
            raise Exception(
                "'start_time_to_unix_time_in_ms' timestamp cannot be smaller than 'start_time_from_unix_time_in_ms'",
            )

        # case close time validation
        if close_time_from_unix_time_in_ms is not None:
            if not SiemplifyUtils.is_unixtimestamp_valid(
                close_time_from_unix_time_in_ms,
            ):
                raise Exception(
                    "'close_time_from_unix_time_in_ms' timestamp is invalid",
                )
            if status == CaseFilterStatusEnum.OPEN:
                raise Exception(
                    f"'close_time_from_unix_time_in_ms' cannot be provided if cases status filter is {status}",
                )

        if close_time_to_unix_time_in_ms is not None:
            if not SiemplifyUtils.is_unixtimestamp_valid(close_time_to_unix_time_in_ms):
                raise Exception("'close_time_to_unix_time_in_ms' timestamp is invalid")
            if close_time_from_unix_time_in_ms is None:
                raise Exception(
                    "'close_time_to_unix_time_in_ms' timestamp provided without 'close_time_from_unix_time_in_ms'",
                )
            if close_time_to_unix_time_in_ms < close_time_from_unix_time_in_ms:
                raise Exception(
                    "'close_time_to_unix_time_in_ms' timestamp cannot be smaller than 'close_time_from_unix_time_in_ms'",
                )

        # case update time validation
        if (
            update_time_from_unix_time_in_ms is not None
            and not SiemplifyUtils.is_unixtimestamp_valid(
                update_time_from_unix_time_in_ms,
            )
        ):
            raise Exception("'update_time_from_unix_time_in_ms' timestamp is invalid")

        if (
            update_time_to_unix_time_in_ms is not None
            and not SiemplifyUtils.is_unixtimestamp_valid(
                update_time_to_unix_time_in_ms,
            )
        ):
            raise Exception("'update_time_to_unix_time_in_ms' timestamp is invalid")

        if status not in [
            CaseFilterStatusEnum.OPEN,
            CaseFilterStatusEnum.CLOSE,
            CaseFilterStatusEnum.BOTH,
        ]:
            raise Exception(
                "'status' must be either one of the values: {}".format(
                    ", ".join(
                        [
                            CaseFilterStatusEnum.OPEN,
                            CaseFilterStatusEnum.CLOSE,
                            CaseFilterStatusEnum.BOTH,
                        ],
                    ),
                ),
            )

        if operator is not None and operator not in [
            CaseFilterOperatorEnum.OR,
            CaseFilterOperatorEnum.AND,
        ]:
            raise Exception(
                "'operator' must be either one of the values: {}".format(
                    ", ".join([CaseFilterOperatorEnum.OR, CaseFilterOperatorEnum.AND]),
                ),
            )

        if sort_by not in [
            CaseFilterSortByEnum.START_TIME,
            CaseFilterSortByEnum.CLOSE_TIME,
            CaseFilterSortByEnum.UPDATE_TIME,
        ]:
            raise Exception(
                "'sort_by' must be either one of the values: {}".format(
                    ", ".join(
                        [
                            CaseFilterSortByEnum.START_TIME,
                            CaseFilterSortByEnum.CLOSE_TIME,
                            CaseFilterSortByEnum.UPDATE_TIME,
                        ],
                    ),
                ),
            )

        if sort_order is not None and sort_order not in [
            CaseFilterSortOrderEnum.ASC,
            CaseFilterSortOrderEnum.DESC,
        ]:
            raise Exception(
                "'sort_order' must be either {}".format(
                    ", ".join(
                        [CaseFilterSortOrderEnum.ASC, CaseFilterSortOrderEnum.DESC],
                    ),
                ),
            )

        if sort_order is None:
            sort_order = CaseFilterSortOrderEnum.DESC

        if (
            status == CaseFilterStatusEnum.OPEN
            and sort_by == CaseFilterSortByEnum.CLOSE_TIME
        ):
            raise Exception(
                "Case status 'OPEN' cannot be provided with 'CLOSE_TIME' sort by filter type",
            )

        payload = {
            "start_time_from_unix_time_in_ms": start_time_from_unix_time_in_ms,
            "start_time_to_unix_time_in_ms": start_time_to_unix_time_in_ms,
            "close_time_from_unix_time_in_ms": close_time_from_unix_time_in_ms,
            "close_time_to_unix_time_in_ms": close_time_to_unix_time_in_ms,
            "update_time_from_unix_time_in_ms": update_time_from_unix_time_in_ms,
            "update_time_to_unix_time_in_ms": update_time_to_unix_time_in_ms,
            "status": status,
            "operator": operator,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "max_results": max_results,
            "environments": environments,
            "tags": tags,
        }

        address = self.address_provider.provide_get_cases_ids_by_filter_address()
        response = self.session.post(address, json=payload)
        self.validate_siemplify_error(response)
        return response.json()

    def get_temp_folder_path(self):
        if not self.temp_folder_path:
            self.temp_folder_path = tempfile.mkdtemp(suffix=str(uuid.uuid4()))
        return self.temp_folder_path

    def remove_temp_folder(self):
        if self.temp_folder_path and os.path.exists(self.temp_folder_path):
            shutil.rmtree(self.temp_folder_path)

    def termination_signal_handler(self, sig, _):
        self.LOGGER.warning(f"Termination signal [{sig}] received, exiting...")
        self.remove_temp_folder()
        sys.exit(-self.SIGNAL_CODES[sig])

    def get_updated_sync_cases_metadata(
        self, start_timestamp_unix_ms, count, allowed_environments=None, vendor=None,
    ):
        """Retrieve updated tracked cases metadata.
        :param start_timestamp_unix_ms: {long} Search for updated cases starting at @start_timestamp_unix_ms or later.
        :param count: {int} Maximum cases ids to fetch.
        :param allowed_environments: {list} Environments to search in. If allowed_environments is None, search in all
        environments.
        :param vendor: {string} Return only cases with alerts originate in @vendor.
        :return: {list} List of SyncCaseMetadata objects, sorted by SyncCaseMetadata.tracking_time.
        """
        address = self.address_provider.provide_get_sync_cases_metadata_address()
        request = {
            "start_timestamp_unix_ms": start_timestamp_unix_ms,
            "items_count": count,
            "allowed_environments": allowed_environments,
            "vendor": vendor,
        }
        response = self.session.get(address, json=request)
        self.validate_siemplify_error(response)

        raw_cases_metadata = response.json()
        cases_metadata = [
            SyncCaseMetadata(
                str(raw_case["id"]), int(raw_case["tracking_time_unix_time_in_ms"]),
            )
            for raw_case in raw_cases_metadata
        ]
        return cases_metadata

    def get_sync_cases(self, case_ids):
        """Retrieve cases information needed for systems synchronization.
        :param case_ids: {list} A list of case IDs to retrieve.
        """
        address = self.address_provider.provide_get_sync_cases_address()

        if not case_ids:
            return []

        request = {"case_ids": case_ids}
        response = self.session.get(address, json=request)
        self.validate_siemplify_error(response)

        raw_cases = response.json()
        cases = [
            SyncCase(
                int(raw_case["id"]),
                str(raw_case["environment"]),
                int(raw_case["priority"]),
                str(raw_case["stage"]),
                int(raw_case["status"]),
                str(raw_case["external_case_id"]),
                str(raw_case["title"]),
            )
            for raw_case in raw_cases
        ]
        return cases

    def batch_update_case_id_matches(self, case_id_matches):
        """Batch update of cases with the suitable external case ids.
        :param case_id_matches: {list} List of SyncCaseIdMatch objects.
        :return: {list} List of case ids which were updated successfully.
        """
        address = self.address_provider.provide_update_cases_address()

        request = {
            "case_ids_matches": [
                case_id_match.__dict__ for case_id_match in case_id_matches
            ],
        }
        response = self.session.post(address, json=request)
        self.validate_siemplify_error(response)
        return response.json()

    def get_updated_sync_alerts_metadata(
        self,
        start_timestamp_unix_ms,
        count,
        allowed_environments=None,
        vendor=None,
        include_non_synced_alerts=True,
    ):
        """Retrieve updated tracked alerts metadata.
        :param start_timestamp_unix_ms: {long} Search for updated alerts starting at @start_timestamp_unix_ms or later.
        :param count: {int} Maximum alerts group ids to fetch.
        :param allowed_environments: {list} Environments to search in. If allowed_environments is None, search in all
        environments.
        :param vendor: {string} Filter alerts by @vendor.
        :param include_non_synced_alerts: {bool} If true, include alerts which have not synced with Chronicle SIEM
        yet, otherwise, exclude them.
        :return: {list} List of SyncAlertMetadata objects, sorted by SyncAlertMetadata.tracking_time.
        """
        address = self.address_provider.provide_get_sync_alerts_metadata_address()
        request = {
            "start_timestamp_unix_ms": start_timestamp_unix_ms,
            "items_count": count,
            "allowed_environments": allowed_environments,
            "vendor": vendor,
            "include_non_synced_alerts": include_non_synced_alerts,
        }
        response = self.session.get(address, json=request)
        self.validate_siemplify_error(response)

        raw_alerts_metadata = response.json()
        alerts_metadata = [
            SyncAlertMetadata(
                str(raw_alert["group_id"]),
                int(raw_alert["tracking_time_unix_time_in_ms"]),
            )
            for raw_alert in raw_alerts_metadata
        ]
        return alerts_metadata

    def get_sync_alerts(self, alert_group_ids):
        """Retrieve alerts information needed for systems synchronization.
        :param alert_group_ids: {list} A list of alert group IDs to retrieve.
        """
        address = self.address_provider.provide_get_sync_alerts_address()

        if not alert_group_ids:
            return []

        request = {"alert_group_ids": alert_group_ids}
        response = self.session.get(address, json=request)
        self.validate_siemplify_error(response)

        raw_alerts = response.json()
        alerts = [
            SyncAlert(
                str(raw_alert["group_id"]),
                str(raw_alert["id"]),
                int(raw_alert["case_id"]),
                str(raw_alert["environment"]),
                int(raw_alert["priority"]),
                int(raw_alert["status"]),
                str(raw_alert["ticket_id"]),
                int(raw_alert["creation_time_unix_time_in_ms"]),
                None
                if raw_alert["close_comment"] is None
                else str(raw_alert["close_comment"]),
                None
                if raw_alert["close_reason"] is None
                else int(raw_alert["close_reason"]),
                None
                if raw_alert["close_root_cause"] is None
                else str(raw_alert["close_root_cause"]),
                None
                if raw_alert["close_usefulness"] is None
                else int(raw_alert["close_usefulness"]),
                None
                if raw_alert.get("siem_alert_id") is None
                else str(raw_alert["siem_alert_id"]),
            )
            for raw_alert in raw_alerts
        ]
        return alerts

    def set_case_sla(
        self,
        period_time,
        period_type,
        critical_period_time,
        critical_period_type,
        case_id,
    ):
        """Sets the SLA of the given @case_id. SLA being set using this API should surpass all other case SLA types.
        :param period_time: {int/string} Represents the total SLA period. period_time > 0.
        :param period_type: {string} Represents the time units of @period_time, represented by ApiPeriodTypeEnum.
        :param critical_period_time: {int/string} Represents the critical SLA period. critical_period_time >= 0.
        : Critical period (after scaling with its time units) should be smaller than the total period.
        :param critical_period_type: {string} Represents the time units of @critical_period_time, represented by
        : ApiPeriodTypeEnum.
        :param case_id: {long}
        """
        if not ApiPeriodTypeEnum.validate(period_type):
            raise Exception(
                f"SLA period type is invalid, valid values are: {ApiPeriodTypeEnum.values()!s}.",
            )

        if not ApiPeriodTypeEnum.validate(critical_period_type):
            raise Exception(
                f"SLA time to critical period type is invalid, valid values are: {ApiPeriodTypeEnum.values()!s}.",
            )

        address = self.address_provider.provide_set_case_sla_address(case_id)
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        response = self.session.post(address, json=request)
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            self.LOGGER.error(f"Could not set case sla: {e}")
            response_content = response.content
            result = ""
            try:
                # Parse fluent validation errors if exist.
                errors = set()
                errors_json = json.loads(response_content)
                errors_by_param = errors_json["errors"]
                for error_param, error_messages in errors_by_param.items():
                    errors.update(error_messages)
                for error_message in errors:
                    result += error_message + ". "
            except Exception:
                # In case of unexpected failure, return the original failure.
                raise Exception(response_content)
            raise Exception(result)

    def set_alert_sla(
        self,
        period_time,
        period_type,
        critical_period_time,
        critical_period_type,
        case_id,
        alert_identifier,
    ):
        """Sets the SLA of the given @alert_identifier of @case_id. SLA being set using this API should surpass all other alert SLA types.
        :param period_time: {int/str} Represents the total SLA period. period_time > 0.
        :param period_type: {str} Represents the time units of @period_time, represented by ApiPeriodTypeEnum.
        :param critical_period_time: {int/str} Represents the critical SLA period. critical_period_time >= 0.
        : Critical period (after scaling with its time units) should be smaller than the total period.
        :param critical_period_type: {str} Represents the time units of @critical_period_time, represented by
        : ApiPeriodTypeEnum.
        :param case_id: {long}
        :param alert_identifier: {str}
        """
        if not ApiPeriodTypeEnum.validate(period_type):
            raise Exception(
                f"SLA period type is invalid, valid values are: {ApiPeriodTypeEnum.values()!s}.",
            )

        if not ApiPeriodTypeEnum.validate(critical_period_type):
            raise Exception(
                f"SLA time to critical period type is invalid, valid values are: {ApiPeriodTypeEnum.values()!s}.",
            )

        address = self.address_provider.provide_set_alert_sla_address(
            case_id, urllib.parse.quote(alert_identifier, safe=""),
        )
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        response = self.session.post(address, json=request)
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            self.LOGGER.error(f"Could not set alert sla: {e}")
            response_content = response.content
            result = ""
            try:
                # Parse fluent validation errors if exist.
                errors = set()
                errors_json = json.loads(response_content)
                errors_by_param = errors_json["errors"]
                for error_param, error_messages in errors_by_param.items():
                    errors.update(error_messages)
                for error_message in errors:
                    result += error_message + ". "
            except Exception:
                # In case of unexpected failure, return the original failure.
                raise Exception(response_content)
            raise Exception(result)

    def fetch_new_alerts_to_sync(self, batch_size=100, environments=None):
        """Fetch newly ingested alerts which are not synced with Chronicle SIEM.
        :param batch_size: {int} Maximum new alerts to fetch.
        :param environments: {list} Environments to search in. If environments is None
        or empty, search in all environments.
        :return: {list} List of alerts to sync with the SIEM instance
        """
        address = self.address_provider.provide_get_new_alerts_to_sync_address()
        request = {
            "batch_size": batch_size,
            "environments": environments,
        }
        response = self.session.get(address, json=request)
        self.validate_siemplify_error(response)

        return response.json()

    def update_new_alerts_sync_status(self, results, environments=None):
        """Update SOAR with results of SOAR alerts creation attempts in Chronicle SIEM.
        :param results: {list} A list of results representing SOAR alerts
        creation attempts in Chronicle SIEM.
        :param environments: {list} Environments that were used to fetch the
        alerts. If environments is None or empty, then, it would be considered
        as all environments.
        :return: {list} A list of the results as saved in the SOAR, in the same
        order of the input.
        """
        address = self.address_provider.provide_update_new_alerts_sync_status_address()
        request = {"results": results, "environments": environments}
        response = self.session.post(address, json=request)
        self.validate_siemplify_error(response)

        return response.json()
