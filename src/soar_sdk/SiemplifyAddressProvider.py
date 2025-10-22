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

from enum import Enum

from SiemplifySdkConfig import SiemplifySdkConfig

BASE_SDK_CONTROLLER_URL_FORMAT = "external/v1/sdk/{}"
BASE_1P_SDK_CONTROLLER_VERSION = "v1alpha"
BASE_1P_SDK_CONTROLLER_URL_FORMAT = "legacySdk:legacy{}"
FORMAT_QUERY_PARAM = "format=snake"


class SdkEndpoint(Enum):
    SET_CONTEXT_PROPERTY = "SET_CONTEXT_PROPERTY"
    TRY_SET_CONTEXT_PROPERTY = "TRY_SET_CONTEXT_PROPERTY"
    GET_CONTEXT_PROPERTY = "GET_CONTEXT_PROPERTY"
    ADD_AGENT_LOGS = "ADD_AGENT_LOGS"
    GET_FAILED_ACTIONS = "GET_FAILED_ACTIONS"
    GET_FAILED_JOBS = "GET_FAILED_JOBS"
    GET_FAILED_ETL_OPERATIONS = "GET_FAILED_ETL_OPERATIONS"
    GET_CONNECTOR_PARAMETERS = "GET_CONNECTOR_PARAMETERS"
    SET_CONNECTOR_PARAMETER = "SET_CONNECTOR_PARAMETER"
    GET_FAILED_CONNECTORS = "GET_FAILED_CONNECTORS"
    CREATE_CONNECTOR_PACKAGE = "CREATE_CONNECTOR_PACKAGE"
    SET_INTEGRATION_CONFIGURATION_PROPERTY = "SET_INTEGRATION_CONFIGURATION_PROPERTY"
    GET_INTEGRATION_CONFIGURATION = "GET_INTEGRATION_CONFIGURATION"
    GET_INTEGRATION_VERSION = "GET_INTEGRATION_VERSION"
    SEND_EMAIL_WITH_ATTACHMENT = "SEND_EMAIL_WITH_ATTACHMENT"
    GET_PROXY_SETTINGS = "GET_PROXY_SETTINGS"
    UPDATE_ENTITIES = "UPDATE_ENTITIES"
    GET_SYSTEM_INFO = "GET_SYSTEM_INFO"
    GET_SYSTEM_VERSION = "GET_SYSTEM_VERSION"
    SEND_SYSTEM_NOTIFICATION = "SEND_SYSTEM_NOTIFICATION"
    CHECK_MARKETPLACE_STATUS = "CHECK_MARKETPLACE_STATUS"
    ANY_ENTITY_IN_LIST = "ANY_ENTITY_IN_LIST"
    ADD_ENTITIES_TO_LIST = "ADD_ENTITIES_TO_LIST"
    REMOVE_ENTITIES_FROM_LIST = "REMOVE_ENTITIES_FROM_LIST"
    GET_CUSTOM_CATEGORIES = "GET_CUSTOM_CATEGORIES"
    GET_REMOTE_CONNECTORS_KEYS_MAP = "GET_REMOTE_CONNECTORS_KEYS_MAP"
    GET_PUBLISHER_BY_ID = "GET_PUBLISHER_BY_ID"
    GET_AGENT_BY_ID = "GET_AGENT_BY_ID"
    ADD_AGENT_CONNECTOR_LOGS = "ADD_AGENT_CONNECTOR_LOGS"

    # Case
    GET_CASE_METADATA = "GET_CASE_METADATA"
    GET_CASE_FULL_DETAILS = "GET_CASE_FULL_DETAILS"
    GET_CASE_ATTACHMENTS = "GET_CASE_ATTACHMENTS"
    GET_ATTACHMENT_DATA = "GET_ATTACHMENT_DATA"
    ASSIGN_USER = "ASSIGN_USER"
    ADD_TAG = "ADD_TAG"
    GET_SIMILAR_CASES_IDS = "GET_SIMILAR_CASES_IDS"
    CHANGE_CASE_STAGE = "CHANGE_CASE_STAGE"
    CHANGE_CASE_PRIORITY = "CHANGE_CASE_PRIORITY"
    CLOSE_CASE = "CLOSE_CASE"
    GET_CASE_CLOSURE_DETAILS = "GET_CASE_CLOSURE_DETAILS"
    CREATE_CASE_INSIGHT = "CREATE_CASE_INSIGHT"
    MARK_CASE_AS_IMPORTANT = "MARK_CASE_AS_IMPORTANT"
    CREATE_CASE = "CREATE_CASE"
    CREATE_ENTITY = "CREATE_ENTITY"
    ATTACH_WORKFLOW_TO_CASE = "ATTACH_WORKFLOW_TO_CASE"
    GET_CASES_BY_FILTER = "GET_CASES_BY_FILTER"
    GET_CASES_IDS_BY_FILTER = "GET_CASES_IDS_BY_FILTER"
    GET_CASE_COMMENTS = "GET_CASE_COMMENTS"
    ADD_OR_UPDATE_CASE_TASK = "ADD_OR_UPDATE_CASE_TASK"
    GET_CASE_TASKS = "GET_CASE_TASKS"
    GET_SYNC_CASES_METADATA = "GET_SYNC_CASES_METADATA"
    GET_SYNC_CASES = "GET_SYNC_CASES"
    UPDATE_CASES = "UPDATE_CASES"
    SET_CASE_SLA = "SET_CASE_SLA"
    ADD_ATTACHMENT = "ADD_ATTACHMENT"

    # Alert
    GET_ALERT_FULL_DETAILS = "GET_ALERT_FULL_DETAILS"
    UPDATE_ALERT_ADDITIONAL_DATA = "UPDATE_ALERT_ADDITIONAL_DATA"
    GET_DISMISSED_ALERTS_TICKET_IDS = "GET_DISMISSED_ALERTS_TICKET_IDS"
    GET_CLOSE_CASE_ALERTS_TICKET_IDS = "GET_CLOSE_CASE_ALERTS_TICKET_IDS"
    GET_CASE_ALERTS_TICKET_IDS = "GET_CASE_ALERTS_TICKET_IDS"
    DISMISSED_ALERT = "DISMISSED_ALERT"
    CLOSE_ALERT = "CLOSE_ALERT"
    RAISE_INCIDENT = "RAISE_INCIDENT"
    GET_SYNC_ALERTS_METADATA = "GET_SYNC_ALERTS_METADATA"
    GET_SYNC_ALERTS = "GET_SYNC_ALERTS"
    SET_ALERT_SLA = "SET_ALERT_SLA"
    GET_NEW_ALERTS_TO_SYNC = "GET_NEW_ALERTS_TO_SYNC"
    UPDATE_NEW_ALERTS_SYNC_STATUS = "UPDATE_NEW_ALERTS_SYNC_STATUS"
    GET_ALERTS_FULL_DETAILS = "GET_ALERTS_FULL_DETAILS"


SDK_ENDPOINT_URLS = {
    SdkEndpoint.SET_CONTEXT_PROPERTY: "SetContextProperty",
    SdkEndpoint.TRY_SET_CONTEXT_PROPERTY: "TrySetContextProperty",
    SdkEndpoint.GET_CONTEXT_PROPERTY: "GetContextProperty",
    SdkEndpoint.ADD_AGENT_LOGS: "AddAgentLogs",
    SdkEndpoint.GET_FAILED_ACTIONS: "GetFailedActions/{}",
    SdkEndpoint.GET_FAILED_JOBS: "GetFailedJobs/{}",
    SdkEndpoint.GET_FAILED_ETL_OPERATIONS: "GetFailedETLOperations/{}",
    SdkEndpoint.GET_CONNECTOR_PARAMETERS: "connectors/{}/parameters",
    SdkEndpoint.SET_CONNECTOR_PARAMETER: "connectors/{}/parameters/{}",
    SdkEndpoint.GET_FAILED_CONNECTORS: "GetFailedConnectors",
    SdkEndpoint.CREATE_CONNECTOR_PACKAGE: "CreateConnectorPackage",
    SdkEndpoint.SET_INTEGRATION_CONFIGURATION_PROPERTY: "configuration/{}/properties/{}",
    SdkEndpoint.GET_INTEGRATION_CONFIGURATION: "configuration/{}",
    SdkEndpoint.GET_INTEGRATION_VERSION: "GetIntegrationVersion/{}",
    SdkEndpoint.SEND_EMAIL_WITH_ATTACHMENT: "SendEmailWithAttachment",
    SdkEndpoint.GET_PROXY_SETTINGS: "GetProxySettings",
    SdkEndpoint.UPDATE_ENTITIES: "UpdateEntities",
    SdkEndpoint.GET_SYSTEM_INFO: "SystemInfo/{}",
    SdkEndpoint.GET_SYSTEM_VERSION: "GetCurrentSiemplifyVersion",
    SdkEndpoint.SEND_SYSTEM_NOTIFICATION: "SendSystemNotification",
    SdkEndpoint.CHECK_MARKETPLACE_STATUS: "CheckMarketplaceStatus",
    SdkEndpoint.ANY_ENTITY_IN_LIST: "AnyEntityInCustomList",
    SdkEndpoint.ADD_ENTITIES_TO_LIST: "AddEntitiesToCustomList",
    SdkEndpoint.REMOVE_ENTITIES_FROM_LIST: "RemoveEntitiesFromCustomList",
    SdkEndpoint.GET_CUSTOM_CATEGORIES: "GetCustomListCategories",
    SdkEndpoint.GET_REMOTE_CONNECTORS_KEYS_MAP: "GetRemoteConnectorsKeysMap?publisherIdStr={}",
    SdkEndpoint.GET_PUBLISHER_BY_ID: "GetPublisherById?publisherIdStr={}",
    SdkEndpoint.GET_AGENT_BY_ID: "GetAgentById?agentIdStr={}",
    SdkEndpoint.ADD_AGENT_CONNECTOR_LOGS: "agents/{}/connectors/{}/logs",
    # Case
    SdkEndpoint.GET_CASE_METADATA: "CaseMetadata/{}",
    SdkEndpoint.GET_CASE_FULL_DETAILS: "CaseFullDetails/{}/{}",
    SdkEndpoint.GET_CASE_ATTACHMENTS: "Attachments/{}",
    SdkEndpoint.GET_ATTACHMENT_DATA: "AttachmentData/{}",
    SdkEndpoint.ASSIGN_USER: "AssignUser",
    SdkEndpoint.ADD_TAG: "AddTag",
    SdkEndpoint.GET_SIMILAR_CASES_IDS: "GetSimilarCasesIds",
    SdkEndpoint.CHANGE_CASE_STAGE: "ChangeCaseStage",
    SdkEndpoint.CHANGE_CASE_PRIORITY: "ChangePriority",
    SdkEndpoint.CLOSE_CASE: "Close",
    SdkEndpoint.GET_CASE_CLOSURE_DETAILS: "GetCaseClosureDetails",
    SdkEndpoint.CREATE_CASE_INSIGHT: "CreateCaseInsight",
    SdkEndpoint.MARK_CASE_AS_IMPORTANT: "MarkAsImportant",
    SdkEndpoint.CREATE_CASE: "CreateCase",
    SdkEndpoint.CREATE_ENTITY: "CreateEntity",
    SdkEndpoint.ATTACH_WORKFLOW_TO_CASE: "AttacheWorkflowToCase",
    SdkEndpoint.GET_CASES_BY_FILTER: "GetCasesByFilter",
    SdkEndpoint.GET_CASES_IDS_BY_FILTER: "GetCasesIdByFilter",
    SdkEndpoint.GET_CASE_COMMENTS: "GetCaseComments/{}?fetchUpdates={}",
    SdkEndpoint.ADD_OR_UPDATE_CASE_TASK: "AddOrUpdateCaseTask",
    SdkEndpoint.GET_CASE_TASKS: "GetCaseTasks/{}",
    SdkEndpoint.GET_SYNC_CASES_METADATA: "sync/cases/metadata",
    SdkEndpoint.GET_SYNC_CASES: "sync/cases",
    SdkEndpoint.UPDATE_CASES: "sync/cases/matches",
    SdkEndpoint.SET_CASE_SLA: "cases/{}/sla",
    SdkEndpoint.ADD_ATTACHMENT: "AddAttachment",
    # Alert
    SdkEndpoint.GET_ALERT_FULL_DETAILS: "AlertFullDetails",
    SdkEndpoint.UPDATE_ALERT_ADDITIONAL_DATA: "UpdateAlertsAdditional",
    SdkEndpoint.GET_DISMISSED_ALERTS_TICKET_IDS: "GetTicketIdsForAlertsDismissedSinceTimestamp",
    SdkEndpoint.GET_CLOSE_CASE_ALERTS_TICKET_IDS: "GetAlertsTicketIdsFromCasesClosedSinceTimestamp",
    SdkEndpoint.GET_CASE_ALERTS_TICKET_IDS: "AlertsTicketIdsByCaseId/{}",
    SdkEndpoint.DISMISSED_ALERT: "DismissAlert",
    SdkEndpoint.CLOSE_ALERT: "CloseAlert",
    SdkEndpoint.RAISE_INCIDENT: "RaiseIncident",
    SdkEndpoint.GET_SYNC_ALERTS_METADATA: "sync/alerts/metadata",
    SdkEndpoint.GET_SYNC_ALERTS: "sync/alerts",
    SdkEndpoint.SET_ALERT_SLA: "cases/{}/alerts/{}/sla",
    SdkEndpoint.GET_NEW_ALERTS_TO_SYNC: "sync/new-alerts",
    SdkEndpoint.UPDATE_NEW_ALERTS_SYNC_STATUS: "sync/new-alerts/results",
    SdkEndpoint.GET_ALERTS_FULL_DETAILS: "AlertsFullDetails/{}/{}",
}

SDK_1P_ENDPOINT_URLS = {
    SdkEndpoint.SET_CONTEXT_PROPERTY: "SetContextProperty",
    SdkEndpoint.TRY_SET_CONTEXT_PROPERTY: "TrySetContextProperty",
    SdkEndpoint.GET_CONTEXT_PROPERTY: "GetContextProperty",
    SdkEndpoint.ADD_AGENT_LOGS: "AddAgentLogs",
    SdkEndpoint.GET_FAILED_ACTIONS: "GetFailedActions?numberOfHours={}",
    SdkEndpoint.GET_FAILED_JOBS: "GetFailedJobs?numberOfHours={}",
    SdkEndpoint.GET_FAILED_ETL_OPERATIONS: "GetFailedETLOperations?numberOfHours={}",
    SdkEndpoint.GET_CONNECTOR_PARAMETERS: "GetConnectorParameters?identifier={}",
    SdkEndpoint.SET_CONNECTOR_PARAMETER: "UpdateConnectorParameter?identifier={}&parameterName={}",
    SdkEndpoint.GET_FAILED_CONNECTORS: "GetFailedConnectors",
    SdkEndpoint.CREATE_CONNECTOR_PACKAGE: "CreateConnectorPackage",
    SdkEndpoint.SET_INTEGRATION_CONFIGURATION_PROPERTY: "UpdateConfigurationProperty?identifier={}&propertyName={}",
    SdkEndpoint.GET_INTEGRATION_CONFIGURATION: "IntegrationConfiguration?identifier={}",
    SdkEndpoint.GET_INTEGRATION_VERSION: "GetIntegrationVersion?integrationIdentifier={}",
    SdkEndpoint.SEND_EMAIL_WITH_ATTACHMENT: "SendEmailWithAttachment",
    SdkEndpoint.GET_PROXY_SETTINGS: "GetProxySettings",
    SdkEndpoint.UPDATE_ENTITIES: "UpdateEntities",
    SdkEndpoint.GET_SYSTEM_INFO: "SystemInfo?lastRunEpochMs={}",
    SdkEndpoint.GET_SYSTEM_VERSION: "GetCurrentSiemplifyVersion",
    SdkEndpoint.SEND_SYSTEM_NOTIFICATION: "SendSystemNotification",
    SdkEndpoint.CHECK_MARKETPLACE_STATUS: "CheckMarketplaceStatus",
    SdkEndpoint.ANY_ENTITY_IN_LIST: "AnyEntityInCustomList",
    SdkEndpoint.ADD_ENTITIES_TO_LIST: "AddEntitiesToCustomList",
    SdkEndpoint.REMOVE_ENTITIES_FROM_LIST: "RemoveEntitiesFromCustomList",
    SdkEndpoint.GET_CUSTOM_CATEGORIES: "GetCustomListCategories",
    SdkEndpoint.GET_REMOTE_CONNECTORS_KEYS_MAP: "GetRemoteConnectorsKeysMap?publisherId={}",
    SdkEndpoint.GET_PUBLISHER_BY_ID: "GetPublisherById?publisherId={}",
    SdkEndpoint.GET_AGENT_BY_ID: "GetAgentById?agentId={}",
    SdkEndpoint.ADD_AGENT_CONNECTOR_LOGS: "AddAgentConnectorLogs?agentIdentifier={"
    "}&connectorIdentifier={}",
    # Case
    SdkEndpoint.GET_CASE_METADATA: "CaseMetadata?caseId={}",
    SdkEndpoint.GET_CASE_FULL_DETAILS: "CaseFullDetails?caseId={}&populateOriginalFile={}",
    SdkEndpoint.GET_CASE_ATTACHMENTS: "Attachments?caseId={}",
    SdkEndpoint.GET_ATTACHMENT_DATA: "AttachmentData?attachmentId={}",
    SdkEndpoint.ASSIGN_USER: "AssignUser",
    SdkEndpoint.ADD_TAG: "AddTag",
    SdkEndpoint.GET_SIMILAR_CASES_IDS: "GetSimilarCasesIds",
    SdkEndpoint.CHANGE_CASE_STAGE: "ChangeCaseStage",
    SdkEndpoint.CHANGE_CASE_PRIORITY: "ChangePriority",
    SdkEndpoint.CLOSE_CASE: "CloseCase",
    SdkEndpoint.GET_CASE_CLOSURE_DETAILS: "GetCaseClosureDetails",
    SdkEndpoint.CREATE_CASE_INSIGHT: "CreateCaseInsight",
    SdkEndpoint.MARK_CASE_AS_IMPORTANT: "MarkAsImportant",
    SdkEndpoint.CREATE_CASE: "CreateCase",
    SdkEndpoint.CREATE_ENTITY: "CreateEntity",
    SdkEndpoint.ATTACH_WORKFLOW_TO_CASE: "AttacheWorkflowToCase",
    SdkEndpoint.GET_CASES_BY_FILTER: "GetCasesByFilter",
    SdkEndpoint.GET_CASES_IDS_BY_FILTER: "GetCasesIdByFilter",
    SdkEndpoint.GET_CASE_COMMENTS: "GetCaseComments/{}?fetchUpdates={}",
    SdkEndpoint.ADD_OR_UPDATE_CASE_TASK: "AddOrUpdateCaseTask",
    SdkEndpoint.GET_CASE_TASKS: "GetCaseTasks?caseId={}",
    SdkEndpoint.GET_SYNC_CASES_METADATA: "GetUpdatedSyncCasesMetadata",
    SdkEndpoint.GET_SYNC_CASES: "GetSyncCases",
    SdkEndpoint.UPDATE_CASES: "UpdateBatchCasesExternalCaseIds",
    SdkEndpoint.SET_CASE_SLA: "SetCaseSla?caseId={}",
    SdkEndpoint.ADD_ATTACHMENT: "AddAttachment",
    # Alert
    SdkEndpoint.GET_ALERT_FULL_DETAILS: "AlertFullDetails",
    SdkEndpoint.UPDATE_ALERT_ADDITIONAL_DATA: "UpdateAlertsAdditional",
    SdkEndpoint.GET_DISMISSED_ALERTS_TICKET_IDS: "GetTicketIdsForAlertsDismissedSinceTimestamp",
    SdkEndpoint.GET_CLOSE_CASE_ALERTS_TICKET_IDS: "GetAlertsTicketIdsFromCasesClosedSinceTimestamp",
    SdkEndpoint.GET_CASE_ALERTS_TICKET_IDS: "AlertsTicketIdsByCaseId?caseId={}",
    SdkEndpoint.DISMISSED_ALERT: "DismissAlert",
    SdkEndpoint.CLOSE_ALERT: "CloseAlert",
    SdkEndpoint.RAISE_INCIDENT: "RaiseIncident",
    SdkEndpoint.GET_SYNC_ALERTS_METADATA: "GetUpdatedSyncAlertsMetadata",
    SdkEndpoint.GET_SYNC_ALERTS: "GetSyncAlerts",
    SdkEndpoint.SET_ALERT_SLA: "SetAlertSla?caseId={}&alertIdentifier={}",
    SdkEndpoint.GET_NEW_ALERTS_TO_SYNC: "GetAlertsToSync",
    SdkEndpoint.UPDATE_NEW_ALERTS_SYNC_STATUS: "UpdateNewAlertsSyncStatus",
    SdkEndpoint.GET_ALERTS_FULL_DETAILS: "AlertsFullDetails?caseId={}&populateOriginalFile={}",
}


class SiemplifyAddressProvider:
    def __init__(self, sdk_config: SiemplifySdkConfig, support_one_platform: bool) -> None:
        if support_one_platform:
            uri = sdk_config.one_platform_api_root_uri_format.format(BASE_1P_SDK_CONTROLLER_VERSION)
            self.API_BASE_ROOT = f"{uri}/{BASE_1P_SDK_CONTROLLER_URL_FORMAT}"
            self.endpoint_mapper = SDK_1P_ENDPOINT_URLS
        else:
            self.API_BASE_ROOT = f"{sdk_config.api_root_uri}/{BASE_SDK_CONTROLLER_URL_FORMAT}"
            self.endpoint_mapper = SDK_ENDPOINT_URLS

    def provide_set_context_property_address(self) -> str:
        return self._create_address(SdkEndpoint.SET_CONTEXT_PROPERTY)

    def provide_try_set_context_property_address(self) -> str:
        return self._create_address(SdkEndpoint.TRY_SET_CONTEXT_PROPERTY)

    def provide_get_context_property_address(self) -> str:
        return self._create_address(SdkEndpoint.GET_CONTEXT_PROPERTY)

    def provide_add_agent_logs_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.ADD_AGENT_LOGS),
        )

    def provide_get_failed_actions_address(self, number_of_hours: int) -> str:
        address = self._create_address(SdkEndpoint.GET_FAILED_ACTIONS).format(number_of_hours)
        return _build_address_with_format_query_param(address)

    def provide_get_failed_jobs_address(self, number_of_hours: int) -> str:
        address = self._create_address(SdkEndpoint.GET_FAILED_JOBS).format(number_of_hours)
        return _build_address_with_format_query_param(address)

    def provide_get_failed_etl_operations_address(self, number_of_hours: int) -> str:
        address = self._create_address(SdkEndpoint.GET_FAILED_ETL_OPERATIONS).format(
            number_of_hours,
        )
        return _build_address_with_format_query_param(address)

    def provide_get_connector_parameters_address(self, connector_identifier: str) -> str:
        return self._create_address(SdkEndpoint.GET_CONNECTOR_PARAMETERS).format(
            connector_identifier,
        )

    def provide_set_connector_parameter_address(
        self,
        connector_identifier: str,
        parameter_name: str,
    ) -> str:
        address = self._create_address(SdkEndpoint.SET_CONNECTOR_PARAMETER).format(
            connector_identifier,
            parameter_name,
        )
        return _build_address_with_format_query_param(address)

    def provide_get_failed_connectors_address(self) -> str:
        address = self._create_address(SdkEndpoint.GET_FAILED_CONNECTORS)
        return _build_address_with_format_query_param(address)

    def provide_create_connector_package_address(self) -> str:
        return self._create_address(SdkEndpoint.CREATE_CONNECTOR_PACKAGE)

    def provide_set_configuration_property_address(
        self,
        integration_instance_identifier: str,
        property_name: str,
    ) -> str:
        address = self._create_address(SdkEndpoint.SET_INTEGRATION_CONFIGURATION_PROPERTY).format(
            integration_instance_identifier,
            property_name,
        )
        return _build_address_with_format_query_param(address)

    def provide_get_integration_configuration_address(
        self,
        integration_instance_identifier: str,
    ) -> str:
        address = self._create_address(SdkEndpoint.GET_INTEGRATION_CONFIGURATION).format(
            integration_instance_identifier,
        )
        return _build_address_with_format_query_param(address)

    def provide_get_integration_version_address(
        self,
        integration_identifier: str,
    ) -> str:
        address = self._create_address(SdkEndpoint.GET_INTEGRATION_VERSION).format(
            integration_identifier,
        )
        return _build_address_with_format_query_param(address)

    def provide_send_email_with_attachment_address(self) -> str:
        address = self._create_address(SdkEndpoint.SEND_EMAIL_WITH_ATTACHMENT)
        return _build_address_with_format_query_param(address)

    def provide_add_attachment_address(self) -> str:
        address = self._create_address(SdkEndpoint.ADD_ATTACHMENT)
        return _build_address_with_format_query_param(address)

    def provide_get_proxy_settings_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_PROXY_SETTINGS),
        )

    def provide_update_entities_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.UPDATE_ENTITIES),
        )

    def provide_get_system_info_address(self, start_time_unixtime_ms: int) -> str:
        address = self._create_address(SdkEndpoint.GET_SYSTEM_INFO).format(
            start_time_unixtime_ms,
        )
        return _build_address_with_format_query_param(address)

    def provide_get_system_version_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_SYSTEM_VERSION),
        )

    def provide_send_system_notification_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.SEND_SYSTEM_NOTIFICATION),
        )

    def provide_get_case_metadata_address(self, case_id: int | str) -> str:
        address = self._create_address(SdkEndpoint.GET_CASE_METADATA).format(case_id)
        return _build_address_with_format_query_param(address)

    def provide_set_case_sla_address(self, case_id: int | str) -> str:
        address = self._create_address(SdkEndpoint.SET_CASE_SLA).format(case_id)
        return _build_address_with_format_query_param(address)

    def provide_set_alert_sla_address(self, case_id: int | str, alert_identifier: str) -> str:
        address = self._create_address(SdkEndpoint.SET_ALERT_SLA).format(
            case_id,
            alert_identifier,
        )
        return _build_address_with_format_query_param(address)

    def provide_get_case_attachments_address(self, case_id: int | str) -> str:
        address = self._create_address(SdkEndpoint.GET_CASE_ATTACHMENTS).format(case_id)
        return _build_address_with_format_query_param(address)

    def provide_get_case_comments_address(
        self,
        case_id: str | int,
        fetch_updates: bool = False,
    ) -> str:
        address = self._create_address(SdkEndpoint.GET_CASE_COMMENTS).format(case_id, fetch_updates)
        return _build_address_with_format_query_param(address)

    def provide_get_attachment_data_address(self, attachment_id: str) -> str:
        address = self._create_address(SdkEndpoint.GET_ATTACHMENT_DATA).format(attachment_id)
        return _build_address_with_format_query_param(address)

    def provide_get_alert_full_details_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_ALERT_FULL_DETAILS),
        )

    def provide_update_alert_additional_data_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.UPDATE_ALERT_ADDITIONAL_DATA),
        )

    def provide_dismissed_alerts_ticket_ids_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_DISMISSED_ALERTS_TICKET_IDS),
        )

    def provide_close_case_alerts_ticket_ids_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_CLOSE_CASE_ALERTS_TICKET_IDS),
        )

    def provide_case_alerts_ticket_ids_address(self, case_id: int | str) -> str:
        address = self._create_address(SdkEndpoint.GET_CASE_ALERTS_TICKET_IDS).format(case_id)
        return _build_address_with_format_query_param(address)

    def provide_assign_user_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.ASSIGN_USER),
        )

    def provide_add_tag_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.ADD_TAG),
        )

    def provide_get_similar_cases_ids_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_SIMILAR_CASES_IDS),
        )

    def provide_change_case_stage_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.CHANGE_CASE_STAGE),
        )

    def provide_change_case_priority_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.CHANGE_CASE_PRIORITY),
        )

    def provide_close_case_address(self) -> str:
        return _build_address_with_format_query_param(self._create_address(SdkEndpoint.CLOSE_CASE))

    def provide_get_case_closure_details_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_CASE_CLOSURE_DETAILS),
        )

    def provide_mark_case_as_important_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.MARK_CASE_AS_IMPORTANT),
        )

    def provide_create_case_insight_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.CREATE_CASE_INSIGHT),
        )

    def provide_create_case_address(self) -> str:
        return _build_address_with_format_query_param(self._create_address(SdkEndpoint.CREATE_CASE))

    def provide_create_entity_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.CREATE_ENTITY),
        )

    def provide_get_case_full_details_address(
        self,
        case_id: int | str,
        populate_original_file: bool = False,
    ) -> str:
        address = self._create_address(SdkEndpoint.GET_CASE_FULL_DETAILS).format(
            case_id,
            populate_original_file,
        )
        return _build_address_with_format_query_param(address)

    def provide_dismiss_alert_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.DISMISSED_ALERT),
        )

    def provide_close_alert_address(self) -> str:
        return _build_address_with_format_query_param(self._create_address(SdkEndpoint.CLOSE_ALERT))

    def provide_raise_incident_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.RAISE_INCIDENT),
        )

    def provide_attach_workflow_to_case_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.ATTACH_WORKFLOW_TO_CASE),
        )

    def provide_get_cases_by_filter_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_CASES_BY_FILTER),
        )

    def provide_get_cases_ids_by_filter_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_CASES_IDS_BY_FILTER),
        )

    def provide_check_marketplace_status_address(self) -> str:
        return self._create_address(SdkEndpoint.CHECK_MARKETPLACE_STATUS)

    def provide_add_or_update_case_task_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.ADD_OR_UPDATE_CASE_TASK),
        )

    def provide_get_case_tasks_address(self, case_id: int | str) -> str:
        address = self._create_address(SdkEndpoint.GET_CASE_TASKS).format(case_id)
        return _build_address_with_format_query_param(address)

    def provide_get_sync_cases_metadata_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_SYNC_CASES_METADATA),
        )

    def provide_get_sync_alerts_metadata_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_SYNC_ALERTS_METADATA),
        )

    def provide_get_sync_alerts_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_SYNC_ALERTS),
        )

    def provide_get_new_alerts_to_sync_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_NEW_ALERTS_TO_SYNC),
        )

    def provide_update_new_alerts_sync_status_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.UPDATE_NEW_ALERTS_SYNC_STATUS),
        )

    def provide_get_sync_cases_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_SYNC_CASES),
        )

    def provide_update_cases_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.UPDATE_CASES),
        )

    def provide_any_entity_in_list_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.ANY_ENTITY_IN_LIST),
        )

    def provide_add_entities_to_list_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.ADD_ENTITIES_TO_LIST),
        )

    def provide_remove_entities_from_list_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.REMOVE_ENTITIES_FROM_LIST),
        )

    def provide_get_custom_categories_address(self) -> str:
        return _build_address_with_format_query_param(
            self._create_address(SdkEndpoint.GET_CUSTOM_CATEGORIES),
        )

    def provide_get_remote_connectors_keys_map_address(self, publisher_id: str) -> str:
        address = self._create_address(
            SdkEndpoint.GET_REMOTE_CONNECTORS_KEYS_MAP,
        ).format(publisher_id)
        return _build_address_with_format_query_param(address)

    def provide_get_publisher_by_id_address(self, publisher_id: str) -> str:
        address = self._create_address(SdkEndpoint.GET_PUBLISHER_BY_ID).format(
            publisher_id,
        )
        return _build_address_with_format_query_param(address)

    def provide_get_agent_by_id_address(self, agent_id) -> str:
        address = self._create_address(SdkEndpoint.GET_AGENT_BY_ID).format(agent_id)
        return _build_address_with_format_query_param(address)

    def provide_add_agent_connector_logs_address(self, agent_id, connector_id) -> str:
        return self._create_address(SdkEndpoint.ADD_AGENT_CONNECTOR_LOGS).format(
            agent_id,
            connector_id,
        )

    def provide_get_alerts_full_details_address(
        self,
        case_id: int | str,
        populate_original_file: bool = False,
    ) -> str:
        address = self._create_address(SdkEndpoint.GET_ALERTS_FULL_DETAILS).format(
            case_id,
            populate_original_file,
        )
        return _build_address_with_format_query_param(address)

    def _create_address(self, endpoint_type: SdkEndpoint) -> str:
        return self.API_BASE_ROOT.format(self.endpoint_mapper.get(endpoint_type))


def _build_address_with_format_query_param(base_address: str) -> str:
    """Builds an address with a format parameter.

    Args:
        base_address: The base URL (string), which may or may not already
                      include query parameters.

    Returns:
        A string with the base address and the 'format query parameter.

    """
    if "?" in base_address:
        return f"{base_address}&{FORMAT_QUERY_PARAM}"
    return f"{base_address}?{FORMAT_QUERY_PARAM}"
