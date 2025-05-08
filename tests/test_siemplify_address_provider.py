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

import pytest

from soar_sdk.SiemplifyAddressProvider import SiemplifyAddressProvider
from soar_sdk.SiemplifySdkConfig import SiemplifySdkConfig

LOCAL_HOST_ADDRESS = "https://localhost:8443"
EXPECTED_1P_ADDRESS = (
    LOCAL_HOST_ADDRESS
    + "/v1alpha/projects/project/locations/location/instances/instance/legacySdk"
    ":legacy{}"
)
EXPECTED_ADDRESS = LOCAL_HOST_ADDRESS + "/api/external/v1/sdk/{}"
FORMAT_QUERY_PARAM = "format=snake"

test_cases = [
    (True, EXPECTED_1P_ADDRESS),
    (False, EXPECTED_ADDRESS),
]


@pytest.fixture
def mock_build_server_uri(mocker):
    """Mocks the _SiemplifySdkConfig__build_server_uri method."""
    return mocker.patch.object(
        SiemplifySdkConfig,
        "_SiemplifySdkConfig__build_server_uri",
        return_value=LOCAL_HOST_ADDRESS,
    )


@pytest.mark.usefixtures("mock_build_server_uri")
class TestSiemplify:
    def test_set_context_property_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_set_context_property_address()
            # assert
            assert address == expected_address.format("SetContextProperty")

    def test_try_set_context_property_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_try_set_context_property_address()
            )
            # assert
            assert address == expected_address.format("TrySetContextProperty")

    def test_get_context_property_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_context_property_address()
            # assert
            assert address == expected_address.format("GetContextProperty")

    def test_add_agent_logs_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_add_agent_logs_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AddAgentLogs"), FORMAT_QUERY_PARAM,
            )

    def test_get_failed_actions_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        number_of_hours = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_failed_actions_address(
                number_of_hours,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?numberOfHours={1}&{2}".format(
                    expected_address.format("GetFailedActions"),
                    number_of_hours,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("GetFailedActions"),
                    number_of_hours,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_failed_jobs_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        number_of_hours = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_failed_jobs_address(
                number_of_hours,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?numberOfHours={1}&{2}".format(
                    expected_address.format("GetFailedJobs"),
                    number_of_hours,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("GetFailedJobs"),
                    number_of_hours,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_failed_jobs_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        number_of_hours = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_failed_etl_operations_address(
                    number_of_hours,
                )
            )
            # assert
            if support_one_platform:
                assert address == "{0}?numberOfHours={1}&{2}".format(
                    expected_address.format("GetFailedETLOperations"),
                    number_of_hours,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("GetFailedETLOperations"),
                    number_of_hours,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_connector_parameters_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        connector_identifier = "connectorIdentifier"
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_connector_parameters_address(
                    connector_identifier,
                )
            )
            # assert
            if support_one_platform:
                assert address == "{0}?identifier={1}".format(
                    expected_address.format("GetConnectorParameters"),
                    connector_identifier,
                )

            else:
                assert address == "{0}/{1}/parameters".format(
                    expected_address.format("connectors"), connector_identifier,
                )

    def test_set_connector_parameter_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        connector_identifier = "connectorIdentifier"
        param_name = "paramName"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_set_connector_parameter_address(
                    connector_identifier, param_name,
                )
            )
            # assert
            if support_one_platform:
                assert address == "{0}?identifier={1}&parameterName={2}&{3}".format(
                    expected_address.format("UpdateConnectorParameter"),
                    connector_identifier,
                    param_name,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}/parameters/{2}?{3}".format(
                    expected_address.format("connectors"),
                    connector_identifier,
                    param_name,
                    FORMAT_QUERY_PARAM,
                )

    def test_set_configuration_property_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        integration_instance_identifier = "InstanceIdentifier"
        property_name = "propertyName"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_set_configuration_property_address(
                    integration_instance_identifier, property_name,
                )
            )
            # assert
            if support_one_platform:
                assert address == "{0}?identifier={1}&propertyName={2}&{3}".format(
                    expected_address.format("UpdateConfigurationProperty"),
                    integration_instance_identifier,
                    property_name,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}/properties/{2}?{3}".format(
                    expected_address.format("configuration"),
                    integration_instance_identifier,
                    property_name,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_integration_configuration_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        integration_instance_identifier = "InstanceIdentifier"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_integration_configuration_address(
                integration_instance_identifier,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?identifier={1}&{2}".format(
                    expected_address.format("IntegrationConfiguration"),
                    integration_instance_identifier,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("configuration"),
                    integration_instance_identifier,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_integration_version_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        integration_instance_identifier = "IntegrationIdentifier"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_integration_version_address(
                    integration_instance_identifier,
                )
            )
            # assert
            if support_one_platform:
                assert address == "{0}?integrationIdentifier={1}&{2}".format(
                    expected_address.format("GetIntegrationVersion"),
                    integration_instance_identifier,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("GetIntegrationVersion"),
                    integration_instance_identifier,
                    FORMAT_QUERY_PARAM,
                )

    def test_send_email_with_attachment_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_send_email_with_attachment_address()
            )
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("SendEmailWithAttachment"),
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("SendEmailWithAttachment"),
                    FORMAT_QUERY_PARAM,
                )

    def test_get_failed_connectors_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_failed_connectors_address()
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("GetFailedConnectors"), FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("GetFailedConnectors"), FORMAT_QUERY_PARAM,
                )

    def test_get_case_metadata_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_case_metadata_address(
                case_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?caseId={1}&{2}".format(
                    expected_address.format("CaseMetadata"), case_id, FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("CaseMetadata"), case_id, FORMAT_QUERY_PARAM,
                )

    def test_get_case_attachments_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_case_attachments_address(
                case_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?caseId={1}&{2}".format(
                    expected_address.format("Attachments"), case_id, FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("Attachments"), case_id, FORMAT_QUERY_PARAM,
                )

    def test_get_case_comments_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_case_comments_address(
                case_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?caseId={1}&{2}".format(
                    expected_address.format("GetCaseComments"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("GetCaseComments"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_attachment_data_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        attachment_id = "attachmentIdentifier"
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_attachment_data_address(
                attachment_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?attachmentId={1}&{2}".format(
                    expected_address.format("AttachmentData"),
                    attachment_id,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("AttachmentData"),
                    attachment_id,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_system_info_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        start_time_unixtime_ms = "10"
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_system_info_address(
                start_time_unixtime_ms,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?lastRunEpochMs={1}&{2}".format(
                    expected_address.format("SystemInfo"),
                    start_time_unixtime_ms,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("SystemInfo"),
                    start_time_unixtime_ms,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_system_info_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        start_time_unixtime_ms = "10"
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_system_info_address(
                start_time_unixtime_ms,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?lastRunEpochMs={1}&{2}".format(
                    expected_address.format("SystemInfo"),
                    start_time_unixtime_ms,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("SystemInfo"),
                    start_time_unixtime_ms,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_alert_full_details_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_alert_full_details_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AlertFullDetails"), FORMAT_QUERY_PARAM,
            )

    def test_update_alert_full_details_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_update_alert_additional_data_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("UpdateAlertsAdditional"), FORMAT_QUERY_PARAM,
            )

    def test_assign_user_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_assign_user_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AssignUser"), FORMAT_QUERY_PARAM,
            )

    def test_add_tag_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_add_tag_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AddTag"), FORMAT_QUERY_PARAM,
            )

    def test_get_similar_cases_ids_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_similar_cases_ids_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetSimilarCasesIds"), FORMAT_QUERY_PARAM,
            )

    def test_dismissed_alerts_ticket_ids_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_dismissed_alerts_ticket_ids_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetTicketIdsForAlertsDismissedSinceTimestamp"),
                FORMAT_QUERY_PARAM,
            )

    def test_close_case_alerts_ticket_ids_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_close_case_alerts_ticket_ids_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format(
                    "GetAlertsTicketIdsFromCasesClosedSinceTimestamp",
                ),
                FORMAT_QUERY_PARAM,
            )

    def test_get_alerts_ticket_ids_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_case_alerts_ticket_ids_address(
                case_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?caseId={1}&{2}".format(
                    expected_address.format("AlertsTicketIdsByCaseId"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("AlertsTicketIdsByCaseId"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_case_full_details_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = "42"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address_with_original_file = (
                siemplify_address_provider.provide_get_case_full_details_address(
                    case_id, populate_original_file=True,
                )
            )
            address_without_original_file = (
                siemplify_address_provider.provide_get_case_full_details_address(
                    case_id,
                )
            )

            # assert
            if support_one_platform:
                assert (
                    address_with_original_file
                    == "{0}?caseId={1}&populateOriginalFile={2}&{3}".format(
                        expected_address.format("CaseFullDetails"),
                        case_id,
                        True,
                        FORMAT_QUERY_PARAM,
                    )
                )
                assert (
                    address_without_original_file
                    == "{0}?caseId={1}&populateOriginalFile={2}&{3}".format(
                        expected_address.format("CaseFullDetails"),
                        case_id,
                        False,
                        FORMAT_QUERY_PARAM,
                    )
                )
            else:
                assert address_with_original_file == "{0}/{1}/{2}?{3}".format(
                    expected_address.format("CaseFullDetails"),
                    case_id,
                    True,
                    FORMAT_QUERY_PARAM,
                )
                assert address_without_original_file == "{0}/{1}/{2}?{3}".format(
                    expected_address.format("CaseFullDetails"),
                    case_id,
                    False,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_proxy_settings_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_proxy_settings_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetProxySettings"), FORMAT_QUERY_PARAM,
            )

    def test_update_entities_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_update_entities_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("UpdateEntities"), FORMAT_QUERY_PARAM,
            )

    def test_change_case_stage_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_change_case_stage_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("ChangeCaseStage"), FORMAT_QUERY_PARAM,
            )

    def test_change_case_stage_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_change_case_priority_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("ChangePriority"), FORMAT_QUERY_PARAM,
            )

    def test_close_case_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_close_case_address()
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("CloseCase"), FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("Close"), FORMAT_QUERY_PARAM,
                )

    def test_get_case_closure_details_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_case_closure_details_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetCaseClosureDetails"), FORMAT_QUERY_PARAM,
            )

    def test_dismiss_alert_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_dismiss_alert_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("DismissAlert"), FORMAT_QUERY_PARAM,
            )

    def test_dismiss_alert_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_close_alert_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("CloseAlert"), FORMAT_QUERY_PARAM,
            )

    def test_create_case_insight_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_create_case_insight_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("CreateCaseInsight"), FORMAT_QUERY_PARAM,
            )

    def test_mark_case_as_important_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_mark_case_as_important_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("MarkAsImportant"), FORMAT_QUERY_PARAM,
            )

    def test_raise_incident_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_raise_incident_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("RaiseIncident"), FORMAT_QUERY_PARAM,
            )

    def test_get_system_version_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_system_version_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetCurrentSiemplifyVersion"),
                FORMAT_QUERY_PARAM,
            )

    def test_get_create_case_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_create_case_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("CreateCase"), FORMAT_QUERY_PARAM,
            )

    def test_get_create_entity_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_create_entity_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("CreateEntity"), FORMAT_QUERY_PARAM,
            )

    def test_attach_workflow_to_case_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_attach_workflow_to_case_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AttacheWorkflowToCase"), FORMAT_QUERY_PARAM,
            )

    def test_send_system_notification_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_send_system_notification_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("SendSystemNotification"), FORMAT_QUERY_PARAM,
            )

    def test_get_cases_by_filter_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_cases_by_filter_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetCasesByFilter"), FORMAT_QUERY_PARAM,
            )

    def test_get_cases_ids_by_filter_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_cases_ids_by_filter_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetCasesIdByFilter"), FORMAT_QUERY_PARAM,
            )

    def test_check_marketplace_status_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_check_marketplace_status_address()
            )
            # assert
            assert address == expected_address.format("CheckMarketplaceStatus")

    def test_add_or_update_case_task_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_add_or_update_case_task_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AddOrUpdateCaseTask"), FORMAT_QUERY_PARAM,
            )

    def test_get_case_tasks_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_case_tasks_address(case_id)
            # assert
            if support_one_platform:
                assert address == "{0}?caseId={1}&{2}".format(
                    expected_address.format("GetCaseTasks"), case_id, FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}?{2}".format(
                    expected_address.format("GetCaseTasks"), case_id, FORMAT_QUERY_PARAM,
                )

    def test_any_entity_in_list_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_any_entity_in_list_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AnyEntityInCustomList"), FORMAT_QUERY_PARAM,
            )

    def test_add_entities_to_list_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_add_entities_to_list_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AddEntitiesToCustomList"), FORMAT_QUERY_PARAM,
            )

    def test_remove_entities_from_list_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_remove_entities_from_list_address()
            )
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("RemoveEntitiesFromCustomList"),
                FORMAT_QUERY_PARAM,
            )

    def test_get_custom_categories_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_custom_categories_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("GetCustomListCategories"), FORMAT_QUERY_PARAM,
            )

    def test_remote_connectors_keys_map_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_remote_connectors_keys_map_address(
                case_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?publisherId={1}&{2}".format(
                    expected_address.format("GetRemoteConnectorsKeysMap"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?publisherIdStr={1}&{2}".format(
                    expected_address.format("GetRemoteConnectorsKeysMap"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_publisher_by_id_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_publisher_by_id_address(
                case_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?publisherId={1}&{2}".format(
                    expected_address.format("GetPublisherById"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?publisherIdStr={1}&{2}".format(
                    expected_address.format("GetPublisherById"),
                    case_id,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_agent_by_id_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_agent_by_id_address(
                case_id,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?agentId={1}&{2}".format(
                    expected_address.format("GetAgentById"), case_id, FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?agentIdStr={1}&{2}".format(
                    expected_address.format("GetAgentById"), case_id, FORMAT_QUERY_PARAM,
                )

    def test_create_connector_package_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_create_connector_package_address()
            )
            # assert
            assert address == expected_address.format("CreateConnectorPackage")

    def test_add_agent_connector_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        connector_identifier = "connectorIdentifier"
        agent_id = "agentId"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_add_agent_connector_logs_address(
                    agent_id, connector_identifier,
                )
            )
            # assert
            if support_one_platform:
                assert (
                    address
                    == "{0}?agentIdentifier={1}&connectorIdentifier={2}".format(
                        expected_address.format("AddAgentConnectorLogs"),
                        agent_id,
                        connector_identifier,
                    )
                )

            else:
                assert address == "{0}/{1}/connectors/{2}/logs".format(
                    expected_address.format("agents"), agent_id, connector_identifier,
                )

    def test_get_sync_cases_metadata_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_sync_cases_metadata_address()
            )
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("GetUpdatedSyncCasesMetadata"),
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("sync/cases/metadata"), FORMAT_QUERY_PARAM,
                )

    def test_get_sync_cases_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_sync_cases_address()
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("GetSyncCases"), FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("sync/cases"), FORMAT_QUERY_PARAM,
                )

    def test_get_sync_alerts_metadata_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_sync_alerts_metadata_address()
            )
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("GetUpdatedSyncAlertsMetadata"),
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("sync/alerts/metadata"), FORMAT_QUERY_PARAM,
                )

    def test_get_sync_alerts_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_get_sync_alerts_address()
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("GetSyncAlerts"), FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("sync/alerts"), FORMAT_QUERY_PARAM,
                )

    def test_update_cases_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_update_cases_address()
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("UpdateBatchCasesExternalCaseIds"),
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("sync/cases/matches"), FORMAT_QUERY_PARAM,
                )

    def test_set_case_sla_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_set_case_sla_address(case_id)
            # assert
            if support_one_platform:
                assert address == "{0}?caseId={1}&{2}".format(
                    expected_address.format("SetCaseSla"), case_id, FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}/sla?{2}".format(
                    expected_address.format("cases"), case_id, FORMAT_QUERY_PARAM,
                )

    def test_set_alert_sla_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = 4
        alert_identifier = "AlertIdentifier"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_set_alert_sla_address(
                case_id, alert_identifier,
            )
            # assert
            if support_one_platform:
                assert address == "{0}?caseId={1}&alertIdentifier={2}&{3}".format(
                    expected_address.format("SetAlertSla"),
                    case_id,
                    alert_identifier,
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}/{1}/alerts/{2}/sla?{3}".format(
                    expected_address.format("cases"),
                    case_id,
                    alert_identifier,
                    FORMAT_QUERY_PARAM,
                )

    def test_get_new_alerts_to_sync_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = (
                siemplify_address_provider.provide_get_new_alerts_to_sync_address()
            )
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("GetAlertsToSync"), FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("sync/new-alerts"), FORMAT_QUERY_PARAM,
                )

    def test_update_new_alerts_sync_status_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_update_new_alerts_sync_status_address()
            # assert
            if support_one_platform:
                assert address == "{0}?{1}".format(
                    expected_address.format("UpdateNewAlertsSyncStatus"),
                    FORMAT_QUERY_PARAM,
                )

            else:
                assert address == "{0}?{1}".format(
                    expected_address.format("sync/new-alerts/results"),
                    FORMAT_QUERY_PARAM,
                )

    def test_get_alerts_full_details_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        case_id = "42"

        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address_with_original_file = (
                siemplify_address_provider.provide_get_alerts_full_details_address(
                    case_id, populate_original_file=True,
                )
            )
            address_without_original_file = (
                siemplify_address_provider.provide_get_alerts_full_details_address(
                    case_id,
                )
            )

            # assert
            if support_one_platform:
                assert (
                    address_with_original_file
                    == "{0}?caseId={1}&populateOriginalFile={2}&{3}".format(
                        expected_address.format("AlertsFullDetails"),
                        case_id,
                        True,
                        FORMAT_QUERY_PARAM,
                    )
                )
                assert (
                    address_without_original_file
                    == "{0}?caseId={1}&populateOriginalFile={2}&{3}".format(
                        expected_address.format("AlertsFullDetails"),
                        case_id,
                        False,
                        FORMAT_QUERY_PARAM,
                    )
                )
            else:
                assert address_with_original_file == "{0}/{1}/{2}?{3}".format(
                    expected_address.format("AlertsFullDetails"),
                    case_id,
                    True,
                    FORMAT_QUERY_PARAM,
                )
                assert address_without_original_file == "{0}/{1}/{2}?{3}".format(
                    expected_address.format("AlertsFullDetails"),
                    case_id,
                    False,
                    FORMAT_QUERY_PARAM,
                )

    def test_add_attachment_address(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        for support_one_platform, expected_address in test_cases:
            siemplify_address_provider = SiemplifyAddressProvider(
                sdk_config, support_one_platform,
            )
            # act
            address = siemplify_address_provider.provide_add_attachment_address()
            # assert
            assert address == "{0}?{1}".format(
                expected_address.format("AddAttachment"), FORMAT_QUERY_PARAM,
            )
