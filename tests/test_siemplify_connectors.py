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

import sys
import unittest.mock
from configparser import ConfigParser

from soar_sdk.SiemplifyBase import SiemplifyBase
from soar_sdk.SiemplifyConnectors import SiemplifyConnectorExecution
from soar_sdk.SiemplifyConnectorsDataModel import AlertInfo, CaseInfo
from soar_sdk.SiemplifySdkConfig import SiemplifySdkConfig

raw_context_data = (
    '{"connector_info": {"identifier": "TEST", "environment": "TEST", "params": [{'
    '"param_name": '
    '"TEST", "param_value":"TEST"}]}, "connector_api_key": "123"}'
)
raw_context_data_run_connector_task = (
    '{"connector_info": {"identifier": "TEST", "environment": "TEST", '
    '"is_locally_scheduled_remote_connector": true, "params": [{"param_name": '
    '"TEST", "param_value":"TEST"}]}, "connector_api_key": "123"}'
)


class TestSiemplifyConnectors:
    def test_siemplify_connectors_init_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        obj = mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )

        # act
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)

        # asserts
        obj.assert_called_once()
        assert siemplify_connectors.whitelist is None
        assert siemplify_connectors.log_location == "SDK_Connectors"
        assert "SiemplifyConnectorExecution" in siemplify_connectors.run_folder
        assert siemplify_connectors.parameters == {"TEST": "TEST"}

    def test_siemplify_connectors_remote_init_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        init_session = mocker.patch.object(
            SiemplifyBase,
            "_init_remote_session",
            return_value=None,
        )
        mocker.patch.object(ConfigParser, "getboolean", return_value=True)
        mocker.patch.object(
            SiemplifySdkConfig,
            "_build_remote_api_server_uri",
            return_value="TEST",
        )

        # act
        siemplify_connectors = SiemplifyConnectorExecution(
            mock_stdin=raw_context_data_run_connector_task,
        )

        # asserts
        assert siemplify_connectors.whitelist is None
        assert siemplify_connectors.log_location == "SDK_Connectors"
        assert siemplify_connectors.parameters == {"TEST": "TEST"}
        init_session.assert_called_once_with("123")

    def test_siemplify_connectors_init_lower_python_than_37_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        obj = mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        mocker.patch("SiemplifyConnectors.is_python_37", return_value=False)
        try:
            mocker.patch(
                "sys.stdin.buffer.read",
                return_value=raw_context_data.encode(),
            )
        except Exception:
            mocker.patch("sys.stdin.read", return_value=raw_context_data.encode())

        # act
        siemplify_connectors = SiemplifyConnectorExecution()

        # asserts
        obj.assert_called_once()
        assert siemplify_connectors.whitelist is None
        assert siemplify_connectors.log_location == "SDK_Connectors"
        assert "SiemplifyConnectorExecution" in siemplify_connectors.run_folder
        assert siemplify_connectors.parameters == {"TEST": "TEST"}

    def test_run_folder_property(self, mocker: unittest.mock.Mock) -> None:
        # assert
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)

        # act
        mocker.patch("os.path.exists", return_value=False)
        os_makedirs_mock = mocker.patch("os.makedirs")
        siemplify_connectors.run_folder

        # assert
        os_makedirs_mock.assert_called_once()

    def test_whitelist_property(self, mocker: unittest.mock.Mock) -> None:
        # assert
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)

        # act
        assert not siemplify_connectors.whitelist
        siemplify_connectors.context = False

        # assert
        assert not siemplify_connectors.whitelist

    def test_is_test_property(self, mocker: unittest.mock.Mock) -> None:
        # assert
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)

        # act
        assert not siemplify_connectors.is_test_run
        sys.argv[1] = "False"
        sys.argv.append(sys.argv[1])

        # assert
        assert siemplify_connectors.is_test_run

    def test_is_overflowed_alert(self, mocker: unittest.mock.Mock) -> None:
        # assert
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        mocker.patch.object(
            siemplify_connectors.overflow_manager,
            "check_is_alert_overflowed",
            return_value=True,
        )

        # act
        response = siemplify_connectors.is_overflowed_alert("Test", "Test")

        # assert
        assert response

    def test_return_package_response_success(self, mocker: unittest.mock.Mock) -> None:
        # assert
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        real_stdout_write_mock = mocker.patch("SiemplifyUtils.real_stdout.write")

        # act
        response = siemplify_connectors.return_package("TEST")

        # assert
        real_stdout_write_mock.assert_called_once()
        assert response is None

    def test_return_test_result_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # assert
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        real_stdout_write_mock = mocker.patch("SiemplifyUtils.real_stdout.write")

        # act
        response = siemplify_connectors.return_test_result(True, {})

        # assert
        real_stdout_write_mock.assert_called_once()
        assert response is None

    def test_extract_action_param_both_options_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)

        # act
        response_dict = {
            "siemplify": siemplify_connectors,
            "input_dictionary": siemplify_connectors.parameters,
            "param_name": "test",
            "default_value": None,
            "input_type": str,
            "is_mandatory": False,
            "print_value": False,
        }
        obj = mocker.patch(
            "SiemplifyConnectors.extract_script_param",
            return_value=response_dict,
        )
        mocker.patch.object(
            siemplify_connectors.session,
            "post",
            return_value=mock_response,
        )
        assert not siemplify_connectors.context.vault_settings
        siemplify_connectors.context.vault_settings = (
            siemplify_connectors.extract_connector_param(param_name="test")
        )
        response = siemplify_connectors.extract_connector_param(param_name="test")

        # assert
        assert siemplify_connectors.context.vault_settings
        assert response == response_dict
        assert obj.call_count == 2

    def test_get_case_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        mocker.patch.object(SiemplifyBase, "get_context_property", return_value="TEST")

        # act
        response = siemplify_connectors.get_connector_context_property(
            identifier=1,
            property_key=1,
        )

        # assert
        assert response == "{}"

    def test_set_case_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        siemplify_connectors.is_locally_scheduled_remote_connector = True
        obj = mocker.patch.object(
            SiemplifyConnectorExecution,
            "set_context_property",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.set_connector_context_property(
            identifier=1,
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once_with(4, 1, 1, 1)
        assert response == "TEST"

    def test_set_connector_context_property_remotely_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        siemplify_connectors.is_locally_scheduled_remote_connector = True
        obj = mocker.patch.object(
            SiemplifyBase,
            "set_context_property",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.set_connector_context_property(
            identifier=1,
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once_with(4, "TEST", 1, 1)
        assert response == "TEST"

    def test_try_set_connector_context_property_locally_scheduled_local_connector_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        siemplify_connectors.is_locally_scheduled_remote_connector = True
        obj = mocker.patch.object(
            SiemplifyBase,
            "try_set_context_property",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.try_set_context_property(
            context_type=2,
            identifier=1,
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once_with(4, "TEST", 1, 1)
        assert response == "TEST"

    def test_try_set_connector_context_property_locally_scheduled_remote_connector_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        siemplify_connectors.is_locally_scheduled_remote_connector = True
        obj = mocker.patch.object(
            SiemplifyBase,
            "try_set_context_property",
            return_value="TEST",
        )
        mocker.patch.object(ConfigParser, "getboolean", return_value=True)
        mocker.patch.object(
            SiemplifySdkConfig,
            "_build_remote_api_server_uri",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.try_set_context_property(
            context_type=2,
            identifier=1,
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once_with(4, "TEST", 1, 1)
        assert response == "TEST"

    def test_try_set_connector_context_property_remotely_scheduled_remote_connector_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        siemplify_connectors.is_locally_scheduled_remote_connector = False
        obj = mocker.patch.object(
            SiemplifyBase,
            "try_set_context_property",
            return_value="TEST",
        )
        mocker.patch.object(ConfigParser, "getboolean", return_value=True)

        # act
        response = siemplify_connectors.try_set_context_property(
            context_type=2,
            identifier=1,
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once_with(2, 1, 1, 1)
        assert response == "TEST"

    def test_set_connector_context_property_locally_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        obj = mocker.patch.object(
            SiemplifyBase,
            "set_context_property",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.set_connector_context_property(
            identifier=1,
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once_with(4, 1, 1, 1)
        assert response == "TEST"

    def test_try_set_connector_context_property_locally_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        obj = mocker.patch.object(
            SiemplifyBase,
            "try_set_context_property",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.try_set_context_property(
            context_type=2,
            identifier=1,
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once_with(2, 1, 1, 1)
        assert response == "TEST"

    def test_get_connector_context_property_locally_scheduled_remote_connector_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        obj = mocker.patch.object(
            SiemplifyBase,
            "get_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        siemplify_connectors.is_locally_scheduled_remote_connector = True
        mocker.patch.object(ConfigParser, "getboolean", return_value=True)
        mocker.patch.object(
            SiemplifySdkConfig,
            "_build_remote_api_server_uri",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.get_connector_context_property(
            identifier=1,
            property_key=1,
        )

        # assert
        obj.assert_called_with(4, "TEST", 1)
        assert response == "{}"

    def test_get_connector_context_property_remotely_scheduled_remote_connector_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        obj = mocker.patch.object(
            SiemplifyBase,
            "get_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        mocker.patch.object(ConfigParser, "getboolean", return_value=True)
        mocker.patch.object(
            SiemplifySdkConfig,
            "_build_remote_api_server_uri",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.get_connector_context_property(
            identifier=1,
            property_key=1,
        )

        # assert
        obj.assert_called_with(4, 1, 1)
        assert response == "{}"

    def test_get_connector_context_property_locally_scheduled_local_connector_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        obj = mocker.patch.object(
            SiemplifyBase,
            "get_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        siemplify_connectors.is_locally_scheduled_remote_connector = True

        # act
        response = siemplify_connectors.get_connector_context_property(
            identifier=1,
            property_key=1,
        )

        # assert
        obj.assert_called_with(4, "TEST", 1)
        assert response == "{}"

    def test_get_connector_context_property_locally_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        obj = mocker.patch.object(
            SiemplifyBase,
            "get_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)

        # act
        response = siemplify_connectors.get_connector_context_property(
            identifier=1,
            property_key=1,
        )

        # assert
        obj.assert_called_with(4, 1, 1)
        assert response == "{}"

    def test_fetch_and_save_timestamp_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        fetch_timestamp = mocker.patch.object(
            SiemplifyBase,
            "fetch_timestamp",
            return_value="TEST",
        )
        save_timestamp = mocker.patch.object(
            SiemplifyBase,
            "save_timestamp",
            return_value="TEST",
        )

        # act
        response = siemplify_connectors.fetch_and_save_timestamp()

        # assert
        fetch_timestamp.assert_called_once()
        save_timestamp.assert_called_once()
        assert response == "TEST"

    def test_get_case_status_by_id_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        case_id = 1
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"status": True}
        mock_response.raise_for_status.return_value = None
        sys.argv.append(sys.argv[1])
        mocker.patch.object(
            SiemplifyConnectorExecution,
            "get_connector_context_property",
            return_value="{}",
        )
        siemplify_connectors = SiemplifyConnectorExecution(mock_stdin=raw_context_data)
        mocker.patch.object(
            siemplify_connectors.session,
            "get",
            return_value=mock_response,
        )

        # act
        response = siemplify_connectors.get_case_status_by_id(case_id=case_id)

        # assert
        siemplify_connectors.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify_connectors.API_ROOT,
                "external/v1/sdk/CaseMetadata",
                case_id,
                "?format=snake",
            ),
        )
        assert response

    def test_case_info(self) -> None:
        # arrange
        case_info = CaseInfo()

        # assert
        case_info.environment = None
        case_info.ticket_id = None
        case_info.description = None
        case_info.display_id = None
        case_info.reason = None
        case_info.name = None
        case_info.source_system_url = None
        case_info.source_rule_identifier = None
        case_info.device_vendor = None
        case_info.device_product = None
        case_info.start_time = None
        case_info.end_time = None
        case_info.is_test_case = False
        case_info.priority = -1
        case_info.rule_generator = None
        case_info.source_grouping_identifier = None
        case_info.extensions = {}
        case_info.events = []
        case_info.attachments = []
        case_info.siem_alert_id = None

    def test_alert_info(self) -> None:
        # arrange
        alert_info = AlertInfo()

        # assert
        alert_info.environment = None
        alert_info.ticket_id = None
        alert_info.description = None
        alert_info.display_id = None
        alert_info.reason = None
        alert_info.name = None
        alert_info.source_system_url = None
        alert_info.source_rule_identifier = None
        alert_info.device_vendor = None
        alert_info.device_product = None
        alert_info.start_time = None
        alert_info.end_time = None
        alert_info.is_test_case = False
        alert_info.priority = -1
        alert_info.rule_generator = None
        alert_info.source_grouping_identifier = None
        alert_info.extensions = {}
        alert_info.events = []
        alert_info.attachments = []
        alert_info.siem_alert_id = None
