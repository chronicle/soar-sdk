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

import base64
import copy
import sys
from unittest.mock import MagicMock

import pytest

import soar_sdk.GcpTokenProvider
from soar_sdk.SiemplifyBase import HEADERS, SiemplifyBase


class TestSiemplifyBase:
    @pytest.fixture(autouse=True)
    def restore_headers(self):
        """Fixture to backup and restore the original HEADERS.
        """
        original_headers = copy.deepcopy(HEADERS)  # Create a deep copy
        yield  # This is where the test using the fixture runs
        HEADERS.clear()  # Remove all current headers. Important for complete
        # restoration.
        HEADERS.update(original_headers)  # Restore from the backup

    def test_siemplify_base_with_baggage_trace(self, mocker):
        # arrange
        TEST_TRACE_ID = "00-956ee8cd79040634d6893323f178bc2d-293643608083a79e-00"
        TEST_BAGGAGE_DATA = "test"
        TEST_BAGGAGE_ENCODED = base64.b64encode(
            TEST_BAGGAGE_DATA.encode("utf-8"),
        ).decode("utf-8")

        mocker.patch(
            "sys.argv",
            [
                "path/to/script.py",
                "QgCZoPAUF8w9FGdXq5wfCyRGG/hK8okLU20qX6KrdjM=",
                "--logPath",
                "/var/log/siemplify/jobs/Actions Monitor/2025021112.log",
                "--correlationId",
                "009ef99da2da4bb5baab273d07ae9a0e",
                "--traceId",
                TEST_TRACE_ID,
                "--baggage",
                TEST_BAGGAGE_ENCODED,
            ],
        )

        # act
        siemplify = SiemplifyBase()

        # assert
        assert siemplify.session.headers["traceparent"] == TEST_TRACE_ID
        assert siemplify.session.headers["baggage"] == TEST_BAGGAGE_DATA

    def test_siemplify_base_without_baggage_trace(self, mocker):
        # arrange
        mocker.patch(
            "sys.argv",
            [
                "path/to/script.py",
                "QgCZoPAUF8w9FGdXq5wfCyRGG/hK8okLU20qX6KrdjM=",
                "--logPath",
                "/var/log/siemplify/jobs/Actions Monitor/2025021112.log",
                "--correlationId",
                "009ef99da2da4bb5baab273d07ae9a0e",
            ],
        )

        # act + assert
        siemplify = SiemplifyBase()

    @pytest.mark.parametrize(
        "uri",
        [
            "https://this-is-server.com/pub/api",
            "https://this-is-server.com/api",
            "https://this-is-server.com",
            "this-is-server.com",
        ],
    )
    def test_platform_url_local_success(self, uri, mocker):
        base = SiemplifyBase()
        mocker.patch("os.environ.get", return_value=uri)

        assert base.platform_url == "https://this-is-server.com/"

    def test_platform_url_local_raise_exception(self, mocker):
        base = SiemplifyBase()
        mocker.patch("os.environ.get", return_value=None)

        with pytest.raises(Exception) as excinfo:
            url = base.platform_url

        assert str(excinfo.value) == "Environment CLIENT_ADDRESS not found"

    @pytest.mark.parametrize(
        "uri",
        [
            "https://this-is-server.com/pub/api",
            "https://this-is-server.com/api",
            "https://this-is-server.com",
            "this-is-server.com",
        ],
    )
    def test_platform_url_remote_success(self, uri):
        base = SiemplifyBase()
        base.sdk_config.is_remote_publisher_sdk = True
        base.sdk_config.api_root_uri = uri

        assert base.platform_url == "https://this-is-server.com/"

    def test_platform_url_remote_raise_exception(self):
        base = SiemplifyBase()
        base.sdk_config.is_remote_publisher_sdk = True
        base.sdk_config.api_root_uri = None

        with pytest.raises(Exception) as excinfo:
            url = base.platform_url

        assert str(
            excinfo.value,
        ) == "Environment SERVER_API_ROOT not found or malformed"

    def test_get_script_context_python_37(self, mocker):
        value = "Success"
        mocker.patch("sys.stdin.read", return_value=value)
        mocker.patch("SiemplifyUtils.is_python_37", return_value=False)

        context = SiemplifyBase.get_script_context()

        assert context == value

    def test_get_script_context_python_not_37(self, mocker):
        if sys.version_info >= (3, 7):
            expected_value = "Success"
            different_value = "Not Success"
            mocker.patch("sys.stdin.read", return_value=different_value)
            mocker.patch("sys.stdin.buffer.read", return_value=expected_value)
            mocker.patch("SiemplifyUtils.is_python_37", return_value=True)

            context = SiemplifyBase.get_script_context()

            assert context == expected_value

    def test_init_remote_session(self, mocker, key=1):
        expected_app_key = "app_key"

        mocked_argv = ["some_value", expected_app_key]
        mocker.patch.object(sys, "argv", mocked_argv)
        siemplify_base = SiemplifyBase()

        # arrange
        mock_response = mocker.Mock()
        mocker.patch("os.environ.get", return_value=True)

        # act
        mocker.patch.object(
            siemplify_base, "_create_remote_session", return_value=mock_response,
        )
        siemplify_base._init_remote_session(key)

        # assert
        if sys.version_info >= (3, 7):
            siemplify_base._create_remote_session.assert_called_with(
                key,
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "AppKey": expected_app_key,
                },
            )
        else:
            siemplify_base._create_remote_session.assert_called_with(
                key,
                {
                    "AppKey": expected_app_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )

    def test_create_remote_session(self, mocker, key=1, headers={}):
        # arrange
        siemplify_base = SiemplifyBase()
        mock_response = mocker.Mock()
        mocker.patch("os.environ.get", return_value="true")
        siemplify_base.remote_agent_proxy = True

        # act
        mocker.patch("requests.Session", return_value=mock_response)
        response = siemplify_base._create_remote_session(key, headers)

        # assert
        assert response == mock_response

    def test_add_gcp_token_when_auth_needed(self, mocker):
        gcp_provider_mock = mocker.patch.object(
            soar_sdk.GcpTokenProvider.GcpTokenProvider, "add_gcp_token",
        )
        mock_sdk_config = MagicMock()
        mock_sdk_config.gcp_auth_required = True
        mock_sdk_config.run_folder_path = ""
        mocker.patch("SiemplifyBase.SiemplifySdkConfig", return_value=mock_sdk_config)
        siemplify_base = SiemplifyBase()

        gcp_provider_mock.assert_called_once_with(siemplify_base)

    def test_does_not_add_gcp_token_when_auth_not_needed(self, mocker):
        gcp_provider_mock = mocker.patch.object(
            soar_sdk.GcpTokenProvider.GcpTokenProvider, "add_gcp_token",
        )
        mock_sdk_config = MagicMock()
        mock_sdk_config.gcp_auth_required = False
        mock_sdk_config.run_folder_path = ""
        mocker.patch("SiemplifyBase.SiemplifySdkConfig", return_value=mock_sdk_config)
        SiemplifyBase()

        gcp_provider_mock.assert_not_called()
