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
import requests

import soar_sdk.GcpTokenProvider
from soar_sdk.SiemplifyBase import HEADERS, SiemplifyBase


class TestSiemplifyBase:
    @pytest.fixture(autouse=True)
    def restore_headers(self):
        """Fixture to backup and restore the original HEADERS."""
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

        assert (
            str(
                excinfo.value,
            )
            == "Environment SERVER_API_ROOT not found or malformed"
        )

    def test_get_script_context_python_37(self, mocker):
        value = "Success"
        mocker.patch("sys.stdin.read", return_value=value)
        mocker.patch("soar_sdk.SiemplifyUtils.is_python_37", return_value=False)

        context = SiemplifyBase.get_script_context()

        assert context == value

    def test_get_script_context_python_not_37(self, mocker):
        if sys.version_info >= (3, 7):
            expected_value = "Success"
            different_value = "Not Success"
            mocker.patch("sys.stdin.read", return_value=different_value)
            mocker.patch("sys.stdin.buffer.read", return_value=expected_value)
            mocker.patch("soar_sdk.SiemplifyUtils.is_python_37", return_value=True)

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
            siemplify_base,
            "_create_remote_session",
            return_value=mock_response,
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
            soar_sdk.GcpTokenProvider.GcpTokenProvider,
            "add_gcp_token",
        )
        mock_sdk_config = MagicMock()
        mock_sdk_config.gcp_auth_required = True
        mock_sdk_config.is_remote_publisher_sdk = False
        mock_sdk_config.run_folder_path = ""
        mocker.patch(
            "soar_sdk.SiemplifyBase.SiemplifySdkConfig",
            return_value=mock_sdk_config,
        )
        siemplify_base = SiemplifyBase()

        gcp_provider_mock.assert_called_once_with(siemplify_base)

    def test_does_not_add_gcp_token_when_auth_not_needed(self, mocker):
        gcp_provider_mock = mocker.patch.object(
            soar_sdk.GcpTokenProvider.GcpTokenProvider,
            "add_gcp_token",
        )
        mock_sdk_config = MagicMock()
        mock_sdk_config.gcp_auth_required = False
        mock_sdk_config.run_folder_path = ""
        mocker.patch(
            "soar_sdk.SiemplifyBase.SiemplifySdkConfig",
            return_value=mock_sdk_config,
        )
        SiemplifyBase()

        gcp_provider_mock.assert_not_called()

    @pytest.mark.parametrize(
        "is_remote, remote_auth, local_auth, expected_result",
        [
            # Test case 1: Remote sdk and remote auth required
            (True, True, False, True),
            # Test case 2: Remote sdk but no remote auth required
            (True, False, False, False),
            # Test case 3: Not remote sdk, but local auth required
            (False, False, True, True),
            # Test case 4: Not remote sdk and no local auth required
            (False, False, False, False),
        ],
    )
    def test_is_running_on_dataplane(
        self, mocker, is_remote: bool, remote_auth: bool, local_auth: bool, expected_result: bool
    ) -> None:
        """Tests the is_running_on_dataplane method under different configurations using parameterization."""
        base = SiemplifyBase()
        base.sdk_config = mocker.MagicMock()
        # Set up the mock sdk_config attributes based on parameters
        base.sdk_config.is_remote_publisher_sdk = is_remote
        base.sdk_config.remote_gcp_auth_required = remote_auth
        base.sdk_config.gcp_auth_required = local_auth

        # Call the method under test
        result = base.is_running_on_dataplane

        # Assert the expected outcome
        assert result is expected_result

    @pytest.mark.parametrize(
        "status_code, response_content, is_dataplane, expected_result",
        [
            # --- Status 204 (NO_CONTENT) ---
            # If status is 204, should always be True, regardless of content or dataplane
            (204, b"data", True, True),
            (204, b"", False, True),
            # --- Status Not 204 ---
            # On dataplane AND no content (This is the special case)
            (200, b"", True, True),
            # On dataplane AND no content (None should also count as no content)
            (200, None, True, True),
            # On dataplane BUT has content
            (200, b"data", True, False),
            # Not on dataplane AND no content
            (200, b"", False, False),
            # Not on dataplane AND has content
            (200, b"data", False, False),
        ],
    )
    def test_has_no_data(
        self,
        mocker,
        status_code: int,
        response_content: bytes | None,
        is_dataplane: bool,
        expected_result: bool,
    ) -> None:
        """Tests the has_no_data method logic:
        - True if status is 204
        - OR True if (on dataplane AND no content)
        - False otherwise
        """
        mocker.patch.object(
            SiemplifyBase,
            "is_running_on_dataplane",
            new_callable=mocker.PropertyMock,
            return_value=is_dataplane,
        )
        base = SiemplifyBase()

        mock_response = mocker.Mock()
        mock_response.status_code = status_code
        mock_response.content = response_content

        result = base.has_no_data(mock_response)

        assert result is expected_result

    def test_create_session_with_retries(self, mocker) -> None:
        # arrange
        mocker.patch("sys.argv", ["path/to/script.py", "dummy_api_key", "--featSDKRetries"])
        mocker.patch("time.sleep")
        mock_make_request = mocker.patch("urllib3.connectionpool.HTTPConnectionPool._make_request")

        mock_httplib_resp = MagicMock()
        mock_httplib_resp.status = 502
        mock_httplib_resp.msg = MagicMock()
        mock_httplib_resp.read.return_value = b""
        mock_httplib_resp.isclosed.return_value = False
        mock_httplib_resp.headers.get.return_value = None
        mock_httplib_resp.get_redirect_location.return_value = None

        mock_make_request.return_value = mock_httplib_resp

        # Mock logger to avoid FileNotFoundError for log file
        mocker.patch("soar_sdk.SiemplifyLogger.SiemplifyLogger")

        siemplify = SiemplifyBase()

        # Mock address provider to avoid actual URL resolution
        mocker.patch.object(
            siemplify.address_provider,
            "provide_get_context_property_address",
            return_value="http://test-site.com/api/context",
        )

        # act & assert we receive a retry error
        with pytest.raises(requests.exceptions.RetryError):
            siemplify.get_context_property_from_server(1, "identifier", "key")

        # Assert retries happened (1 initial + 3 retries)
        assert mock_make_request.call_count == 4

        # Assert AppKey header is present in session
        assert "AppKey" in siemplify.session.headers
        assert siemplify.session.headers["AppKey"] == "dummy_api_key"
