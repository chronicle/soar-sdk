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

from soar_sdk.GcpTokenProvider import GcpTokenProvider

CHRONICLE_SERVICE_ACCOUNT_EMAIL = "CHRONICLE_SERVICE_ACCOUNT_EMAIL"
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class TestGcpTokenProvider:
    def test_add_gcp_token_local_with_impersonation_success(self, mocker):
        # arrange
        service_account_email = "mockEmail"
        token = "expected_token"

        mocker.patch("os.environ.get", return_value=service_account_email)

        mock_siempliy_base_obj = mocker.Mock()
        mock_siempliy_base_obj.sdk_config.is_remote_publisher_sdk = False
        mock_siempliy_base_obj.session.headers = {}

        mock_credentials_obj = mocker.Mock()
        mock_impersonated_credentials_obj = mocker.Mock()
        mock_auth_request_obj = mocker.Mock()

        # Define the side effect for the refresh method
        def refresh_side_effect(*args, **kwargs):
            if len(args) > 0 and args[0] == mock_auth_request_obj:
                mock_impersonated_credentials_obj.token = (
                    token  # Assign the token property
                )

        mock_impersonated_credentials_obj.refresh.side_effect = refresh_side_effect

        mock_auth_default = mocker.patch(
            "google.auth.default",
            return_value=(mock_credentials_obj, "mocked_project_id"),
        )
        mock_impersonated_credentials = mocker.patch(
            "google.auth.impersonated_credentials.Credentials",
            return_value=mock_impersonated_credentials_obj,
        )
        mocker.patch(
            "google.auth.transport.requests.Request",
            return_value=mock_auth_request_obj,
        )

        # act
        GcpTokenProvider.add_gcp_token(mock_siempliy_base_obj)

        # assert
        mock_auth_default.assert_called_once_with(DEFAULT_SCOPES)
        mock_impersonated_credentials.assert_called_once_with(
            source_credentials=mock_credentials_obj,
            target_principal=service_account_email,
            target_scopes=DEFAULT_SCOPES,
        )
        assert (
            mock_siempliy_base_obj.session.headers["Authorization"] == f"Bearer {token}"
        )

    def test_add_gcp_token_local_with_impersonation_no_impersonation_credentials_failed(
        self,
        mocker,
    ):
        # arrange
        service_account_email = "mockEmail"

        mocker.patch("os.environ.get", return_value=service_account_email)

        mock_siempliy_base_obj = mocker.Mock()
        mock_siempliy_base_obj.sdk_config.is_remote_publisher_sdk = False
        mock_siempliy_base_obj.session.headers = {}

        mock_credentials_obj = mocker.Mock()

        # Define the side effect for the refresh method

        mock_auth_default = mocker.patch(
            "google.auth.default",
            return_value=(mock_credentials_obj, "mocked_project_id"),
        )
        mocker.patch(
            "google.auth.impersonated_credentials.Credentials",
            return_value=None,
        )

        # act
        GcpTokenProvider.add_gcp_token(mock_siempliy_base_obj)

        # assert
        mock_auth_default.assert_called_once_with(DEFAULT_SCOPES)
        assert len(mock_siempliy_base_obj.session.headers) == 0

    def test_add_gcp_token_local_with_impersonation_no_mail_failed(self, mocker):
        # arrange
        mocker.patch("os.environ.get", return_value=None)

        mock_siempliy_base_obj = mocker.Mock()
        mock_siempliy_base_obj.sdk_config.is_remote_publisher_sdk = False
        mock_siempliy_base_obj.session.headers = {}

        mock_credentials_obj = mocker.Mock()
        mock_impersonated_credentials_obj = mocker.Mock()
        mock_auth_default = mocker.patch(
            "google.auth.default",
            return_value=(mock_credentials_obj, "mocked_project_id"),
        )
        mock_impersonated_credentials = mocker.patch(
            "google.auth.impersonated_credentials.Credentials",
            return_value=mock_impersonated_credentials_obj,
        )

        # act
        GcpTokenProvider.add_gcp_token(mock_siempliy_base_obj)

        # assert
        mock_auth_default.assert_called_once_with(DEFAULT_SCOPES)
        mock_impersonated_credentials.assert_not_called()
        assert len(mock_siempliy_base_obj.session.headers) == 0

    def test_add_gcp_token_local_with_impersonation_no_credentials(self, mocker):
        # arrange
        mocker.patch("os.environ.get", return_value=None)

        mock_siempliy_base_obj = mocker.Mock()
        mock_siempliy_base_obj.sdk_config.is_remote_publisher_sdk = False
        mock_siempliy_base_obj.session.headers = {}

        # Define the side effect for the refresh method

        mock_auth_default = mocker.patch(
            "google.auth.default",
            return_value=(None, "mocked_project_id"),
        )

        # act
        GcpTokenProvider.add_gcp_token(mock_siempliy_base_obj)

        # assert
        mock_auth_default.assert_called_once_with(DEFAULT_SCOPES)
        assert len(mock_siempliy_base_obj.session.headers) == 0

    def test_add_gcp_token_remote_success(self, mocker):
        # arrange
        token = "expected_token"

        mock_siempliy_base_obj = mocker.Mock()
        mock_siempliy_base_obj.sdk_config.is_remote_publisher_sdk = True
        mock_siempliy_base_obj.session.headers = {}

        mock_credentials_obj = mocker.Mock()
        mock_auth_request_obj = mocker.Mock()

        # Define the side effect for the refresh method
        def refresh_side_effect(*args, **kwargs):
            if len(args) > 0 and args[0] == mock_auth_request_obj:
                mock_credentials_obj.token = token  # Assign the token property

        mock_credentials_obj.refresh.side_effect = refresh_side_effect

        mock_auth_default = mocker.patch(
            "google.auth.default",
            return_value=(mock_credentials_obj, "mocked_project_id"),
        )
        mocker.patch(
            "google.auth.transport.requests.Request",
            return_value=mock_auth_request_obj,
        )

        # act
        GcpTokenProvider.add_gcp_token(mock_siempliy_base_obj)

        # assert
        mock_auth_default.assert_called_once_with(DEFAULT_SCOPES)

        assert (
            mock_siempliy_base_obj.session.headers["Authorization"] == f"Bearer {token}"
        )
