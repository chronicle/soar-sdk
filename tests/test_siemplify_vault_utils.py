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

import soar_sdk.SiemplifyVaultUtils


class TestSiemplifyVaultUtils:
    def test_extract_vault_param_not_vault_placeholder_returns_the_param_success(self):
        # arrange
        not_vault_placeholder_configuration_item = "configuration_item"

        # act
        result = soar_sdk.SiemplifyVaultUtils.extract_vault_param(
            not_vault_placeholder_configuration_item, "dummy settings",
        )

        # assert
        assert result == not_vault_placeholder_configuration_item

    def test_extract_vault_param_vault_placeholder_returns_the_mock_param_success(
        self, mocker,
    ):
        # arrange
        vault_placeholder_configuration_item = (
            "[Default Environment:::CyberArkPAM:::CyberArkPAM_1:::33_3]"
        )
        mock_secret = "mocked secret value"
        mocker.patch("SiemplifyVaultUtils.get_vault_secret", return_value=mock_secret)

        # act
        result = soar_sdk.SiemplifyVaultUtils.extract_vault_param(
            vault_placeholder_configuration_item, "dummy settings",
        )

        # assert
        assert result == mock_secret

    def test_get_vault_secret_missing_url_vault_param_throws_exception(self, mocker):
        # arrange
        account_id = "test_account_id"
        vault_settings = {
            "vault_username": "vault_username",
            "vault_password": "vault_password",
            "vault_type": 0,
        }

        # act
        with pytest.raises(Exception) as excinfo:
            soar_sdk.SiemplifyVaultUtils.get_vault_secret(account_id, vault_settings)

        # assert
        assert "Cannot initialize vault. Missing parameters" in str(excinfo.value)

    def test_get_vault_secret_missing_username_vault_param_throws_exception(self):
        # arrange
        account_id = "test_account_id"
        vault_settings = {
            "vault_api_root": "https://mock-vault.com",
            "vault_password": "vault_password",
            "vault_type": 0,
        }

        # act
        with pytest.raises(Exception) as excinfo:
            soar_sdk.SiemplifyVaultUtils.get_vault_secret(account_id, vault_settings)

        # assert
        assert "Cannot initialize vault. Missing parameters" in str(excinfo.value)

    def test_get_vault_secret_missing_password_vault_param_throws_exception(self):
        # arrange
        account_id = "test_account_id"
        vault_settings = {
            "vault_api_root": "https://mock-vault.com",
            "vault_username": "vault_username",
            "vault_type": 0,
        }

        # act
        with pytest.raises(Exception) as excinfo:
            soar_sdk.SiemplifyVaultUtils.get_vault_secret(account_id, vault_settings)

        # assert
        assert "Cannot initialize vault. Missing parameters" in str(excinfo.value)

    def test_get_vault_secret_invalid_vault_provider_type_throws_exception(self):
        # arrange
        account_id = "test_account_id"
        vault_settings = {
            "vault_api_root": "https://mock-vault.com",
            "vault_username": "vault_username",
            "vault_type": 2,
        }

        # act
        with pytest.raises(Exception) as excinfo:
            soar_sdk.SiemplifyVaultUtils.get_vault_secret(account_id, vault_settings)

        # assert
        assert "The vault provider {0} is not supported".format(
            vault_settings.get("vault_type"),
        ) in str(excinfo.value)
