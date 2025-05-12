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

from typing import Any

from . import SiemplifyUtils

"""
Base vault class. All vault provider managers should inherit from it.
"""


class SiemplifyVault:
    def __init__(self, vault_settings: dict[str, Any]) -> None:
        # Extract and validate vault parameters
        if vault_settings is not None:
            self.session = SiemplifyUtils.SessionCreator.create_session()
            self.api_root = vault_settings.get("vault_api_root")
            self.verify_ssl = vault_settings.get("vault_verify_ssl", False)
            self.username = vault_settings.get("vault_username")
            self.password = vault_settings.get("vault_password")
            self.client_ca_certificate = vault_settings.get(
                "vault_client_ca_certificate",
            )
            self.client_certificate = vault_settings.get("vault_client_certificate")
            self.client_certificate_passphrase = vault_settings.get(
                "vault_client_certificate_passphrase",
            )
            self.validate_vault_params()

    def validate_vault_params(self) -> None:
        if not self.username or not self.password or not self.api_root:
            raise Exception("Cannot initialize vault. Missing parameters")
