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

from SiemplifyVaultCyberArkPam import SiemplifyVaultCyberArkPam

# vault providers enums
CYBERARK_VAULT_PROVIDER: int = 0


# the vault factory class creates the vault correct vault provider according to the
# vault type
class VaultProviderFactory:
    @staticmethod
    def create_vault_class_by_provider_type(
        vault_settings: dict[str, Any] | None,
    ) -> SiemplifyVaultCyberArkPam:
        if vault_settings is None:
            raise Exception("Vault settings were not supplied")

        provider_type = vault_settings.get("vault_type", CYBERARK_VAULT_PROVIDER)

        # For now, we only support CyberArkVault provider
        if provider_type == CYBERARK_VAULT_PROVIDER:
            return SiemplifyVaultCyberArkPam(vault_settings)
        raise Exception(f"The vault provider {provider_type} is not supported")
