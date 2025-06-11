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

from typing import TYPE_CHECKING, Any

from SiemplifyBase import SiemplifyBase

if TYPE_CHECKING:
    import requests

    from SiemplifyAddressProvider import SiemplifyAddressProvider
    from SiemplifyLogger import SiemplifyLogger


class CaseAlertsProvider:
    def __init__(
        self,
        session: requests.Session,
        api_root: str,
        case_id: str | int,
        get_source_file: bool,
        logger: SiemplifyLogger,
        address_provider: SiemplifyAddressProvider,
    ) -> None:
        """Initialize a new instance of the CaseAlertsProvider class.

        Args:
            session: The `requests` session to use for making API calls.
            api_root: The root URL of the Siemplify API.
            case_id: The ID of the case to get alerts for.
            get_source_file: Whether to include the source file in the response.
            logger: The logger to use for logging.
            address_provider: The address provider to use for generating API
                addresses.

        Returns:
            None

        """
        self.session = session
        self.API_ROOT = api_root
        self.case_id = case_id
        self.get_source_file = get_source_file
        self.logger = logger
        self.address_provider = address_provider

    def get_alerts(self) -> dict[str, Any]:
        """Get alerts for a case.

        Returns:
            dict[str, Any]: The alerts for the case.

        """
        address = self.address_provider.provide_get_alerts_full_details_address(
            self.case_id,
            self.get_source_file,
        )

        try:
            response = self.session.get(address)
            SiemplifyBase.validate_siemplify_error(response)
            return response.json()
        except Exception as e:
            self.logger.exception(
                f"Error while getting alerts for case {self.case_id}: {e}",
            )
            return {}
