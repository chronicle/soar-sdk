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
from SiemplifyDataModel import (
    Alert,
    AlertLazy,
    DomainEntityInfo,
    DomainRelationInfo,
    SecurityEventInfo,
)


class BaseProvider:
    def __init__(self, siemplify_api: Any) -> None:
        self._siemplify = siemplify_api


class BulkAlertsLoader(BaseProvider):
    """Loader responsible for fetching alert details (security events, entities, relations) in bulk.

    This is used when lazy loading is enabled to optimize API calls by fetching data for all
    alerts in a case at once, rather than making individual requests per alert.
    """

    def __init__(self, siemplify_api: Any, case_id: str | int) -> None:
        super().__init__(siemplify_api)
        self._case_id = case_id
        self._alerts: list[AlertLazy] = []

    def register_alert(self, alert: AlertLazy) -> None:
        self._alerts.append(alert)

    def load_details(self, *args: Any, **kwargs: Any) -> None:
        """Load entities, relations and security_events for all registered alerts."""
        alerts_details_data = self._siemplify.get_alerts_full_details(
            case_id=self._case_id,
            populate_original_file=self._siemplify.get_source_file,
        )
        details_map = {
            data.get("alert_group_identifier"): data for data in (alerts_details_data or [])
        }

        for alert in self._alerts or []:
            details = details_map.get(alert.alert_group_identifier, {})
            alert.entities = [
                DomainEntityInfo(**entity) for entity in details.get("domain_entities", []) or []
            ]
            alert.relations = [
                DomainRelationInfo(**relation)
                for relation in details.get("domain_relations", []) or []
            ]
            alert.security_events = [
                SecurityEventInfo(**event) for event in details.get("security_events", []) or []
            ]


class CaseAlertsProvider(BaseProvider):
    """Provider class responsible for retrieving alerts for a given case.

    It supports two modes of operation:
    1. Lazy Loading (is_alert_lazy_loading_enabled=True): Fetches basic alert data and uses BulkAlertsLoader
       to load detailed information (events, entities, relations) only when accessed.
    2. Eager Loading (is_alert_lazy_loading_enabled=False): Fetches all alert details upfront in a single API call.
    """

    def __init__(
        self,
        siemplify_api: Any,
        case_id: str | int | None = None,
        is_alert_lazy_loading_enabled: bool = False,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        # Handle legacy signature: (session, api_root, case_id, get_source_file, logger, address_provider)
        if len(args) >= 3 and not hasattr(siemplify_api, "get_alerts_full_details"):
            super().__init__(siemplify_api)
            self._case_id = args[1]
            self.case_id = args[1]
            self.is_alert_lazy_loading_enabled = False
            self.session = siemplify_api
            self.API_ROOT = case_id
            self.get_source_file = args[2] if len(args) > 2 else False
            self.logger = args[3] if len(args) > 3 else None
            self.address_provider = args[4] if len(args) > 4 else None
            self._legacy_mode = True
        else:
            super().__init__(siemplify_api)
            self._case_id = case_id
            self.case_id = case_id
            self.is_alert_lazy_loading_enabled = is_alert_lazy_loading_enabled
            self._legacy_mode = False

    def get_alerts(self) -> list[Any]:
        """Get alerts for the case.

        Returns a list of AlertLazy objects if lazy loading enabled, otherwise Alert objects.
        """
        if (
            getattr(self, "_legacy_mode", False)
            and hasattr(self, "address_provider")
            and self.address_provider
        ):
            address = self.address_provider.provide_get_alerts_full_details_address(
                self.case_id,
                self.get_source_file,
            )
            try:
                response = self.session.get(address)
                SiemplifyBase.validate_siemplify_error(response)
                return response.json()
            except Exception as e:
                if self.logger:
                    self.logger.exception(
                        f"Error while getting alerts for case {self.case_id}: {e}"
                    )
                return []

        if self.is_alert_lazy_loading_enabled:
            alerts_metadata = self._siemplify.get_case_alerts_metadata(self._case_id)
            alerts: list[AlertLazy] = []
            lazy_loader = BulkAlertsLoader(self._siemplify, self._case_id)

            for alert_metadata in alerts_metadata or []:
                lazy_alert = AlertLazy(
                    lazy_loader=lazy_loader,
                    **alert_metadata,
                )
                lazy_loader.register_alert(lazy_alert)
                alerts.append(lazy_alert)
            return alerts
        else:
            try:
                alerts_data = self._siemplify.get_alerts_full_details(
                    case_id=self._case_id,
                    populate_original_file=self._siemplify.get_source_file,
                )
                return [Alert(**alert) for alert in (alerts_data or [])]
            except Exception as e:
                logger = getattr(self._siemplify, "LOGGER", None)
                if logger:
                    logger.error(f"Failed to get alerts for case {self._case_id}: {e}")
                return []
