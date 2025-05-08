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

import json


class ConnectorContext:
    def __init__(
        self,
        connector_info,
        vault_settings=None,
        environment_api_key=None,
        connector_api_key=None,
    ):
        self.connector_info = ConnectorInfo(**connector_info)
        self.vault_settings = vault_settings
        self.environment_api_key = environment_api_key
        self.connector_api_key = connector_api_key


class ConnectorInfo:
    def __init__(self, **kwargs):
        self.environment = kwargs.get("environment")
        self.integration = kwargs.get("integration")
        self.connector_definition_name = kwargs.get("connector_definition_name")
        self.identifier = kwargs.get("identifier")
        self.display_name = kwargs.get("display_name")
        self.description = kwargs.get("description")
        self.is_locally_scheduled_remote_connector = kwargs.get(
            "is_locally_scheduled_remote_connector",
            False,
        )
        self.result_data_type = kwargs.get("result_data_type")
        self.params = kwargs.get("params")
        white_list = kwargs.get("allow_list", kwargs.get("white_list"))
        if white_list is not None:
            self.white_list = white_list
        else:
            white_list = kwargs.get(
                "allow_list_json_object",
                kwargs.get("white_list_json_object"),
            )
            self.white_list = json.loads(white_list) if white_list != None else None


class CaseInfo:
    def __init__(self):
        self.environment = None
        self.ticket_id = None
        self.description = None
        self.display_id = None
        self.reason = None
        self.name = None
        self.source_system_url = None
        self.source_rule_identifier = None
        self.device_vendor = None
        self.device_product = None
        self.start_time = None
        self.end_time = None
        self.is_test_case = False
        self.priority = -1
        self.rule_generator = None
        self.source_grouping_identifier = None
        self.extensions = {}
        self.events = []
        self.attachments = []
        self.siem_alert_id = None
        self.updated_fields = {}
        self.alert_update_supported = False
        self.alert_metadata = {}
        self.data_access_scope = None


class AlertInfo(CaseInfo):
    def __init__(self):
        super(AlertInfo, self).__init__()
