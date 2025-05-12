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
import os
import uuid
from typing import Any

from . import SiemplifyUtils
from .SiemplifyConnectorsDataModel import CaseInfo


class SimulatedCasesCreator:
    def create_cases_from_json(self, file_path: str) -> list[CaseInfo]:
        absolute_path = self.convert_to_absolut_path(file_path)
        f = open(absolute_path)
        jsonContent = f.read()

        caseJson = json.loads(jsonContent)

        cases = []

        for case in caseJson["Cases"]:
            jsonEvents = case["Events"]
            events = self.build_events_from_json_events(jsonEvents)

            case_info = CaseInfo()
            case_info.events = events
            case_info.ticket_id = str(uuid.uuid4())  # newly generated every time

            case_info.environment = case["Environment"]
            # case_info. = ["SourceSystemName": "Splunk",

            case_info.start_time = (
                SiemplifyUtils.unix_now()
            )  # newly generated every time
            case_info.end_time = SiemplifyUtils.unix_now()  # newly generated every time

            case_info.description = case["Description"]
            case_info.dis = case["DisplayId"]
            # case_info. = ["Reason": "Phishing email detector",
            case_info.name = case["Name"]
            case_info.device_vendor = case["DeviceVendor"]
            case_info.device_product = case["DeviceProduct"]
            case_info.priority = case["Priority"]
            case_info.rule_generator = case["RuleGenerator"]
            # case_info. = ["Extensions": [],
            # case_info.is_ = ["IsTestCase": false

            cases.append(case_info)

        return cases

    def build_events_from_json_events(
        self,
        jsonEvents: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        events = []

        for jsonEvent in jsonEvents:
            raw_data_fields = jsonEvent["_rawDataFields"]
            events.append(raw_data_fields)

        return events

    def convert_to_absolut_path(self, relative_path: str) -> str:
        running_folder = os.path.dirname(os.path.abspath(__file__))
        absolut_path = os.path.join(running_folder, relative_path)
        return absolut_path
