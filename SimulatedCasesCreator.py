import os
import json
from SiemplifyConnectorsDataModel import CaseInfo
import uuid
import SiemplifyUtils

class SimulatedCasesCreator(object):
    def create_cases_from_json(self, file_path):
        absolute_path = self.convert_to_absolut_path(file_path)
        f = open(absolute_path, "r")
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

            case_info.start_time = SiemplifyUtils.unix_now()  # newly generated every time
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

    def build_events_from_json_events(self, jsonEvents):
        events = []

        for jsonEvent in jsonEvents:
            raw_data_fields = jsonEvent["_rawDataFields"]
            events.append(raw_data_fields)

        return events

    def convert_to_absolut_path(self, relative_path):
        running_folder = os.path.dirname(os.path.abspath(__file__))
        absolut_path = os.path.join(running_folder, relative_path)
        return absolut_path