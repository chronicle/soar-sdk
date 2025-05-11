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

import datetime
import sys

import arrow
import pytest
import requests
from dateutil import parser, tz

from soar_sdk.Siemplify import SiemplifyUtils
from soar_sdk.SiemplifyDataModel import DomainEntityInfo

SYSTEM_NOTIFICATION_CUSTOM_MESSAGE_ID = "SDK_CUSTOM_NOTIFICATION"
SYSTEM_NOTIFICATION_MESSAGE_CHAR_LIMIT = 500
SYSTEM_NOTIFICATION_MESSAGE_ID_CHAR_LIMIT = 50
SIEMPLIFY_ACTION_OBJ = """{"case_id":"1","alert_id":"RANDOM ALERT NAME 
B0259B26-B494-4CF3-AB1E-07347F13EF5C_00E2695E-E176-461D-981C-1D9CAF27D310",
"target_entities":[],"workflow_id":null,"parameters":{"Output Name":"test","Result 
Json Example":null,"Include JSON Result":"False","Polling Timeout":"600","Default 
Return Value":""},"python_version":0,"integration_identifier":"Siemplify",
"previous_remote_parameters":null,
"integration_instance":"f37562fa-c4ca-4d8b-ab37-b048241ca747",
"action_definition_name":"Get siemplify version","environment":"Default Environment",
"original_requesting_user":null,"async_polling_interval_in_sec":0,
"async_total_duration_deadline":0,"script_timeout_deadline":0,
"execution_deadline_unix_time_ms":1681735184309,"default_result_value":"",
"alert_identifier":"1","use_proxy_settings":false,"max_json_result_size":15,
"vault_settings":null}"""


class TestSiemplifyUtils:
    def test_is_at_least_python_3_11(self):
        if sys.version_info >= (3, 11):
            assert SiemplifyUtils.is_at_least_python_3_11() is True

        else:
            assert SiemplifyUtils.is_at_least_python_3_11() is False

    def test_create_session(self):
        session = SiemplifyUtils.SessionCreator.create_session()

        assert isinstance(session, requests.Session)

    def test_is_dict_in_list(self):
        # Standard input
        target_list = ["a", {"a": "1", "b": "2", "c": "3"}]
        expected_output = {"a": "1", "b": "2", "c": "3"}
        assert SiemplifyUtils.is_dict_in_list(target_list) == expected_output

        # Standard input with no dict in the list, that should return empty
        target_list = ["a", "b", "c", "d"]
        expected_output = None
        assert SiemplifyUtils.is_dict_in_list(target_list) == expected_output

        # Invalid input
        target_list = None
        with pytest.raises(TypeError) as excinfo:
            SiemplifyUtils.is_dict_in_list(target_list)
        assert "object is not iterable" in str(excinfo.value)

    def test_add_prefix_to_dict_keys(self, mocker):
        # With email in additional properties
        target_dict = {"a": "1", "b": "2", "c": "3"}
        prefix = "test"
        expected_output = {
            f"{prefix}_{key}": value for key, value in list(target_dict.items())
        }
        assert (
            SiemplifyUtils.add_prefix_to_dict_keys(target_dict, prefix)
            == expected_output
        )

        # None prefix
        target_dict = {"a": "1", "b": "2", "c": "3"}
        prefix = None
        expected_output = {
            f"{prefix}_{key}": value for key, value in list(target_dict.items())
        }
        assert (
            SiemplifyUtils.add_prefix_to_dict_keys(target_dict, prefix)
            == expected_output
        )

        # Invalid input
        target_dict = None
        prefix = "test"
        with pytest.raises(AttributeError) as excinfo:
            SiemplifyUtils.add_prefix_to_dict_keys(target_dict, prefix)
        assert "object has no attribute 'items'" in str(excinfo.value)

    def test_add_prefix_to_dict_encoded_keys(self, mocker):
        # With email in additional properties
        target_dict = {"a": "1", "b": "2", "c": "3"}
        prefix = "test"
        expected_output = {
            f"{prefix}_{key}": value for key, value in list(target_dict.items())
        }
        assert (
            SiemplifyUtils.add_prefix_to_dict_encoded_keys(target_dict, prefix)
            == expected_output
        )

        # None prefix
        target_dict = {"a": "1", "b": "2", "c": "3"}
        prefix = None
        expected_output = {
            f"{prefix}_{key}": value for key, value in list(target_dict.items())
        }
        assert (
            SiemplifyUtils.add_prefix_to_dict_encoded_keys(target_dict, prefix)
            == expected_output
        )

        # Invalid input
        target_dict = None
        prefix = "test"
        with pytest.raises(AttributeError) as excinfo:
            SiemplifyUtils.add_prefix_to_dict_encoded_keys(target_dict, prefix)
        assert "object has no attribute 'items'" in str(excinfo.value)

    def test_get_domain_from_entity_email(self, mocker):
        # With email in additional properties
        updated_entities = {
            "CaseIdentifier": "2",
            "AlertIdentifier": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
            "EntityType": "HOSTNAME",
            "IsInternal": False,
            "IsSuspicious": False,
            "IsArtifact": False,
            "IsEnriched": False,
            "IsVulnerable": False,
            "IsPivot": False,
            "Identifier": "LAB@SIEMPLIFY.LOCAL",
            "CreationTime": 0,
            "ModificationTime": 0,
            "AdditionalProperties": {
                "AutomationEntityKey_ez": "AutomationEntityValue_qs",
                "IsVulnerable": "False",
                "IsInternalAsset": "False",
                "IsAttacker": "False",
                "IsFromLdapString": "False",
                "IsTestCase": "False",
                "Environment": "Default Environment",
                "Network_Priority": "0",
                "Alert_Id": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
                "IsPivot": "False",
                "IsArtifact": "False",
                "IsSuspicious": "False",
                "IsManuallyCreated": "False",
                "Identifier": "LAB@SIEMPLIFY.LOCAL",
                "Type": "HOSTNAME",
                "IsEnriched": "False",
                "Email": "email@domain.com",
            },
        }
        test_entity = DomainEntityInfo(
            updated_entities.get("Identifier"),
            updated_entities.get("CreationTime"),
            updated_entities.get("ModificationTime"),
            updated_entities.get("CaseIdentifier"),
            updated_entities.get("AlertIdentifier"),
            updated_entities.get("EntityType"),
            updated_entities.get("IsInternal"),
            updated_entities.get("IsSuspicious"),
            updated_entities.get("IsArtifact"),
            updated_entities.get("IsEnriched"),
            updated_entities.get("IsVulnerable"),
            updated_entities.get("IsPivot"),
            updated_entities.get("AdditionalProperties"),
        )
        expected_output = test_entity.additional_properties["Email"].split("@")[-1]
        assert SiemplifyUtils.get_domain(test_entity) == expected_output

        # Without email in additional properties
        entity = {
            "CaseIdentifier": "2",
            "AlertIdentifier": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
            "EntityType": "HOSTNAME",
            "IsInternal": False,
            "IsSuspicious": False,
            "IsArtifact": False,
            "IsEnriched": False,
            "IsVulnerable": False,
            "IsPivot": False,
            "Identifier": "LAB@SIEMPLIFY.LOCAL",
            "CreationTime": 0,
            "ModificationTime": 0,
            "AdditionalProperties": {
                "AutomationEntityKey_ez": "AutomationEntityValue_qs",
                "IsVulnerable": "False",
                "IsInternalAsset": "False",
                "IsAttacker": "False",
                "IsFromLdapString": "False",
                "IsTestCase": "False",
                "Environment": "Default Environment",
                "Network_Priority": "0",
                "Alert_Id": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
                "IsPivot": "False",
                "IsArtifact": "False",
                "IsSuspicious": "False",
                "IsManuallyCreated": "False",
                "Identifier": "LAB@SIEMPLIFY.LOCAL",
                "Type": "HOSTNAME",
                "IsEnriched": "False",
            },
        }
        test_entity = DomainEntityInfo(
            updated_entities.get("Identifier"),
            updated_entities.get("CreationTime"),
            updated_entities.get("ModificationTime"),
            updated_entities.get("CaseIdentifier"),
            updated_entities.get("AlertIdentifier"),
            updated_entities.get("EntityType"),
            updated_entities.get("IsInternal"),
            updated_entities.get("IsSuspicious"),
            updated_entities.get("IsArtifact"),
            updated_entities.get("IsEnriched"),
            updated_entities.get("IsVulnerable"),
            updated_entities.get("IsPivot"),
            updated_entities.get("AdditionalProperties"),
        )
        expected_output = test_entity.additional_properties["Email"].split("@")[-1]
        assert SiemplifyUtils.get_domain(test_entity) == expected_output

        test_entity = None
        expected_output = None
        assert SiemplifyUtils.get_domain(test_entity) == expected_output

    def test_get_email_address(self, mocker):
        # With email in additional properties
        updated_entities = {
            "CaseIdentifier": "2",
            "AlertIdentifier": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
            "EntityType": "HOSTNAME",
            "IsInternal": False,
            "IsSuspicious": False,
            "IsArtifact": False,
            "IsEnriched": False,
            "IsVulnerable": False,
            "IsPivot": False,
            "Identifier": "LAB@SIEMPLIFY.LOCAL",
            "CreationTime": 0,
            "ModificationTime": 0,
            "AdditionalProperties": {
                "AutomationEntityKey_ez": "AutomationEntityValue_qs",
                "IsVulnerable": "False",
                "IsInternalAsset": "False",
                "IsAttacker": "False",
                "IsFromLdapString": "False",
                "IsTestCase": "False",
                "Environment": "Default Environment",
                "Network_Priority": "0",
                "Alert_Id": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
                "IsPivot": "False",
                "IsArtifact": "False",
                "IsSuspicious": "False",
                "IsManuallyCreated": "False",
                "Identifier": "LAB@SIEMPLIFY.LOCAL",
                "Type": "HOSTNAME",
                "IsEnriched": "False",
                "Email": "email@domain.com",
            },
        }

        test_entity = DomainEntityInfo(
            updated_entities.get("Identifier"),
            updated_entities.get("CreationTime"),
            updated_entities.get("ModificationTime"),
            updated_entities.get("CaseIdentifier"),
            updated_entities.get("AlertIdentifier"),
            updated_entities.get("EntityType"),
            updated_entities.get("IsInternal"),
            updated_entities.get("IsSuspicious"),
            updated_entities.get("IsArtifact"),
            updated_entities.get("IsEnriched"),
            updated_entities.get("IsVulnerable"),
            updated_entities.get("IsPivot"),
            updated_entities.get("AdditionalProperties"),
        )
        expected_output = test_entity.additional_properties["Email"]
        assert SiemplifyUtils.get_email_address(test_entity) == expected_output

        # Without email in additional properties
        entity = {
            "CaseIdentifier": "2",
            "AlertIdentifier": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
            "EntityType": "HOSTNAME",
            "IsInternal": False,
            "IsSuspicious": False,
            "IsArtifact": False,
            "IsEnriched": False,
            "IsVulnerable": False,
            "IsPivot": False,
            "Identifier": "LAB@SIEMPLIFY.LOCAL",
            "CreationTime": 0,
            "ModificationTime": 0,
            "AdditionalProperties": {
                "AutomationEntityKey_ez": "AutomationEntityValue_qs",
                "IsVulnerable": "False",
                "IsInternalAsset": "False",
                "IsAttacker": "False",
                "IsFromLdapString": "False",
                "IsTestCase": "False",
                "Environment": "Default Environment",
                "Network_Priority": "0",
                "Alert_Id": "DATA EXFILTRATION_63C61D5A-1F52-4463-AF4C-77C6E3E60A51",
                "IsPivot": "False",
                "IsArtifact": "False",
                "IsSuspicious": "False",
                "IsManuallyCreated": "False",
                "Identifier": "LAB@SIEMPLIFY.LOCAL",
                "Type": "HOSTNAME",
                "IsEnriched": "False",
            },
        }

        test_entity = DomainEntityInfo(
            updated_entities.get("Identifier"),
            updated_entities.get("CreationTime"),
            updated_entities.get("ModificationTime"),
            updated_entities.get("CaseIdentifier"),
            updated_entities.get("AlertIdentifier"),
            updated_entities.get("EntityType"),
            updated_entities.get("IsInternal"),
            updated_entities.get("IsSuspicious"),
            updated_entities.get("IsArtifact"),
            updated_entities.get("IsEnriched"),
            updated_entities.get("IsVulnerable"),
            updated_entities.get("IsPivot"),
            updated_entities.get("AdditionalProperties"),
        )
        expected_output = test_entity.additional_properties["Email"]
        assert SiemplifyUtils.get_email_address(test_entity) == expected_output

        test_entity = None
        expected_output = None
        assert SiemplifyUtils.get_email_address(test_entity) == expected_output

    def test_extract_domain(self, mocker):
        email = "email@domain.com"
        expected_output = email.split("@")[-1]
        assert SiemplifyUtils.extract_domain(email) == expected_output

        email = None
        with pytest.raises(AttributeError) as excinfo:
            SiemplifyUtils.extract_domain(email)
        assert "object has no attribute 'split'" in str(excinfo.value)

    def test_add_prefix_to_dict(self, mocker):
        given_dict = {"a": "1", "b": "2", "c": "3"}
        prefix = "data"
        expected_output = {
            f"{prefix}_{key}": value for key, value in list(given_dict.items())
        }
        assert SiemplifyUtils.add_prefix_to_dict(given_dict, prefix) == expected_output

        given_dict = None
        prefix = "data"
        with pytest.raises(AttributeError) as excinfo:
            SiemplifyUtils.add_prefix_to_dict(given_dict, prefix)
        assert "object has no attribute 'items'" in str(excinfo.value)

    def test_convert_datetime_to_unix_time(self, mocker):
        unix_time = 165018000
        expected_output = datetime.datetime(
            1970,
            1,
            1,
            0,
            0,
            0,
            0,
            tzinfo=tz.gettz("UTC"),
        ) + datetime.timedelta(milliseconds=unix_time)
        result = SiemplifyUtils.convert_unixtime_to_datetime(unix_time)
        assert result == expected_output

        # Test a negative Unix timestamp
        unix_time = -1650180000
        expected_output = datetime.datetime(
            1970,
            1,
            1,
            0,
            0,
            0,
            0,
            tzinfo=tz.gettz("UTC"),
        ) + datetime.timedelta(milliseconds=unix_time)
        result = SiemplifyUtils.convert_unixtime_to_datetime(unix_time)
        assert result == expected_output

        # Test a Unix timestamp that corresponds to a date after 2022
        unix_time = 1800000000
        expected_output = datetime.datetime(
            1970,
            1,
            1,
            0,
            0,
            0,
            0,
            tzinfo=tz.gettz("UTC"),
        ) + datetime.timedelta(milliseconds=unix_time)
        result = SiemplifyUtils.convert_unixtime_to_datetime(unix_time)
        assert result == expected_output

        unix_time = 165018000
        expected_output = datetime.datetime(
            1970,
            1,
            1,
            0,
            0,
            0,
            0,
            tzinfo=tz.gettz("UTC"),
        ) + datetime.timedelta(milliseconds=unix_time)
        result = SiemplifyUtils.convert_unixtime_to_datetime(unix_time)
        assert result == expected_output

    def test_unix_to_datetime(self, mocker):
        # Test the expected case
        unix_time = 1650180000
        expected_output = datetime.datetime(2022, 4, 16, 0, 0)
        mocker.patch("datetime.datetime")
        SiemplifyUtils.datetime.datetime.fromtimestamp.return_value = expected_output
        result = SiemplifyUtils.from_unix_time(unix_time)
        assert result == expected_output

        # Test a negative Unix timestamp
        unix_time = -1650180000
        expected_output = datetime.datetime(1937, 4, 8, 16, 40)
        SiemplifyUtils.datetime.datetime.fromtimestamp.return_value = expected_output
        result = SiemplifyUtils.from_unix_time(unix_time)
        assert result == expected_output

        # Test a Unix timestamp that corresponds to a date after 2022
        unix_time = 1800000000
        expected_output = datetime.datetime(2027, 9, 14, 19, 33, 20)
        SiemplifyUtils.datetime.datetime.fromtimestamp.return_value = expected_output
        result = SiemplifyUtils.from_unix_time(unix_time)
        assert result == expected_output

        # Test a Unix timestamp that is not an integer
        unix_time = "1650180000"
        with pytest.raises(TypeError):
            SiemplifyUtils.from_unix_time(unix_time)

        # Test a Unix timestamp that is None
        unix_time = None
        with pytest.raises(TypeError):
            SiemplifyUtils.from_unix_time(unix_time)

    def test_convert_string_to_datetime(self, mocker):
        # Test with standard input
        datetime_str = "Tue, 28 Mar 2017 21:34:39 +0700"
        timezone_str = "UTC"
        dt = parser.parse(datetime_str)

        if not dt.tzinfo:
            if timezone_str:
                aware_dt = arrow.get(dt).replace(tzinfo=timezone_str)
                expected_output = aware_dt.datetime
        else:
            expected_output = dt

        result = SiemplifyUtils.convert_string_to_datetime(datetime_str, timezone_str)
        assert result == expected_output

        # Test without timezone
        datetime_str = "Tue, 28 Mar 2017 21:34:39 +0700"
        timezone_str = None
        dt = parser.parse(datetime_str)

        if not dt.tzinfo:
            if timezone_str:
                aware_dt = arrow.get(dt).replace(tzinfo=timezone_str)
                dt = aware_dt.datetime
            else:
                expected_output = Exception(
                    "no timezone info was supplied (either in input string or "
                    "optional parameter",
                )
        else:
            expected_output = dt

        result = SiemplifyUtils.convert_string_to_datetime(datetime_str, timezone_str)
        assert result == expected_output

    @pytest.mark.parametrize(
        "input_value, expected_output",
        [
            (5, "5"),
            (True, "True"),
            ("Hello", "Hello"),
            (b"bytes", "bytes"),
            (b"Hello, World!", "Hello, World!"),
            (b"Bonjour, le monde!", "Bonjour, le monde!"),
            (b"\x80\x81\x82", "Unable to decode value (unknown encoding)"),
            (
                "Bonjour, le monde!".encode("iso-8859-15"),
                "Bonjour, le monde!",
            ),  # ISO-8859-15 encoding
            (
                "Привет, мир!".encode("windows-1251"),
                "Привет, мир!",
            ),  # Windows-1251 encoding
            (
                "こんにちは、世界！".encode("euc-jp"),
                "こんにちは、世界！",
            ),  # euc-jp encoding
        ],
    )
    def test_get_unicode_common(self, input_value, expected_output):
        result = SiemplifyUtils.get_unicode(input_value)
        assert result == expected_output
