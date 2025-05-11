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
import signal
import time
import unittest.mock

import pytest

from soar_sdk.CaseAlertsProvider import CaseAlertsProvider
from soar_sdk.Siemplify import Siemplify
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyBase import SiemplifyBase
from soar_sdk.SiemplifyDataModel import (
    Alert,
    Attachment,
    CustomList,
    CyberCase,
    CyberCaseLazy,
    DomainEntityInfo,
)

try:
    from unittest.mock import PropertyMock, mock_open, patch
except ImportError:
    from unittest.mock import PropertyMock, patch

with open(
    os.path.join(os.path.dirname(__file__), "siemplify_action_mock.json"),
) as f:
    DATA = f.read()

test_entities = {
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
        "ThreatSource": "AutomationEntityValue_qs",
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

test_lazy_case = CyberCaseLazy(
    alerts_provider=CaseAlertsProvider(None, None, None, None, None, None),
    identifier=1,
    creation_time=None,
    modification_time=None,
    alert_count=1,
    priority=None,
    is_touched=False,
    is_merged=False,
    is_important=True,
    environment="Default",
    assigned_user=None,
    title="Test",
    description=None,
    status=None,
    is_incident=False,
    stage=None,
    has_suspicious_entity=None,
    high_risk_products=None,
    is_locked=False,
    has_workflow=False,
    sla_expiration_unix_time=None,
    additional_properties=None,
)

lazy_case_dict = dict(
    identifier=1,
    creation_time=None,
    modification_time=None,
    alert_count=1,
    priority=None,
    is_touched=False,
    is_merged=False,
    is_important=True,
    environment="Default",
    assigned_user=None,
    title="Test",
    description=None,
    status=None,
    is_incident=False,
    stage=None,
    has_suspicious_entity=None,
    high_risk_products=None,
    is_locked=False,
    has_workflow=False,
    sla_expiration_unix_time=None,
    additional_properties=None,
)

test_cyber_case = dict(
    identifier=1,
    creation_time=None,
    modification_time=None,
    alert_count=1,
    priority=None,
    is_touched=False,
    is_merged=False,
    is_important=True,
    environment="Default",
    assigned_user=None,
    title="Test",
    description=None,
    status=None,
    is_incident=False,
    stage=None,
    has_suspicious_entity=None,
    high_risk_products=None,
    is_locked=False,
    has_workflow=False,
    sla_expiration_unix_time=None,
    additional_properties=None,
    cyber_alerts=[],
)

test_dict_alert = dict(
    identifier=1,
    alert_group_identifier=None,
    creation_time=time.time(),
    modification_time=None,
    case_identifier=None,
    reporting_vendor=None,
    reporting_product=None,
    environment=None,
    name=None,
    description=None,
    external_id=1,
    severity=None,
    rule_generator=None,
    tags=None,
    detected_time=time.time() - 10,
    security_events=[],
    domain_relations=[],
    domain_entities=[],
    additional_properties=None,
    additional_data=None,
)

test_relation = dict(
    identifier=1,
    creation_time=None,
    modification_time=None,
    case_identifier=None,
    alert_identifier=None,
    security_event_identifier=None,
    relation_type=None,
    event_id=None,
    from_identifier=None,
    to_identifier=None,
    device_product=None,
    device_vendor=None,
    event_class_id=None,
    severity=None,
    start_time=None,
    end_time=None,
    destination_port=None,
    category_outcome=None,
    additional_properties=None,
    to_type=None,
    from_type=None,
)

test_entity = dict(
    identifier=1,
    creation_time=None,
    modification_time=None,
    case_identifier=1,
    alert_identifier=1,
    entity_type="ALERT",
    is_internal=None,
    is_suspicious=None,
    is_artifact=None,
    is_enriched=None,
    is_vulnerable=None,
    is_pivot=None,
    additional_properties=None,
)

test_alert = Alert(
    identifier=1,
    alert_group_identifier=None,
    creation_time=time.time(),
    modification_time=None,
    case_identifier=None,
    reporting_vendor=None,
    reporting_product=None,
    environment=None,
    name=None,
    description=None,
    external_id=1,
    severity=None,
    rule_generator=None,
    tags=None,
    detected_time=time.time() - 10,
    security_events=[],
    domain_relations=[test_relation],
    domain_entities=[test_entity],
    additional_properties=None,
    additional_data=None,
)


class TestSiemplifyAction:
    def test_siemplify_action_init_mock_stdin_is_none(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        mocker.patch("sys.stdin.read", return_value=DATA.encode())

        # act
        siemplify_action = SiemplifyAction()
        mocker.patch.object(siemplify_action, "_load_current_alert")
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )

        # assert
        assert siemplify_action.log_location == "SDK_Actions"
        assert siemplify_action.is_timeout_reached
        assert siemplify_action.environment == "Default"
        assert siemplify_action.current_alert is None
        assert siemplify_action._current_alert is None
        assert siemplify_action.case
        assert siemplify_action._case
        assert siemplify_action.target_entities == []
        assert siemplify_action._target_entities == []

    def test_siemplify_action_init_mock_stdin_is_not_none(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.status_code = None
        siemplify_action = SiemplifyAction(mock_stdin=DATA)

        # act
        mocker.patch.object(siemplify_action, "_load_current_alert")
        mocker.patch.object(siemplify_action, "_load_target_entities")
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )

        # assert
        assert siemplify_action.log_location == "SDK_Actions"
        assert siemplify_action.is_timeout_reached
        assert siemplify_action.environment == "Default"
        assert siemplify_action.current_alert is None
        assert siemplify_action._current_alert is None
        assert isinstance(siemplify_action.case, CyberCaseLazy)
        assert isinstance(siemplify_action._case, CyberCaseLazy)
        assert siemplify_action.target_entities is None
        assert siemplify_action._target_entities is None

    def test_siemplify_action_init_old_entities(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.status_code = None
        test_data = json.loads(DATA.encode())
        test_data.update(
            {"target_entities": [{"item1": 1, "item2": 2}, {"item1": 1, "item2": 2}]},
        )
        test_data.update({"case_id": 0})
        test_data = json.dumps(test_data)

        # act
        siemplify_action = SiemplifyAction(test_data)
        mocker.patch.object(siemplify_action, "_load_current_alert")
        mocker.patch.object(siemplify_action, "_load_target_entities")
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )

        # assert
        assert not siemplify_action.support_old_entities
        assert siemplify_action.log_location == "SDK_Actions"
        assert siemplify_action.is_timeout_reached
        assert siemplify_action.environment == "Default"
        assert siemplify_action.current_alert is None
        assert siemplify_action._current_alert is None
        assert isinstance(siemplify_action.case, CyberCaseLazy)
        assert isinstance(siemplify_action._case, CyberCaseLazy)
        assert siemplify_action.target_entities is None
        assert siemplify_action._target_entities is None

    def test_init_proxy_settings(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.status_code = None
        test_data = json.loads(DATA.encode())
        test_data.update(
            {
                "use_proxy_settings": True,
            },
        )
        test_data = json.dumps(test_data)

        # act
        with patch.object(Siemplify, "init_proxy_settings", return_value=None):
            siemplify_action = SiemplifyAction(test_data)
            mocker.patch.object(siemplify_action, "_load_current_alert")
            mocker.patch.object(siemplify_action, "_load_target_entities")
            mocker.patch.object(
                siemplify_action,
                "_get_case_metadata_by_id",
                return_value=lazy_case_dict,
            )

        # assert
        assert siemplify_action.log_location == "SDK_Actions"
        assert siemplify_action.is_timeout_reached
        assert siemplify_action.environment == "Default"
        assert siemplify_action.current_alert is None
        assert siemplify_action._current_alert is None
        assert isinstance(siemplify_action.case, CyberCaseLazy)
        assert isinstance(siemplify_action._case, CyberCaseLazy)
        assert siemplify_action.target_entities is None
        assert siemplify_action._target_entities is None

    def test_siemplify_action_is_timeout_reached_raise_exception(self, mocker):
        # arrange
        mocker.patch("sys.stdin.read", return_value=DATA.encode())

        # act
        siemplify_action = SiemplifyAction()
        siemplify_action.execution_deadline_unix_time_ms = None
        with pytest.raises(Exception) as exception_info:
            siemplify_action.is_timeout_reached()

        # assert
        assert str(exception_info.value) == "execution_deadline_unix_time_ms is None"

    def test_init_remote_file_storage_session_response_success(self):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)

        # act
        response = siemplify_action._init_remote_file_storage_session()

        # assert
        assert response is None

    def test_get_case_if_is_remote_response_success(self):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.is_remote = True
        file = open("case_data.json", "w")
        file.write('{"first line": 1}')
        file.close()

        # act
        response = siemplify_action._get_case()
        os.remove("case_data.json")

        # assert
        assert response == {"first line": 1}

    def test_get_case_if_metadata_is_true_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        obj = mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=1,
        )

        # act
        response = siemplify_action._get_case(metadata_only=True)

        # assert
        obj.assert_called_once()
        assert response == 1

    def test_get_case_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        obj = mocker.patch.object(
            siemplify_action,
            "_get_case_by_id",
            return_value=test_cyber_case,
        )

        # act
        response = siemplify_action._get_case()

        # assert
        obj.assert_called_once()
        assert response == test_cyber_case

    def test_load_current_alert_response_success(self):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)

        # act
        response = siemplify_action._load_current_alert()

        # assert
        assert response is None

    def test_load_alert_if_alerts_already_loaded_raise_exception(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        obj = mocker.patch.object(
            siemplify_action,
            "_get_current_alert_by_id",
            return_value={"items": 1},
        )

        # act
        response = siemplify_action._load_alert()

        # assert
        assert response is None
        obj.assert_called_once()

    def test_load_current_alert_if_alerts_already_loaded_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action,
            "_has_alerts_already_loaded",
            return_value=True,
        )
        obj = mocker.patch.object(siemplify_action, "_find_alert_by_id")

        # act
        response = siemplify_action._load_current_alert()

        # assert
        assert not response
        obj.assert_called_once()

    def test_load_target_entities_response_success(self, mocker):
        # arrange
        test_data = json.loads(DATA.encode())
        test_data.update(
            {"target_entities": [{"item1": 1, "item2": 2}, {"item1": 1, "item2": 2}]},
        )
        test_data = json.dumps(test_data)
        siemplify_action = SiemplifyAction(mock_stdin=test_data)

        mock_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_property.return_value = test_alert

        # act
        response = siemplify_action._load_target_entities()

        # assert
        assert not response

    def test_load_target_entities_not_support_old_entities_response_success(
        self,
        mocker,
    ):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_property.return_value = test_alert

        # act
        response = siemplify_action._load_target_entities()

        # assert
        assert not response

    def test_find_alert_by_id_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "case",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_lazy_case
        mocker.patch.object(
            CaseAlertsProvider,
            "get_alerts",
            return_value=[test_dict_alert],
        )

        # act
        response = siemplify_action._find_alert_by_id()

        # assert
        assert isinstance(response, Alert)

    def test_case_is_remote_option_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.is_remote = True
        mocker.patch.object(siemplify_action, "_get_case", return_value=test_cyber_case)
        mocker.patch.object(siemplify_action, "_get_current_alert_by_id")
        mocker.patch.object(siemplify_action, "_load_current_alert")
        mocker.patch.object(siemplify_action, "_load_target_entities")

        # act
        response = siemplify_action.case

        # assert
        assert isinstance(response, CyberCase)

    def test_target_entities_is_remote_option_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.is_remote = True
        mocker.patch.object(siemplify_action, "_get_case", return_value=test_cyber_case)
        mocker.patch.object(siemplify_action, "_get_current_alert_by_id")
        mocker.patch.object(siemplify_action, "_load_current_alert")
        obj = mocker.patch.object(siemplify_action, "_load_target_entities")

        # act
        response = siemplify_action.target_entities

        # assert
        obj.assert_called_once()
        assert response is None

    def test_alerts_is_remote_option_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.is_remote = True
        mocker.patch.object(siemplify_action, "_get_case", return_value=test_cyber_case)
        mocker.patch.object(siemplify_action, "_get_current_alert_by_id")
        mocker.patch.object(siemplify_action, "_load_target_entities")
        obj = mocker.patch.object(siemplify_action, "_load_current_alert")

        # act
        response = siemplify_action.current_alert

        # assert
        obj.assert_called_once()
        assert response is None

    def test_load_case_data_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        obj = mocker.patch.object(
            siemplify_action,
            "_get_case_by_id",
            return_value=test_cyber_case,
        )

        # act
        response = siemplify_action.load_case_data()

        # assert
        obj.assert_called_once()
        assert not response

    def test_add_attachment_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = "TEST"
        mock_response.raise_for_status.return_value = None
        file = open("test.txt", "w")
        file.write("first line")
        file.close()

        # act
        attachment = Attachment.fromfile(
            "test.txt",
            case_id=1,
            alert_identifier=1,
            description=None,
            is_favorite=False,
        )
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        response = siemplify_action.add_attachment(
            "test.txt",
            case_id=0,
            alert_identifier=1,
        )

        # delete the created file
        os.remove("test.txt")

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/AddAttachment?format=snake",
            ),
            json=attachment.__dict__,
        )

        # assert
        assert response == "TEST"

    def test_get_attachments_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = "TEST"
        mock_response.raise_for_status.return_value = None
        case_id = 1

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(siemplify_action.session, "get", return_value=mock_response)
        response = siemplify_action.get_attachments(case_id=case_id)

        # assert the correct API address is called
        siemplify_action.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/Attachments",
                str(case_id),
                "?format=snake",
            ),
        )

        # assert
        assert response == "TEST"

    def test_assign_case_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = None
        case_id = 1
        alert_identifier = 1
        user = "@Administrator"
        request_dict = {
            "case_id": str(case_id),
            "alert_identifier": alert_identifier,
            "user_id": user,
        }

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        response = siemplify_action.assign_case(
            user=user,
            case_id=case_id,
            alert_identifier=alert_identifier,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}{2}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/AssignUser",
                "?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_add_comment_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = None
        case_id = 1
        alert_identifier = 1
        comment = "test"
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "comment": comment,
        }

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        response = siemplify_action.add_comment(
            comment=comment,
            case_id=case_id,
            alert_identifier=alert_identifier,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}{2}".format(
                siemplify_action.API_ROOT,
                "external/v1/cases/comments",
                "?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_add_tag_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = None
        case_id = 1
        alert_identifier = 1
        tag = "test"
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "tag": tag,
        }

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        response = siemplify_action.add_tag(
            tag=tag,
            case_id=case_id,
            alert_identifier=alert_identifier,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}{2}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/AddTag",
                "?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_attach_workflow_to_case_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.text = '{"TEST": 1}'
        mock_response.raise_for_status.return_value = """{"result" : "True"}"""
        cyber_case_id = "1"
        indicator_identifier = 1
        workflow_name = "test"
        request_dict = {
            "wf_name": workflow_name,
            "should_run_automatic": True,
            "cyber_case_id": str(cyber_case_id),
            "alert_identifier": indicator_identifier,
        }

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        response = siemplify_action.attach_workflow_to_case(
            workflow_name=workflow_name,
            cyber_case_id=cyber_case_id,
            indicator_identifier=indicator_identifier,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}{2}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/AttacheWorkflowToCase",
                "?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response == {"TEST": 1}

    def test_get_similar_cases_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = [25, 21, 26, 27, 23, 22, 20, 24]
        mock_response.raise_for_status.return_value = None
        mock_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_property.return_value = test_alert
        consider_ports = True
        consider_category_outcome = True
        consider_rule_generator = True
        consider_entity_identifiers = True
        days_to_look_back = "1"
        case_id = 1

        # set the mock response to be returned by the session.get method
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        mocker.patch.object(
            siemplify_action,
            "_get_current_alert_by_id",
            return_value=test_alert,
        )
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )

        # act
        # call the get_system_version method
        response = siemplify_action.get_similar_cases(
            consider_ports=consider_ports,
            consider_category_outcome=consider_category_outcome,
            consider_rule_generator=consider_rule_generator,
            consider_entity_identifiers=consider_entity_identifiers,
            days_to_look_back=days_to_look_back,
            case_id=case_id,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_once()

        # assert
        # assert the correct system version is returned
        assert response == [25, 21, 26, 27, 23, 22, 20, 24]

    def test_get_ticket_ids_for_alerts_dismissed_since_timestamp_valid_response_success(
        self,
        mocker,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = [1, 2, 4, 9]
        mock_response.raise_for_status.return_value = None
        timestamp_unix_ms = time.time()

        # set the mock response to be returned by the session.get method
        request_dict = {"time_stamp_unix_ms": str(timestamp_unix_ms)}
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.get_ticket_ids_for_alerts_dismissed_since_timestamp(
            timestamp_unix_ms,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/GetTicketIdsForAlertsDismissedSinceTimestamp?format"
                "=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response == [1, 2, 4, 9]

    def test_get_alerts_ticket_ids_from_cases_closed_since_timestamp_response_success(
        self,
        mocker,
    ):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = [1, 2, 4, 9]
        mock_response.raise_for_status.return_value = None
        timestamp_unix_ms = time.time()
        rule_generator = "Phishing email detector"
        request_dict = {
            "time_stamp_unix_ms": str(timestamp_unix_ms),
            "rule_generator": rule_generator,
            "include_dismissed_alerts": False,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = (
            siemplify_action.get_alerts_ticket_ids_from_cases_closed_since_timestamp(
                timestamp_unix_ms,
                rule_generator,
            )
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/GetAlertsTicketIdsFromCasesClosedSinceTimestamp"
                "?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response == [1, 2, 4, 9]

    def test_change_case_stage_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        stage = "Incident"
        case_id = 1
        alert_identifier = 1
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.change_case_stage(stage, case_id, alert_identifier)

        # assert the correct API address is called
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "stage": stage,
        }
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/ChangeCaseStage?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_change_case_priority_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        priority = 40
        case_id = 1
        alert_identifier = 1
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.change_case_priority(
            priority,
            case_id,
            alert_identifier,
        )

        # assert the correct API address is called
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "priority": priority,
        }
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/ChangePriority?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_close_case_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        root_cause = "test"
        comment = "test"
        reason = "test"
        case_id = 1
        alert_identifier = 1

        # set the mock response to be returned by the session.get method
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.close_case(
            root_cause,
            comment,
            reason,
            case_id,
            alert_identifier,
        )

        # assert the correct API address is called
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "root_cause": root_cause,
            "comment": comment,
            "reason": reason,
        }
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/Close?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_dismiss_alert_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        alert_group_identifier = ("test",)
        should_close_case_if_all_alerts_were_dismissed = False
        case_id = 1

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": str(case_id),
            "alert_group_identifier": alert_group_identifier,
            "should_close_case_if_all_alerts_were_dismissed": should_close_case_if_all_alerts_were_dismissed,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.dismiss_alert(
            alert_group_identifier,
            should_close_case_if_all_alerts_were_dismissed,
            case_id,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/DismissAlert?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_close_alert_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        root_cause = "test"
        comment = "test"
        reason = "test"
        case_id = 1
        alert_id = 1

        # set the mock response to be returned by the session.get method
        request_dict = {
            "source_case_id": str(case_id),
            "alert_identifier": alert_id,
            "root_cause": root_cause,
            "reason": reason,
            "comment": comment,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.close_alert(
            root_cause,
            comment,
            reason,
            case_id,
            alert_id,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/CloseAlert?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response == {}

    def test_add_entity_insight_threat_source_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = True
        mock_response.raise_for_status.return_value = None
        message = "test"
        entity = DomainEntityInfo(
            test_entities.get("Identifier"),
            test_entities.get("CreationTime"),
            test_entities.get("ModificationTime"),
            test_entities.get("CaseIdentifier"),
            test_entities.get("AlertIdentifier"),
            test_entities.get("EntityType"),
            test_entities.get("IsInternal"),
            test_entities.get("IsSuspicious"),
            test_entities.get("IsArtifact"),
            test_entities.get("IsEnriched"),
            test_entities.get("IsVulnerable"),
            test_entities.get("IsPivot"),
            test_entities.get("AdditionalProperties"),
        )
        entity._update_internal_properties()
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        request_dict = dict(
            case_id=1,
            alert_identifier=None,
            triggered_by="AutomationEntityValue_qs",
            title="Entity insight",
            content="test",
            entity_identifier="LAB@SIEMPLIFY.LOCAL",
            severity=1,
            type=1,
            entity_type="HOSTNAME",
            additional_data=None,
            additional_data_type=None,
            additional_data_title=None,
            original_requesting_user=None,
        )

        response = siemplify_action.add_entity_insight(entity, message)

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/CreateCaseInsight?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response

    def test_add_entity_insight_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = True
        mock_response.raise_for_status.return_value = None
        message = "test"
        entity = DomainEntityInfo(
            test_entities.get("Identifier"),
            test_entities.get("CreationTime"),
            test_entities.get("ModificationTime"),
            test_entities.get("CaseIdentifier"),
            test_entities.get("AlertIdentifier"),
            test_entities.get("EntityType"),
            test_entities.get("IsInternal"),
            test_entities.get("IsSuspicious"),
            test_entities.get("IsArtifact"),
            test_entities.get("IsEnriched"),
            test_entities.get("IsVulnerable"),
            test_entities.get("IsPivot"),
            {"IsInternalAsset": None},
        )
        entity._update_internal_properties()
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        request_dict = dict(
            case_id=1,
            alert_identifier=None,
            triggered_by=1,
            title="Entity insight",
            content="test",
            entity_identifier="LAB@SIEMPLIFY.LOCAL",
            severity=1,
            type=1,
            entity_type="HOSTNAME",
            additional_data=None,
            additional_data_type=None,
            additional_data_title=None,
            original_requesting_user=None,
        )

        response = siemplify_action.add_entity_insight(entity, message)

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/CreateCaseInsight?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response

    def test_add_entity_insight_integration_identifier_is_none_valid_response_success(
        self,
        mocker,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = True
        mock_response.raise_for_status.return_value = None
        message = "test"
        entity = DomainEntityInfo(
            test_entities.get("Identifier"),
            test_entities.get("CreationTime"),
            test_entities.get("ModificationTime"),
            test_entities.get("CaseIdentifier"),
            test_entities.get("AlertIdentifier"),
            test_entities.get("EntityType"),
            test_entities.get("IsInternal"),
            test_entities.get("IsSuspicious"),
            test_entities.get("IsArtifact"),
            test_entities.get("IsEnriched"),
            test_entities.get("IsVulnerable"),
            test_entities.get("IsPivot"),
            {"IsInternalAsset": None},
        )
        entity._update_internal_properties()
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.integration_identifier = None
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        request_dict = dict(
            case_id=1,
            alert_identifier=None,
            triggered_by="Siemplify System",
            title="Entity insight",
            content="test",
            entity_identifier="LAB@SIEMPLIFY.LOCAL",
            severity=1,
            type=1,
            entity_type="HOSTNAME",
            additional_data=None,
            additional_data_type=None,
            additional_data_title=None,
            original_requesting_user=None,
        )

        response = siemplify_action.add_entity_insight(entity, message)

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/CreateCaseInsight?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response

    def test_create_case_insight_internal_valid_response_success(self, mocker):
        # arrange
        case_id = 1
        alert_identifier = 1
        triggered_by = "test"
        title = "test"
        content = "test"
        entity_identifier = ("test",)
        severity = 1
        insight_type = 0
        additional_data = "test"
        additional_data_type = ("string",)
        additional_data_title = "test"
        mock_response = mocker.Mock()
        mock_response.json.return_value = True
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "triggered_by": triggered_by,
            "title": title,
            "content": content,
            "entity_identifier": entity_identifier,
            "severity": severity,
            "type": insight_type,
            "entity_type": None,
            "additional_data": additional_data,
            "additional_data_type": additional_data_type,
            "additional_data_title": additional_data_title,
            "original_requesting_user": None,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.create_case_insight(
            triggered_by,
            title,
            content,
            entity_identifier,
            severity,
            insight_type,
            additional_data,
            additional_data_type,
            additional_data_title,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/CreateCaseInsight?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response

    def test_escalate_vase_valid_response_success(self, mocker):
        # arrange
        comment = "test"
        case_id = 1
        alert_identifier = 1
        mock_response = mocker.Mock()
        mock_response.text = "{}"
        mock_response.raise_for_status.return_value = """{"result" : "True"}"""
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "comment": comment,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.escalate_case(comment, case_id, alert_identifier)

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/Escalate?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response == {}

    def test_mark_case_as_important_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        case_id = 1
        alert_identifier = 1
        request_dict = {"case_id": case_id, "alert_identifier": alert_identifier}
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.mark_case_as_important(case_id, alert_identifier)

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/MarkAsImportant?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert not response

    def test_get_case_context_property_response_success(self, mocker):
        # arrange
        property_key = 1
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "case",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_lazy_case
        obj = mocker.patch.object(
            SiemplifyBase,
            "get_context_property",
            return_value="TEST",
        )
        # act
        response = siemplify_action.get_case_context_property(property_key=property_key)

        # assert
        obj.assert_called_once()
        assert response == "TEST"

    def test_set_case_context_property_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "case",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_lazy_case
        obj = mocker.patch.object(
            SiemplifyBase,
            "set_context_property",
            return_value="TEST",
        )
        # act
        response = siemplify_action.set_case_context_property(
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once()
        assert response == "TEST"

    def test_try_set_case_context_property_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "case",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_lazy_case
        obj = mocker.patch.object(
            SiemplifyBase,
            "try_set_context_property",
            return_value="TEST",
        )
        # act
        response = siemplify_action.try_set_case_context_property(
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once()
        assert response == "TEST"

    def test_set_alert_context_property_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_alert
        obj = mocker.patch.object(
            SiemplifyBase,
            "set_context_property",
            return_value="TEST",
        )
        # act
        response = siemplify_action.set_alert_context_property(
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once()
        assert response == "TEST"

    def test_get_alert_context_property_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_alert
        obj = mocker.patch.object(
            SiemplifyBase,
            "get_context_property",
            return_value="TEST",
        )
        # act
        response = siemplify_action.get_alert_context_property(property_key=1)

        # assert
        obj.assert_called_once()
        assert response == "TEST"

    def test_try_set_alert_context_property_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_alert
        obj = mocker.patch.object(
            SiemplifyBase,
            "try_set_context_property",
            return_value="TEST",
        )
        # act
        response = siemplify_action.try_set_alert_context_property(
            property_key=1,
            property_value=1,
        )

        # assert
        obj.assert_called_once()
        assert response == "TEST"

    def test_fetch_and_save_timestamp_response_success(self, mocker):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_case_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_case_property.return_value = test_alert
        fetch_timestamp = mocker.patch.object(
            SiemplifyBase,
            "fetch_timestamp",
            return_value="TEST",
        )
        save_timestamp = mocker.patch.object(
            SiemplifyBase,
            "save_timestamp",
            return_value="TEST",
        )
        # act
        response = siemplify_action.fetch_and_save_timestamp()

        # assert
        fetch_timestamp.assert_called_once()
        save_timestamp.assert_called_once()
        assert response == "TEST"

    def test_raise_incident_valid_response_success(self, mocker):
        # arrange
        case_id = 1
        alert_identifier = 1
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {"case_id": case_id, "alert_identifier": alert_identifier}
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.raise_incident(case_id, alert_identifier)

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/RaiseIncident?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_add_entity_to_case_invalid_response_raise_exception(self, mocker):
        # arrange
        case_id = "1"
        alert_identifier = None
        entity_identifier = "google.com"
        entity_type = "ADDRESS"
        is_internal = True
        is_suspicous = True
        is_enriched = True
        is_vulnerable = True
        properties = {"a": "a"}
        environment = "Default"
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        request_dict = {
            "alert_id_str": 1,
            "case_id": 1,
            "populate_original_file": False,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        with pytest.raises(Exception) as exception_info:
            siemplify_action.add_entity_to_case(
                case_id,
                alert_identifier,
                entity_identifier,
                entity_type,
                is_internal,
                is_suspicous,
                is_enriched,
                is_vulnerable,
                properties,
                environment,
            )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/AlertFullDetails?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert "Cannot Create" in str(exception_info)

    def test_add_entity_to_case_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = None
        mock_property = mocker.patch.object(
            SiemplifyAction,
            "current_alert",
            new_callable=PropertyMock,
        )
        mock_property.return_value = test_alert

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": 1,
            "alert_identifier": 1,
            "entity_identifier": "google.com",
            "entity_type": "ADDRESS",
            "is_internal": True,
            "is_suspicious": True,
            "is_enriched": True,
            "is_vulnerable": False,
            "properties": None,
            "environment": "Default",
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )

        # act
        response = siemplify_action.add_entity_to_case(
            entity_identifier="google.com",
            entity_type="ADDRESS",
            is_internal=True,
            is_suspicous=True,
            is_enriched=True,
            is_vulnerable=False,
            properties=None,
            case_id=None,
            alert_identifier=1,
            environment=None,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/CreateEntity?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_get_case_comments_valid_response_success(self, mocker):
        # arrange
        case_id = "1"
        mock_response = mocker.Mock()
        temp = str(
            json.dumps(
                [
                    {
                        "comment": "test",
                        "is_deleted": False,
                        "last_editor_full_name": "oriann barzely",
                        "modification_time_unix_time_in_ms_for_client": 0,
                        "creation_time_unix_time_in_ms": 1681827156279,
                        "id": 8,
                        "modification_time_unix_time_in_ms": 1681827156279,
                        "case_id": 4,
                        "is_favorite": False,
                        "alert_identifier": None,
                        "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                        "last_editor": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                        "type": 5,
                        "comment_for_client": None,
                        "creator_full_name": "oriann barzely",
                    },
                    {
                        "comment": "test",
                        "is_deleted": False,
                        "last_editor_full_name": "oriann barzely",
                        "modification_time_unix_time_in_ms_for_client": 0,
                        "creation_time_unix_time_in_ms": 1681827157057,
                        "id": 9,
                        "modification_time_unix_time_in_ms": 1681827157057,
                        "case_id": 4,
                        "is_favorite": False,
                        "alert_identifier": None,
                        "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                        "last_editor": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                        "type": 5,
                        "comment_for_client": None,
                        "creator_full_name": "oriann barzely",
                    },
                    {
                        "comment": "etest",
                        "is_deleted": False,
                        "last_editor_full_name": "oriann barzely",
                        "modification_time_unix_time_in_ms_for_client": 0,
                        "creation_time_unix_time_in_ms": 1681827157850,
                        "id": 10,
                        "modification_time_unix_time_in_ms": 1681827157850,
                        "case_id": 4,
                        "is_favorite": False,
                        "alert_identifier": None,
                        "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                        "last_editor": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                        "type": 5,
                        "comment_for_client": None,
                        "creator_full_name": "oriann barzely",
                    },
                ],
            ),
        )
        mock_response.text = temp
        mock_response.raise_for_status.return_value = None
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(siemplify_action.session, "get", return_value=mock_response)

        # act
        response = siemplify_action.get_case_comments(case_id)

        # assert the correct API address is called
        siemplify_action.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/GetCaseComments",
                case_id,
                "?format=snake",
            ),
        )

        # assert
        assert response == [
            {
                "comment": "test",
                "is_deleted": False,
                "last_editor_full_name": "oriann barzely",
                "modification_time_unix_time_in_ms_for_client": 0,
                "creation_time_unix_time_in_ms": 1681827156279,
                "id": 8,
                "modification_time_unix_time_in_ms": 1681827156279,
                "case_id": 4,
                "is_favorite": False,
                "alert_identifier": None,
                "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "last_editor": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "type": 5,
                "comment_for_client": None,
                "creator_full_name": "oriann barzely",
            },
            {
                "comment": "test",
                "is_deleted": False,
                "last_editor_full_name": "oriann barzely",
                "modification_time_unix_time_in_ms_for_client": 0,
                "creation_time_unix_time_in_ms": 1681827157057,
                "id": 9,
                "modification_time_unix_time_in_ms": 1681827157057,
                "case_id": 4,
                "is_favorite": False,
                "alert_identifier": None,
                "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "last_editor": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "type": 5,
                "comment_for_client": None,
                "creator_full_name": "oriann barzely",
            },
            {
                "comment": "etest",
                "is_deleted": False,
                "last_editor_full_name": "oriann barzely",
                "modification_time_unix_time_in_ms_for_client": 0,
                "creation_time_unix_time_in_ms": 1681827157850,
                "id": 10,
                "modification_time_unix_time_in_ms": 1681827157850,
                "case_id": 4,
                "is_favorite": False,
                "alert_identifier": None,
                "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "last_editor": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "type": 5,
                "comment_for_client": None,
                "creator_full_name": "oriann barzely",
            },
        ]

    def test_update_alerts_additional_data_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        case_id = 1
        alerts_additional_data = 1
        request_dict = {
            "case_id": case_id,
            "alerts_additional_data": alerts_additional_data,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.update_alerts_additional_data(
            case_id,
            alerts_additional_data,
        )

        # assert the correct API address is called
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/UpdateAlertsAdditional?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response is None

    def test_build_output_object_response_success(self):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.result.support_old_entities = False

        # act
        response = siemplify_action._build_output_object()

        # assert
        assert type(response) == dict

    def test_build_output_object_support_old_entities_response_success(self):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)

        # act
        response = siemplify_action._build_output_object()

        # assert
        assert type(response) == dict

    def test_build_output_object_invalid_json_size_response_fails(self):
        # arrange
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.max_json_result_size = -1

        # act
        response = siemplify_action._build_output_object()

        # assert
        assert (
            "Action failed as JSON result exceeded maximum size" in response["Message"]
        )

    def test_any_entity_in_custom_list_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.text = "True"
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        response = siemplify_action.any_alert_entities_in_custom_list(
            category_name="test",
        )

        # assert
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/AnyEntityInCustomList?format=snake",
            ),
            json=[],
        )
        assert response

    def test_add_entities_to_custom_list_response_success(self, mocker):
        # arrange
        request_dict = {"identifier": "test", "category": "test", "environment": "test"}
        mock_response = mocker.Mock()
        mock_response.json.return_value = [request_dict]
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )
        response = siemplify_action.add_alert_entities_to_custom_list(
            category_name="test",
        )

        # assert
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/AddEntitiesToCustomList?format=snake",
            ),
            json=[],
        )
        assert isinstance(response[0], CustomList)

    def test_remove_entities_from_custom_list_response_success(self, mocker):
        # arrange
        request_dict = {"identifier": "test", "category": "test", "environment": "test"}
        mock_response = mocker.Mock()
        mock_response.json.return_value = [request_dict]
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        response = siemplify_action.remove_alert_entities_from_custom_list(
            category_name="test",
        )

        # assert
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/RemoveEntitiesFromCustomList?format=snake",
            ),
            json=[],
        )
        assert isinstance(response[0], CustomList)

    def test_extract_action_param(
        self,
        mocker,
    ):
        # arrange
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        obj = mocker.patch("SiemplifyAction.extract_script_param")
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )
        siemplify_action.extract_action_param(param_name="test")

        # assert
        obj.assert_called_once()

    def test_get_configuration_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }
        mock_response.raise_for_status.return_value = None
        provider = 1
        integration_instance = ""
        identifier = integration_instance if integration_instance else provider
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )
        mocker.patch.object(siemplify_action.session, "get", return_value=mock_response)

        # act
        response = siemplify_action.get_configuration(provider)

        # assert the correct API address is called
        siemplify_action.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/configuration",
                identifier,
                "?format=snake",
            ),
        )

        # assert
        assert response == {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }

    def test_get_configuration_by_provider_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }
        mock_response.raise_for_status.return_value = None
        provider = "Siemplify"
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )
        mocker.patch.object(siemplify_action.session, "get", return_value=mock_response)

        # act
        response = siemplify_action.get_configuration_by_provider(provider)

        # assert the correct API address is called
        siemplify_action.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/configuration",
                provider,
                "?format=snake",
            ),
        )

        # assert
        assert response == {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }

    def test_get_configuration_by_provider_is_remote_valid_response_success(
        self,
        mocker,
    ):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }
        mock_response.raise_for_status.return_value = None
        provider = 1
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        siemplify_action.is_remote = True
        siemplify_action.integration_instance = "integration_instance"
        mocker.patch.object(siemplify_action, "_get_case", return_value=test_cyber_case)
        mocker.patch.object(siemplify_action, "_get_current_alert_by_id")
        mocker.patch.object(siemplify_action, "_load_current_alert")
        mocker.patch.object(siemplify_action, "_load_target_entities")
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )
        mocker.patch.object(siemplify_action.session, "get", return_value=mock_response)

        # act
        response = siemplify_action.get_configuration_by_provider(provider)

        # assert the correct API address is called
        siemplify_action.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/configuration",
                siemplify_action.integration_instance,
                "?format=snake",
            ),
        )

        # assert
        assert response == {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }

    def test_get_custom_list_items_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch.object(
            siemplify_action,
            "_get_case_metadata_by_id",
            return_value=lazy_case_dict,
        )
        response = siemplify_action._get_custom_list_items("test", [test_alert])

        # assert
        assert isinstance(response[0], CustomList)

    def test_termination_signal_handler(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mocker.patch("sys.exit")
        obj = mocker.patch.object(siemplify_action, "remove_temp_folder")
        siemplify_action.termination_signal_handler(signal.SIGTERM, None)

        # assert
        obj.assert_called_once()

    def test_set_case_sla_response_success(self, mocker):
        # arrange
        period_time = 1
        period_type = "Minutes"
        critical_period_time = 1
        critical_period_type = "Minutes"
        case_id = 1
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.set_case_sla(
            period_time,
            period_type,
            critical_period_time,
            critical_period_type,
            case_id,
        )

        # assert
        assert response is None
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}?format=snake".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "sla",
            ),
            json=request,
        )

    def test_set_alert_sla_response_success(self, mocker):
        # arrange
        period_time = 1
        period_type = "Minutes"
        critical_period_time = 1
        critical_period_type = "Minutes"
        case_id = 1
        alert_identifier = "1"
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify_action = SiemplifyAction(mock_stdin=DATA)
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200
        mocker.patch.object(
            siemplify_action.session,
            "post",
            return_value=mock_response,
        )

        # act
        response = siemplify_action.set_alert_sla(
            period_time,
            period_type,
            critical_period_time,
            critical_period_type,
            case_id,
            alert_identifier,
        )

        # assert
        assert response is None
        siemplify_action.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}/{4}/{5}?format=snake".format(
                siemplify_action.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "alerts",
                alert_identifier,
                "sla",
            ),
            json=request,
        )
