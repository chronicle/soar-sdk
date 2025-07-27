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
import sys
import tempfile
import time
import uuid
from datetime import timedelta
from typing import TYPE_CHECKING
from unittest.mock import mock_open, patch

import pytest
import requests

from soar_sdk import SiemplifyUtils
from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED, ScriptResult
from soar_sdk.Siemplify import Siemplify
from soar_sdk.SiemplifyDataModel import (
    ApiSyncAlertCloseReasonEnum,
    ApiSyncAlertPriorityEnum,
    ApiSyncAlertStatusEnum,
    ApiSyncAlertUsefulnessEnum,
    ApiSyncCasePriorityEnum,
    ApiSyncCaseStatusEnum,
    Attachment,
    CaseFilterSortByEnum,
    CaseFilterSortOrderEnum,
    CaseFilterStatusEnum,
    CasesFilter,
    CustomList,
    DomainEntityInfo,
    InsightSeverity,
    InsightType,
    SyncCaseIdMatch,
    Task,
)
from soar_sdk.SiemplifyUtils import convert_datetime_to_unix_time, unix_now, utc_now

if TYPE_CHECKING:
    import unittest.mock

# Consts
EXTERNAL_CONFIG_PROVIDER_FILE = r"external_providers.json"
INSIGHT_DEFAULT_THREAT_SOURCE = "Siemplify System"
HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
REQUEST_CA_BUNDLE = "REQUESTS_CA_BUNDLE"
JSON_RESULT_KEY = "JsonResult"
CASE_FILTER_MAX_RESULTS = 10000
SYSTEM_NOTIFICATION_CUSTOM_MESSAGE_ID = "SDK_CUSTOM_NOTIFICATION"
SYSTEM_NOTIFICATION_MESSAGE_CHAR_LIMIT = 500
SYSTEM_NOTIFICATION_MESSAGE_ID_CHAR_LIMIT = 50
CASE_METADATA = "external/v1/sdk/CaseMetadata"
ALERT_FULL_DETAILS = "external/v1/sdk/AlertFullDetails"
FORMAT_SNAKE = "?format=snake"


class TestSiemplify:
    def test_fix_parameters(self) -> None:
        # arrange
        parameters = {"test": ""}
        siemplify = Siemplify()
        # act
        response = siemplify._fix_parameters(parameters)
        # assert
        assert response == parameters

    def test_get_err_message(
        self,
        exception: Exception = Exception("Test exception"),
    ) -> None:
        # arrange
        siemplify = Siemplify()
        # act
        response = siemplify._get_err_message(exception)
        # assert
        assert response == "Test exception"

    def test_get_case_by_id_when_source_is_false(
        self,
        mocker: unittest.mock.Mock,
        case_id: int = 1,
    ) -> None:
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.status_code = None
        mock_response.json.return_value = {}

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        response = siemplify._get_case_by_id(case_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_once_with(
            "{0}/{1}/{2}/{3}{4}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CaseFullDetails",
                case_id,
                False,
                "?format=snake",
            ),
        )
        # assert
        assert response == {}

    def test_get_case_by_id_when_source_is_true(
        self,
        mocker: unittest.mock.Mock,
        case_id: int = 1,
        get_source_file: bool = True,
    ) -> None:
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.status_code = None
        mock_response.json.return_value = {}

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        response = siemplify._get_case_by_id(case_id, get_source_file=get_source_file)

        # assert the correct API address is called
        siemplify.session.get.assert_called_once_with(
            "{0}/{1}/{2}/{3}{4}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CaseFullDetails",
                case_id,
                get_source_file,
                "?format=snake",
            ),
        )
        # assert
        assert response == {}

    def test_get_case_metadata_by_id(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        case_id = 1
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.status_code = None
        mock_response.json.return_value = {}

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        response = siemplify._get_case_metadata_by_id(case_id=case_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_once_with(
            f"{siemplify.API_ROOT}/{CASE_METADATA}/{case_id}{FORMAT_SNAKE}",
        )

        # assert
        assert response == {}

    def test_get_current_alert_by_id(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        case_id = 1
        alert_id = 1
        get_source_file = True
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.status_code = None
        mock_response.json.return_value = [25]

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": case_id,
            "alert_id_str": alert_id,
            "populate_original_file": get_source_file,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        response = siemplify._get_current_alert_by_id(
            case_id=case_id,
            alert_id=alert_id,
            get_source_file=get_source_file,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_once_with(
            f"{siemplify.API_ROOT}/{ALERT_FULL_DETAILS}{FORMAT_SNAKE}",
            json=request_dict,
        )

        # assert
        assert response == [25]

    def test_get_proxy_settings(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.status_code = None
        mock_response.json.return_value = {}

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        response = siemplify._get_proxy_settings()

        # assert the correct API address is called
        siemplify.session.get.assert_called_once_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetProxySettings?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {}

    def test_init_proxy_settings(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "proxy_server_address": {"proxy_server_address": True},
        }
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)
        mocker.patch("soar_sdk.SiemplifyUtils.set_proxy_state")

        # act
        response = siemplify.init_proxy_settings()

        # assert
        assert not response

    def test_update_entities_valid_response_success(
        self,
        mocker,
    ):
        # arrange
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
            },
        }
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # Create entity
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

        test_entity._update_internal_properties()
        entity_data = []
        entity_data.append(test_entity.to_dict())

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.update_entities([test_entity])

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/UpdateEntities?format=snake",
            ),
            json=entity_data,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_update_entities_invalid_response_raise_exception(
        self,
        mocker,
    ):
        # arrange
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
            },
        }
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # Create entity
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
        test_entity._update_internal_properties()
        entity_data = []
        entity_data.append(test_entity.to_dict())

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.update_entities([test_entity])

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_cases_ids_by_filter_valid_request_with_env_and_without_tags_should_pass(
        self,
        mocker,
    ):
        # Arrang
        status = "OPEN"
        start_time_from_unix_time_in_ms = None
        start_time_to_unix_time_in_ms = None
        close_time_from_unix_time_in_ms = None
        close_time_to_unix_time_in_ms = None
        update_time_from_unix_time_in_ms = None
        update_time_to_unix_time_in_ms = None
        operator = None
        sort_by = CaseFilterSortByEnum.START_TIME
        sort_order = CaseFilterSortOrderEnum.DESC
        max_results = 1000
        environments = None
        # create a mock response object
        if environments is None:
            environments = ["Env A"]

        if start_time_to_unix_time_in_ms is None:
            start_time_to_unix_time_in_ms = unix_now()

        if start_time_from_unix_time_in_ms is None:
            start_time_from_unix_time_in_ms = convert_datetime_to_unix_time(
                utc_now() - timedelta(days=30),
            )  # 30 days backwards

        mock_response = mocker.Mock()
        mock_response.json.return_value = [9, 15, 14, 13, 12, 11, 10, 6, 5, 4, 3, 8, 1]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        payload = {
            "start_time_from_unix_time_in_ms": start_time_from_unix_time_in_ms,
            "start_time_to_unix_time_in_ms": start_time_to_unix_time_in_ms,
            "close_time_from_unix_time_in_ms": close_time_from_unix_time_in_ms,
            "close_time_to_unix_time_in_ms": close_time_to_unix_time_in_ms,
            "update_time_from_unix_time_in_ms": update_time_from_unix_time_in_ms,
            "update_time_to_unix_time_in_ms": update_time_to_unix_time_in_ms,
            "status": status,
            "operator": operator,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "max_results": max_results,
            "environments": environments,
            "tags": None,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # Act
        siemplify.get_cases_ids_by_filter(
            status,
            start_time_from_unix_time_in_ms,
            start_time_to_unix_time_in_ms,
            close_time_from_unix_time_in_ms,
            close_time_to_unix_time_in_ms,
            update_time_from_unix_time_in_ms,
            update_time_to_unix_time_in_ms,
            operator,
            sort_by,
            sort_order,
            max_results,
            environments=environments,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCasesIdByFilter",
            ),
            json=payload,
        )

    def test_get_cases_ids_by_filter_valid_request_with_tags_and_without_envs_should_pass(
        self,
        mocker,
    ):
        # Arrange
        status = "OPEN"
        start_time_from_unix_time_in_ms = None
        start_time_to_unix_time_in_ms = None
        close_time_from_unix_time_in_ms = None
        close_time_to_unix_time_in_ms = None
        update_time_from_unix_time_in_ms = None
        update_time_to_unix_time_in_ms = None
        operator = None
        sort_by = CaseFilterSortByEnum.START_TIME
        sort_order = CaseFilterSortOrderEnum.DESC
        max_results = 1000
        tags = None
        # create a mock response object
        if tags is None:
            tags = ["Tag A"]

        if start_time_to_unix_time_in_ms is None:
            start_time_to_unix_time_in_ms = unix_now()

        if start_time_from_unix_time_in_ms is None:
            start_time_from_unix_time_in_ms = convert_datetime_to_unix_time(
                utc_now() - timedelta(days=30),
            )  # 30 days backwards

        mock_response = mocker.Mock()
        mock_response.json.return_value = [9, 15, 14, 13, 12, 11, 10, 6, 5, 4, 3, 8, 1]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        payload = {
            "start_time_from_unix_time_in_ms": start_time_from_unix_time_in_ms,
            "start_time_to_unix_time_in_ms": start_time_to_unix_time_in_ms,
            "close_time_from_unix_time_in_ms": close_time_from_unix_time_in_ms,
            "close_time_to_unix_time_in_ms": close_time_to_unix_time_in_ms,
            "update_time_from_unix_time_in_ms": update_time_from_unix_time_in_ms,
            "update_time_to_unix_time_in_ms": update_time_to_unix_time_in_ms,
            "status": status,
            "operator": operator,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "max_results": max_results,
            "environments": None,
            "tags": tags,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # Act
        siemplify.get_cases_ids_by_filter(
            status,
            start_time_from_unix_time_in_ms,
            start_time_to_unix_time_in_ms,
            close_time_from_unix_time_in_ms,
            close_time_to_unix_time_in_ms,
            update_time_from_unix_time_in_ms,
            update_time_to_unix_time_in_ms,
            operator,
            sort_by,
            sort_order,
            max_results,
            tags=tags,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCasesIdByFilter",
            ),
            json=payload,
        )

    def test_get_cases_ids_by_filter_invalid_response_raise_exception(self, mocker):
        # arrange

        status = "OPEN"
        start_time_from_unix_time_in_ms = None
        start_time_to_unix_time_in_ms = None
        close_time_from_unix_time_in_ms = None
        close_time_to_unix_time_in_ms = None
        update_time_from_unix_time_in_ms = None
        update_time_to_unix_time_in_ms = None
        operator = None
        sort_by = CaseFilterSortByEnum.START_TIME
        sort_order = CaseFilterSortOrderEnum.DESC
        max_results = 1000
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        payload = {
            "start_time_from_unix_time_in_ms": start_time_from_unix_time_in_ms,
            "start_time_to_unix_time_in_ms": start_time_to_unix_time_in_ms,
            "close_time_from_unix_time_in_ms": close_time_from_unix_time_in_ms,
            "close_time_to_unix_time_in_ms": close_time_to_unix_time_in_ms,
            "update_time_from_unix_time_in_ms": update_time_from_unix_time_in_ms,
            "update_time_to_unix_time_in_ms": update_time_to_unix_time_in_ms,
            "status": status,
            "operator": operator,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "max_results": max_results,
        }
        siemplify = Siemplify()
        mocker.patch.object(
            siemplify.session,
            "post",
            return_value=mock_response,
            json=payload,
        )

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status,
                start_time_from_unix_time_in_ms,
                start_time_to_unix_time_in_ms,
                close_time_from_unix_time_in_ms,
                close_time_to_unix_time_in_ms,
                update_time_from_unix_time_in_ms,
                update_time_to_unix_time_in_ms,
                operator,
                sort_by,
                sort_order,
                max_results,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_cases_ids_by_filter_valid_response_success(self, mocker):
        # arrange

        status = "OPEN"
        start_time_from_unix_time_in_ms = time.time()
        start_time_to_unix_time_in_ms = time.time()
        close_time_from_unix_time_in_ms = None
        close_time_to_unix_time_in_ms = None
        update_time_from_unix_time_in_ms = None
        update_time_to_unix_time_in_ms = None
        operator = None
        sort_by = CaseFilterSortByEnum.START_TIME
        sort_order = CaseFilterSortOrderEnum.DESC
        max_results = 1000
        environments = None
        tags = None
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = [9, 15, 14, 13, 12, 11, 10, 6, 5, 4, 3, 8, 1]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        payload = {
            "start_time_from_unix_time_in_ms": start_time_from_unix_time_in_ms,
            "start_time_to_unix_time_in_ms": start_time_to_unix_time_in_ms,
            "close_time_from_unix_time_in_ms": close_time_from_unix_time_in_ms,
            "close_time_to_unix_time_in_ms": close_time_to_unix_time_in_ms,
            "update_time_from_unix_time_in_ms": update_time_from_unix_time_in_ms,
            "update_time_to_unix_time_in_ms": update_time_to_unix_time_in_ms,
            "status": status,
            "operator": operator,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "max_results": max_results,
            "environments": environments,
            "tags": tags,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_cases_ids_by_filter(
            status,
            start_time_from_unix_time_in_ms,
            start_time_to_unix_time_in_ms,
            close_time_from_unix_time_in_ms,
            close_time_to_unix_time_in_ms,
            update_time_from_unix_time_in_ms,
            update_time_to_unix_time_in_ms,
            operator,
            sort_by,
            sort_order,
            max_results,
            environments,
            tags,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCasesIdByFilter",
            ),
            json=payload,
        )

        # assert
        # assert the correct system version is returned
        assert response == [9, 15, 14, 13, 12, 11, 10, 6, 5, 4, 3, 8, 1]

    def test_get_cases_ids_by_filter_invalid_response_exception_raised(self, mocker):
        # arrange

        status = "OPEN"
        start_time_from_unix_time_in_ms = None
        start_time_to_unix_time_in_ms = None
        close_time_from_unix_time_in_ms = None
        close_time_to_unix_time_in_ms = None
        update_time_from_unix_time_in_ms = None
        update_time_to_unix_time_in_ms = None
        operator = None
        sort_by = CaseFilterSortByEnum.START_TIME
        sort_order = None
        max_results = 10001
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        payload = {
            "start_time_from_unix_time_in_ms": start_time_from_unix_time_in_ms,
            "start_time_to_unix_time_in_ms": start_time_to_unix_time_in_ms,
            "close_time_from_unix_time_in_ms": close_time_from_unix_time_in_ms,
            "close_time_to_unix_time_in_ms": close_time_to_unix_time_in_ms,
            "update_time_from_unix_time_in_ms": update_time_from_unix_time_in_ms,
            "update_time_to_unix_time_in_ms": update_time_to_unix_time_in_ms,
            "status": status,
            "operator": operator,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "max_results": max_results,
        }
        siemplify = Siemplify()
        mocker.patch.object(
            siemplify.session,
            "post",
            return_value=mock_response,
            json=payload,
        )

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status,
                start_time_from_unix_time_in_ms,
                start_time_to_unix_time_in_ms,
                close_time_from_unix_time_in_ms,
                close_time_to_unix_time_in_ms,
                update_time_from_unix_time_in_ms,
                update_time_to_unix_time_in_ms,
                operator,
                sort_by,
                sort_order,
                max_results,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_max_results_number_raise_exception(self):
        # arrange
        status = "Test"
        max_results = -1
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(status=status, max_results=max_results)

        # assert
        assert "must be positive" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_start_time_to_unix_raise_exception(self):
        # arrange
        status = "Test"
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                start_time_to_unix_time_in_ms="Error",
            )

        # assert
        assert "timestamp is invalid" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_start_time_from_unix_raise_exception(self):
        # arrange
        status = "Test"
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                start_time_from_unix_time_in_ms="Error",
            )

        # assert
        assert "timestamp is invalid" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_start_time_smaller_from_unix_raise_exception(
        self,
    ):
        # arrange
        status = "Test"
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                start_time_from_unix_time_in_ms=2,
                start_time_to_unix_time_in_ms=1,
            )

        # assert
        assert "cannot be smaller" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_close_time_from_unix_raise_exception(self):
        # arrange
        status = "Test"
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                close_time_from_unix_time_in_ms="Error",
            )

        # assert
        assert "timestamp is invalid" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_close_time_from_unix_and_status_open_raise_exception(
        self,
    ):
        # arrange
        status = CaseFilterStatusEnum.OPEN
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                close_time_from_unix_time_in_ms=1,
            )

        # assert
        assert "cannot be provided" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_close_time_to_unix_raise_exception(self):
        # arrange
        status = 1
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                close_time_to_unix_time_in_ms="Error",
            )

        # assert
        assert "timestamp is invalid" in str(excinfo.value)

    def test_get_cases_ids_by_filter_close_time_to_unix_is_none_raise_exception(self):
        # arrange
        status = 1
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                close_time_to_unix_time_in_ms=1,
                close_time_from_unix_time_in_ms=None,
            )

        # assert
        assert "timestamp provided without" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_close_time_from_unix_higher_than_time_to_unix_raise_exception(
        self,
    ):
        # arrange
        status = 1
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                close_time_from_unix_time_in_ms=2,
                close_time_to_unix_time_in_ms=1,
            )

        # assert
        assert "cannot be smaller" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_update_time_from_unix_raise_exception(
        self,
    ):
        # arrange
        status = 1
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                update_time_from_unix_time_in_ms="Error",
            )

        # assert
        assert "update_time_from_unix_time_in_ms" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_update_time_to_unix_raise_exception(
        self,
        status=1,
    ):
        # arrange
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(
                status=status,
                update_time_to_unix_time_in_ms="Error",
            )

        # assert
        assert "update_time_to_unix_time_in_ms" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_status_raise_exception(self, status=1):
        # arrange
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(status=status)

        # assert
        assert "status' must" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_operator_raise_exception(
        self,
        status=CaseFilterStatusEnum.OPEN,
    ):
        # arrange
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(status=status, operator="Error")

        # assert
        assert "'operator' must be either" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_sort_by_raise_exception(
        self,
        status=CaseFilterStatusEnum.OPEN,
    ):
        # arrange
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(status=status, sort_by="Error")

        # assert
        assert "'sort_by' must be either" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_sort_order_raise_exception(
        self,
        status=CaseFilterStatusEnum.OPEN,
    ):
        # arrange
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(status=status, sort_order="Error")

        # assert
        assert "'sort_order' must be either" in str(excinfo.value)

    def test_get_cases_ids_by_filter_invalid_status_and_sort_by_raise_exception(
        self,
        status=CaseFilterStatusEnum.OPEN,
        sort_by=CaseFilterSortByEnum.CLOSE_TIME,
    ):
        # arrange
        siemplify = Siemplify()

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_ids_by_filter(status=status, sort_by=sort_by)

        # assert
        assert "cannot be provided" in str(excinfo.value)

    def test_create_connector_package_valid_response_success(
        self,
        mocker,
        connector_package="Siemplify",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        siemplify.create_connector_package(connector_package)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CreateConnectorPackage",
            ),
            json=connector_package,
        )

    def test_create_connector_package_invalid_response_raise_exception(
        self,
        mocker,
        connector_package="Siemplify",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.create_connector_package(connector_package)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_integration_version_valid_response_success(
        self,
        mocker,
        integration_identifier="Siemplify",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "67.0"
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_integration_version(integration_identifier)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetIntegrationVersion",
                integration_identifier,
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == "67.0"

    def test_get_integration_version_invalid_response_raise_exception(
        self,
        mocker,
        integration_identifier="Siemplify",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_integration_version(integration_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_agent_by_id_valid_response_success(
        self,
        mocker,
        agent_id="f56d0d33-dbf7-4a97-ad9e-68690d3be697",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "status": 0,
            "name": "test",
            "certificate": "-----BEGIN PUBLIC KEY-----abc\n-----END PUBLIC KEY-----\n",
            "publisher_id": 1,
            "environments": ["Default Environment"],
            "logging_level": 40,
            "access_link": "https://gcs-lab.siemplify-soar.com/pub/?id"
            "=YWJlZjRmN2MtZjg0ZS00YmQzLWIxNDQtYTAzMTczNjliODgyOjQyN2JmNGIyLWNlNmMtNDBhMi1iN2M4LTcxNDg4MzM2YmJmNg==",
            "publisher_slave_name": None,
            "identifier": "f56d0d33-dbf7-4a97-ad9e-68690d3be697",
            "publisher_name": "Cloud Publisher",
            "id": 1,
        }
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_agent_by_id(agent_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}?agentIdStr={2}&format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetAgentById",
                agent_id,
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {
            "status": 0,
            "name": "test",
            "certificate": "-----BEGIN PUBLIC KEY-----abc\n-----END PUBLIC KEY-----\n",
            "publisher_id": 1,
            "environments": ["Default Environment"],
            "logging_level": 40,
            "access_link": "https://gcs-lab.siemplify-soar.com/pub/?id"
            "=YWJlZjRmN2MtZjg0ZS00YmQzLWIxNDQtYTAzMTczNjliODgyOjQyN2JmNGIyLWNlNmMtNDBhMi1iN2M4LTcxNDg4MzM2YmJmNg==",
            "publisher_slave_name": None,
            "identifier": "f56d0d33-dbf7-4a97-ad9e-68690d3be697",
            "publisher_name": "Cloud Publisher",
            "id": 1,
        }

    def test_get_agent_by_id_invalid_response_raise_exception(
        self,
        mocker,
        agent_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_agent_by_id(agent_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_publisher_by_id_valid_response_success(self, mocker, publisher_id="1"):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "certificate": None,
            "name": "Cloud Publisher",
            "publisher_logs_link": None,
            "server_api_root": "https://gcs-lab.siemplify-soar.com/pub",
            "agent_communication_time_in_seconds": 60,
            "slave_publisher_id": None,
            "api_token": "7ff167e1200b01e770a5e7fbce5f847b5b9e3ab7",
            "id": 1,
        }
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_publisher_by_id(publisher_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}?publisherIdStr={2}&format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetPublisherById",
                publisher_id,
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {
            "certificate": None,
            "name": "Cloud Publisher",
            "publisher_logs_link": None,
            "server_api_root": "https://gcs-lab.siemplify-soar.com/pub",
            "agent_communication_time_in_seconds": 60,
            "slave_publisher_id": None,
            "api_token": "7ff167e1200b01e770a5e7fbce5f847b5b9e3ab7",
            "id": 1,
        }

    def test_get_publisher_by_id_invalid_response_raise_exception(
        self,
        mocker,
        publisher_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_publisher_by_id(publisher_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_remote_connector_keys_map_valid_response_success(
        self,
        mocker,
        publisher_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_remote_connector_keys_map(publisher_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}?publisherIdStr={2}&format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetRemoteConnectorsKeysMap",
                publisher_id,
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {}

    def test_get_remote_connector_keys_map_invalid_response_raise_exception(
        self,
        mocker,
        publisher_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_remote_connector_keys_map(publisher_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_is_existing_category_valid_response_success(self, mocker, category="test"):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = ["test", "test1", "test2", "test3"]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.is_existing_category(category)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCustomListCategories?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == True

    def test_is_existing_category_invalid_response_raise_exception(
        self,
        mocker,
        category="test",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.is_existing_category(category)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_existing_custom_list_categories_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = ["test", "test1", "test2", "test3"]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_existing_custom_list_categories()

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCustomListCategories?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == ["test", "test1", "test2", "test3"]

    def test_get_existing_custom_list_categories_invalid_response_raise_exception(
        self,
        mocker,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_existing_custom_list_categories()

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_case_tasks_invalid_response_raise_exception(self, mocker, case_id="1"):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_case_tasks(case_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_add_or_update_case_task_invalid_response_raise_exception(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.check_marketpalce_status()

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_check_marketpalce_status_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.check_marketpalce_status()

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CheckMarketplaceStatus",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_check_marketplace_status_invalid_response_raise_exception(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.check_marketpalce_status()

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_case_comments_invalid_response_raise_exception(
        self,
        mocker,
        case_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_case_comments(case_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_cases_by_filter_invalid_response_raise_exception(
        self,
        mocker,
        environments=None,
        analysts=None,
        statuses=None,
        case_names=None,
        tags=None,
        priorities=None,
        stages=None,
        case_types=None,
        products=None,
        networks=None,
        ticked_ids_free_search="",
        case_ids_free_search="",
        wall_data_free_search="",
        entities_free_search="",
        start_time_unix_time_in_ms=-1,
        end_time_unix_time_in_ms=-1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        case_filter = CasesFilter(
            environments,
            analysts,
            statuses,
            case_names,
            tags,
            priorities,
            stages,
            case_types,
            products,
            networks,
            ticked_ids_free_search,
            case_ids_free_search,
            wall_data_free_search,
            entities_free_search,
            start_time_unix_time_in_ms,
            end_time_unix_time_in_ms,
        )
        obj = siemplify.generate_serialized_object(case_filter)
        mocker.patch.object(
            siemplify.session,
            "post",
            return_value=mock_response,
            json=obj,
        )

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_by_filter(
                environments,
                analysts,
                statuses,
                case_names,
                tags,
                priorities,
                stages,
                case_types,
                products,
                networks,
                ticked_ids_free_search,
                case_ids_free_search,
                wall_data_free_search,
                entities_free_search,
                start_time_unix_time_in_ms,
                end_time_unix_time_in_ms,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_cases_by_ticket_id_invalid_response_raise_exception(
        self,
        mocker,
        ticket_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_cases_by_ticket_id(ticket_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_send_system_notification_message_valid_response_success(
        self,
        mocker,
        message="test",
        message_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "message": str(message)[:SYSTEM_NOTIFICATION_MESSAGE_CHAR_LIMIT],
            "message_id": str(message_id)[:SYSTEM_NOTIFICATION_MESSAGE_ID_CHAR_LIMIT],
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.send_system_notification_message(message, message_id)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/SendSystemNotification?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_send_system_notification_message_invalid_response_raise_exception(
        self,
        mocker,
        message="test",
        message_id="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.send_system_notification_message(message, message_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_send_system_notification_valid_response_success(
        self,
        mocker,
        message="test",
        message_id=SYSTEM_NOTIFICATION_CUSTOM_MESSAGE_ID,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "message": str(message)[:SYSTEM_NOTIFICATION_MESSAGE_CHAR_LIMIT],
            "message_id": str(message_id)[:SYSTEM_NOTIFICATION_MESSAGE_ID_CHAR_LIMIT],
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.send_system_notification(message)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/SendSystemNotification?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_send_system_notification_invalid_response_raise_exception(
        self,
        mocker,
        message="test",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.send_system_notification(message)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_attach_workflow_to_case_valid_response_success(
        self,
        mocker,
        workflow_name="test",
        cyber_case_id="1",
        indicator_identifier="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.text = "{}"
        mock_response.raise_for_status.return_value = """{"result" : "True"}"""

        # set the mock response to be returned by the session.get method
        request_dict = {
            "wf_name": workflow_name,
            "should_run_automatic": True,
            "cyber_case_id": str(cyber_case_id),
            "alert_identifier": indicator_identifier,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.attach_workflow_to_case(
            workflow_name,
            cyber_case_id,
            indicator_identifier,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AttacheWorkflowToCase?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == {}

    def test_attach_workflow_to_case_invalid_response_raise_exception(
        self,
        mocker,
        workflow_name="test",
        cyber_case_id="1",
        indicator_identifier="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.attach_workflow_to_case(
                workflow_name,
                cyber_case_id,
                indicator_identifier,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_add_entity_to_case_valid_response_success(
        self,
        mocker,
        case_id="1",
        alert_identifier="1",
        entity_identifier="google.com",
        entity_type="ADDRESS",
        is_internal=True,
        is_suspicous=True,
        is_enriched=True,
        is_vulnerable=True,
        properties={"a": "a"},
        environment="Default",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "entity_identifier": entity_identifier,
            "entity_type": entity_type,
            "is_internal": is_internal,
            "is_suspicious": is_suspicous,
            "is_enriched": is_enriched,
            "is_vulnerable": is_vulnerable,
            "properties": properties,
            "environment": environment,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.add_entity_to_case(
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
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CreateEntity?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_add_entity_to_case_invalid_response_raise_exception(
        self,
        mocker,
        case_id="1",
        alert_identifier="1",
        entity_identifier="google.com",
        entity_type="ADDRESS",
        is_internal=True,
        is_suspicous=True,
        is_enriched=True,
        is_vulnerable=True,
        properties={"a": "a"},
        environment="Default",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.add_entity_to_case(
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

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_create_case_valid_response_success(
        self,
        mocker,
        case_info={
            "Name": ["test"],
            "TicketId": ["4564"],
            "DeviceVendor": ["test"],
            "RuleGenerator": ["test"],
            "SourceSystemName": ["test"],
        },
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.create_case(case_info)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CreateCase?format=snake",
            ),
            json=case_info,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_create_case_invalid_response_raise_exception(
        self,
        mocker,
        case_info={
            "Name": ["test"],
            "TicketId": ["4564"],
            "DeviceVendor": ["test"],
            "RuleGenerator": ["test"],
            "SourceSystemName": ["test"],
        },
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.create_case(case_info)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_system_info_invalid_response_raise_exception(
        self,
        mocker,
        start_time_unixtime_ms=time.time(),
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_system_info(start_time_unixtime_ms)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_configuration_by_provider_valid_response_success(
        self,
        mocker,
        identifier="Siemplify",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "Elastic Server Address": "localhost",
            "Recipients": "example@mail.com,example1@mail.com",
        }
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_configuration_by_provider(identifier)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/configuration",
                identifier,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {
            "Elastic Server Address": "localhost",
            "Recipients": "example@mail.com,example1@mail.com",
        }

    def test_get_configuration_by_provider_invalid_response_raise_exception(
        self,
        mocker,
        identifier="VirusTotal",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_configuration_by_provider(identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_raise_incident_valid_response_success(
        self,
        mocker,
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {"case_id": case_id, "alert_identifier": alert_identifier}
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.raise_incident(case_id, alert_identifier)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/RaiseIncident?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_raise_incident_invalid_response_raise_exception(
        self,
        mocker,
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.raise_incident(case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_end(
        self,
        mocker,
        message="test",
        result_value="test_result",
        execution_state=EXECUTION_STATE_COMPLETED,
    ):
        # arrange
        siemplify = Siemplify()
        siemplify.result.message = message
        siemplify.result.result_value = result_value
        siemplify.result.execution_state = execution_state

        # set the mock response to be returned
        mocker.patch.object(siemplify, "remove_temp_folder", return_value=None)
        mocker.patch.object(siemplify, "end_script", result_value=None)

        # act
        # call the get_system_version method
        siemplify.end(message, result_value, execution_state)

        # assert the correct API address is called
        siemplify.remove_temp_folder.assert_called_once()
        siemplify.end_script.assert_called_once()

    def test_end_script(self, mocker):
        # arrange
        siemplify = Siemplify()
        mocker.patch.object(siemplify, "_build_output_object", return_value=None)
        mocker.patch("soar_sdk.SiemplifyUtils.real_stdout.write")
        mocker.patch("sys.exit")

        # act
        siemplify.end_script()

        # assert
        siemplify._build_output_object.assert_called_once()

    def test_build_output_object_response_success(self):
        # arrange
        siemplify = Siemplify()

        # act
        response = siemplify._build_output_object()

        # assert
        assert response

    def test_build_output_object_old_entities_response_success(self):
        # arrange
        siemplify = Siemplify()
        siemplify.result.support_old_entities = True

        # act
        response = siemplify._build_output_object()

        # assert
        assert response

    def test_build_output_object_json_result_response_success(self, mocker):
        # arrange
        siemplify = Siemplify()
        result = ScriptResult(entities=("1",))
        result._result_object = {"JsonResult": 1, "test": 2}
        siemplify._result = result

        # act
        response = siemplify._build_output_object()

        # assert
        assert response

    def test_build_output_object_json_result_in_tuple_response_success(self, mocker):
        # arrange
        siemplify = Siemplify()
        result = ScriptResult(entities=("1",))
        result._result_object = {("JsonResult",): "some_value"}
        siemplify._result = result

        # act
        response = siemplify._build_output_object()

        # assert
        assert response

    def test_mark_case_as_important_valid_response_success(
        self,
        mocker,
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {"case_id": case_id, "alert_identifier": alert_identifier}
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        response = siemplify.mark_case_as_important(case_id, alert_identifier)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/MarkAsImportant?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert not response

    def test_mark_case_as_important_invalid_response_raise_exception(
        self,
        mocker,
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.mark_case_as_important(case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_escalate_vase_valid_response_success(
        self,
        mocker,
        comment="test",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.text = "{}"
        mock_response.raise_for_status.return_value = """{"result" : "True"}"""

        # set the mock response to be returned by the session.post method
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "comment": comment,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        response = siemplify.escalate_case(comment, case_id, alert_identifier)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/Escalate?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response == {}

    def test_escalate_case_invalid_response_raise_exception(
        self,
        mocker,
        comment="test",
        case_id="1",
        alert_identifier="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.escalate_case(comment, case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_create_case_insight_internal_valid_response_success(
        self,
        mocker,
        case_id=1,
        alert_identifier=1,
        triggered_by="test",
        title="test",
        content="test",
        entity_identifier="test",
        severity=1,
        insight_type=0,
        additional_data="test",
        additional_data_type="string",
        additional_data_title="test",
        original_requesting_user="test",
        entity_type="ADDRESS",
    ):
        # arrange
        # create a mock response object
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
            "entity_type": entity_type,
            "additional_data": additional_data,
            "additional_data_type": additional_data_type,
            "additional_data_title": additional_data_title,
            "original_requesting_user": original_requesting_user,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.create_case_insight_internal(
            case_id,
            alert_identifier,
            triggered_by,
            title,
            content,
            entity_identifier,
            severity,
            insight_type,
            additional_data,
            additional_data_type,
            additional_data_title,
            original_requesting_user,
            entity_type,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CreateCaseInsight?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == True

    def test_create_case_insight_internal_invalid_response_raise_exception(
        self,
        mocker,
        case_id=1,
        alert_identifier=1,
        triggered_by="test",
        title="test",
        content="test",
        entity_identifier="test",
        severity=1,
        insight_type=0,
        additional_data="test",
        additional_data_type="string",
        additional_data_title="test",
        original_requesting_user="test",
        entity_type="ADDRESS",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.create_case_insight_internal(
                case_id,
                alert_identifier,
                triggered_by,
                title,
                content,
                entity_identifier,
                severity,
                insight_type,
                additional_data,
                additional_data_type,
                additional_data_title,
                original_requesting_user,
                entity_type,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_close_alert_valid_response_success(
        self,
        mocker,
        root_cause="test",
        comment="test",
        reason="test",
        case_id=1,
        alert_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "source_case_id": str(case_id),
            "alert_identifier": alert_id,
            "root_cause": root_cause,
            "reason": reason,
            "comment": comment,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.close_alert(root_cause, comment, reason, case_id, alert_id)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CloseAlert?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == {}

    def test_close_alert_invalid_response_raise_exception(
        self,
        mocker,
        root_cause="test",
        comment="test",
        reason="test",
        case_id=1,
        alert_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.close_alert(root_cause, comment, reason, case_id, alert_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_dismiss_alert_valid_response_success(
        self,
        mocker,
        alert_group_identifier="test",
        should_close_case_if_all_alerts_were_dismissed=False,
        case_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": str(case_id),
            "alert_group_identifier": alert_group_identifier,
            "should_close_case_if_all_alerts_were_dismissed": should_close_case_if_all_alerts_were_dismissed,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.dismiss_alert(
            alert_group_identifier,
            should_close_case_if_all_alerts_were_dismissed,
            case_id,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/DismissAlert?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_dismiss_alert_invalid_response_raise_exception(
        self,
        mocker,
        alert_group_identifier="test",
        should_close_case_if_all_alerts_were_dismissed=False,
        case_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.dismiss_alert(
                alert_group_identifier,
                should_close_case_if_all_alerts_were_dismissed,
                case_id,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_case_closure_details_valid_response_success(
        self,
        mocker,
        case_id_list=["1", "2", "3"],
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = [
            {
                "case_closed_action_type": 1,
                "reason": "Malicious",
                "root_cause": "root_cause",
            },
        ]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_case_closure_details(case_id_list)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCaseClosureDetails?format=snake",
            ),
            json=case_id_list,
        )

        # assert
        # assert the correct system version is returned
        assert response == [
            {
                "case_closed_action_type": 1,
                "reason": "Malicious",
                "root_cause": "root_cause",
            },
        ]

    def test_get_case_closure_details_invalid_response_raise_exception(
        self,
        mocker,
        case_id_list=["1", "2", "3"],
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_case_closure_details(case_id_list)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_close_case_valid_response_success(
        self,
        mocker,
        root_cause="test",
        comment="test",
        reason="test",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.close_case(
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
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(siemplify.API_ROOT, "external/v1/sdk/Close?format=snake"),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_close_case_invalid_response_raise_exception(
        self,
        mocker,
        root_cause="test",
        comment="test",
        reason="test",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.close_case(root_cause, comment, reason, case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_change_case_priority_valid_response_success(
        self,
        mocker,
        priority=40,
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.change_case_priority(priority, case_id, alert_identifier)

        # assert the correct API address is called
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "priority": priority,
        }
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/ChangePriority?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_change_case_priority_invalid_response_raise_exception(
        self,
        mocker,
        priority=40,
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.change_case_stage(priority, case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_change_case_stage_valid_response_success(
        self,
        mocker,
        stage="Incident",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.change_case_stage(stage, case_id, alert_identifier)

        # assert the correct API address is called
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "stage": stage,
        }
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/ChangeCaseStage?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_change_case_stage_invalid_response_raise_exception(
        self,
        mocker,
        stage="Incident",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.change_case_stage(stage, case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_ticket_ids_for_alerts_dismissed_since_timestamp_valid_response_success(
        self,
        mocker,
        timestamp_unix_ms=time.time(),
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = [1, 2, 4, 9]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {"time_stamp_unix_ms": str(timestamp_unix_ms)}
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_ticket_ids_for_alerts_dismissed_since_timestamp(
            timestamp_unix_ms,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetTicketIdsForAlertsDismissedSinceTimestamp?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == [1, 2, 4, 9]

    def test_get_ticket_ids_for_alerts_dismissed_since_timestamp_invalid_response_raise_exception(
        self,
        mocker,
        timestamp_unix_ms=time.time(),
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_ticket_ids_for_alerts_dismissed_since_timestamp(
                timestamp_unix_ms,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_alerts_ticket_ids_from_cases_closed_since_timestamp(
        self,
        mocker,
        timestamp_unix_ms=time.time(),
        rule_generator="Phishing email detector",
    ):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = [1, 2, 4, 9]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "time_stamp_unix_ms": str(timestamp_unix_ms),
            "rule_generator": rule_generator,
            "include_dismissed_alerts": False,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        response = siemplify.get_alerts_ticket_ids_from_cases_closed_since_timestamp(
            timestamp_unix_ms,
            rule_generator,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetAlertsTicketIdsFromCasesClosedSinceTimestamp?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response == [1, 2, 4, 9]

    def test_get_alerts_ticket_ids_by_case_id(self, mocker, case_id=1):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = [1, 2, 4, 9]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        response = siemplify.get_alerts_ticket_ids_by_case_id(case_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AlertsTicketIdsByCaseId",
                str(case_id),
                "?format=snake",
            ),
        )

        # assert
        assert response == [1, 2, 4, 9]

    def test_get_similar_cases_valid_response_success(
        self,
        mocker,
        case_id=1,
        ports_filter=True,
        category_outcome_filter=True,
        rule_generator_filter=True,
        entity_identifiers_filter=True,
        start_time_unix_ms=time.time(),
        end_time_unix_ms=time.time(),
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = [25, 21, 26, 27, 23, 22, 20, 24]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": case_id,
            "ports_filter": ports_filter,
            "category_outcome_filter": category_outcome_filter,
            "rule_generator_filter": rule_generator_filter,
            "entity_identifiers_filter": entity_identifiers_filter,
            "start_time_unix_ms": start_time_unix_ms,
            "end_time_unix_ms": end_time_unix_ms,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_similar_cases(
            case_id,
            ports_filter,
            category_outcome_filter,
            rule_generator_filter,
            entity_identifiers_filter,
            start_time_unix_ms,
            end_time_unix_ms,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetSimilarCasesIds?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == [25, 21, 26, 27, 23, 22, 20, 24]

    def test_get_similar_cases_invalid_response_raise_exception(
        self,
        mocker,
        case_id=1,
        ports_filter=False,
        category_outcome_filter=False,
        rule_generator_filter=False,
        entity_identifiers_filter=False,
        start_time_unix_ms=time.time(),
        end_time_unix_ms=time.time(),
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_similar_cases(
                case_id,
                ports_filter,
                category_outcome_filter,
                rule_generator_filter,
                entity_identifiers_filter,
                start_time_unix_ms,
                end_time_unix_ms,
            )

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_update_alerts_additional_data_valid_response_success(
        self,
        mocker,
        case_id=1,
        alerts_additional_data={"name": "test"},
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": case_id,
            "alerts_additional_data": alerts_additional_data,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.update_alerts_additional_data(
            case_id,
            alerts_additional_data,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/UpdateAlertsAdditional?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_update_alerts_additional_data_invalid_response_raise_exception(
        self,
        mocker,
        case_id=1,
        alerts_additional_data={"name": "test"},
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.update_alerts_additional_data(case_id, alerts_additional_data)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_add_tag_valid_response_success(
        self,
        mocker,
        tag="test",
        case_id="1",
        alert_identifier="1",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "tag": tag,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.add_tag(tag, case_id, alert_identifier)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(siemplify.API_ROOT, "external/v1/sdk/AddTag?format=snake"),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_add_tag_invalid_response_raise_exception(
        self,
        mocker,
        tag="test",
        case_id=4,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.add_tag(tag, case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_add_comment_valid_response_success(
        self,
        mocker,
        comment="test",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.add_comment(comment, case_id, alert_identifier)

        # assert the correct API address is called
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_identifier,
            "comment": comment,
        }
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/cases/comments?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_add_comment_invalid_response_raise_exception(
        self,
        mocker,
        comment="test",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.add_comment(comment, case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_assign_case_valid_response_success(
        self,
        mocker,
        user="@Administrator",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        request_dict = {
            "case_id": str(case_id),
            "alert_identifier": alert_identifier,
            "user_id": user,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.assign_case(user, case_id, alert_identifier)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AssignUser?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == None

    def test_assign_case_invalid_response_raise_exception(
        self,
        mocker,
        user="@Administrator",
        case_id=1,
        alert_identifier=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.assign_case(user, case_id, alert_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_attachment_invalid_response_raise_exception(
        self,
        mocker,
        attachment_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_attachment(attachment_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_attachments_valid_response_success(self, mocker, case_id=1):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = [
            {
                "is_favorite": False,
                "description": "",
                "type": ".txt",
                "id": 1,
                "name": "test.py",
            },
        ]
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_attachments(case_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/Attachments",
                case_id,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == [
            {
                "is_favorite": False,
                "description": "",
                "type": ".txt",
                "id": 1,
                "name": "test.py",
            },
        ]

    def test_get_attachments_invalid_response_raise_exception(self, mocker, case_id=1):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_attachments(case_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_extract_configuration_param_valid_response_success(
        self,
        mocker,
        provider="GoogleChronicle",
        param_name="API Root",
    ):
        # arrange
        # create a mock response object
        extract_script_param_response = mocker.Mock()
        extract_script_param_response.return_value = "https://backstory.googleapis.com"
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sasa",
            "AgentIdentifier": "null",
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)
        mocker.patch.object(
            SiemplifyUtils,
            "extract_script_param",
            return_value=extract_script_param_response,
        )

        # act
        response = siemplify.extract_configuration_param(provider, param_name)

        # assert
        assert response.return_value == "https://backstory.googleapis.com"

    def test_extract_configuration_param_invalid_response_raise_exception(
        self,
        mocker,
        provider=None,
        param_name="API Root",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        extract_script_param_response = mocker.Mock()
        extract_script_param_response.return_value = "https://backstory.googleapis.com"
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)
        mocker.patch.object(
            SiemplifyUtils,
            "extract_script_param",
            return_value=extract_script_param_response,
        )

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.extract_configuration_param(provider, param_name)

        # assert
        assert r"provider_name cannot be None\empty" in str(excinfo.value)

    def test_get_configuration_valid_response_success(
        self,
        mocker,
        provider="GoogleChronicle",
        environment="all",
        integration_instance="",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        identifier = integration_instance if integration_instance else provider
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_configuration(provider)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/configuration",
                identifier,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }

    def test_get_configuration_invalid_response_raise_exception(
        self,
        mocker,
        provider="GoogleChronicle",
        environment="all",
        integration_instance="",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        identifier = integration_instance if integration_instance else provider
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_configuration(provider, environment, integration_instance)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_configuration_valid_response_success_remote_option(
        self,
        mocker,
        provider="GoogleChronicle",
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        identifier = provider
        siemplify = Siemplify()
        siemplify.is_remote = True
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_configuration(provider)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/configuration",
                identifier,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }

    def test_load_vault_settings(self, mocker) -> None:
        # arrange
        siemplify = Siemplify()
        siemplify.is_remote = True
        siemplify.vault_settings = True
        configurations = {"key": "value"}
        mocker.patch(
            "soar_sdk.SiemplifyVaultUtils.extract_vault_param",
            return_value=configurations["key"],
        )

        # set the mock response to be returned by the session.get method
        response = siemplify.load_vault_settings(configurations)

        # assert
        # assert the correct system version is returned
        assert response == configurations

    def test_get_configuration_by_provider_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        configuration_identifier = "GoogleChronicle"
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_configuration_by_provider(configuration_identifier)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/configuration",
                configuration_identifier,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {
            "API Root": "https://backstory.googleapis.com",
            "UI Root": "https://{instance}.chronicle.security",
            "Verify SSL": "True",
            "User's Service Account": "sadsadsadadsada",
            "AgentIdentifier": "null",
        }

    def test_get_configuration_by_provider_invalid_response_raise_exception(
        self,
        mocker,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        configuration_identifier = "GoogleChronicle"
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_configuration_by_provider(configuration_identifier)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_system_info_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {
            "sla_count": 0,
            "manual_actions_used": 0,
            "reports_generated": 0,
            "new_integrations": ["Siemplify", "SiemplifyUtilities", "GoogleChronicle"],
            "new_connectors": [
                "Google Chronicle - Chronicle Alerts Connector",
                "Google Chronicle - IoCs Connector",
                "Google Chronicle - Alerts Connector",
            ],
            "workbooks_with_close_action": 0,
            "last_upgrade_date": "2023-03-23T10:41:48",
            "action_playbook_appearances": [],
            "unique_users_last_month": 5,
            "average_opened_cases_per_user": 2.0,
            "important_cases_count": 0,
            "playbooks_executed": 0,
            "top_user_screen_resolutions": [],
            "playbooks_edited": 0,
            "average_alerts_per_day": 0.00010289745857029612,
            "average_closed_cases_per_day": 0.0,
            "widgets_created": 17,
            "visualization_accessed": 0,
            "searches_executed": 0,
            "incidents_invoked_count": 0,
            "average_tasks_per_case": 0.0,
            "environments_count": 1,
            "custom_actions_created": 53,
            "average_insights_per_case": 0.0,
            "case_comments_added": 0,
            "version_number": "6.2.16.1",
            "dashboard_shows": 0,
            "theme_usages": [],
            "users_created": 6,
            "top_user_browsers": [
                "python-urllib3/1.26.11",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ("
                "KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
                "python-urllib3/1.26.14",
            ],
            "report_templates_edited": 7,
            "case_reports_generated": 0,
            "unique_users_last_day": 2,
            "average_users_per_day": 1.0,
            "widgets_edited": 17,
            "average_cases_per_day": 0.0001028974585703574,
            "custom_actions_edited": 53,
            "playbooks_created": 0,
        }
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        start_time_unixtime_ms = time.time()
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_system_info(start_time_unixtime_ms)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/SystemInfo",
                start_time_unixtime_ms,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {
            "sla_count": 0,
            "manual_actions_used": 0,
            "reports_generated": 0,
            "new_integrations": ["Siemplify", "SiemplifyUtilities", "GoogleChronicle"],
            "new_connectors": [
                "Google Chronicle - Chronicle Alerts Connector",
                "Google Chronicle - IoCs Connector",
                "Google Chronicle - Alerts Connector",
            ],
            "workbooks_with_close_action": 0,
            "last_upgrade_date": "2023-03-23T10:41:48",
            "action_playbook_appearances": [],
            "unique_users_last_month": 5,
            "average_opened_cases_per_user": 2.0,
            "important_cases_count": 0,
            "playbooks_executed": 0,
            "top_user_screen_resolutions": [],
            "playbooks_edited": 0,
            "average_alerts_per_day": 0.00010289745857029612,
            "average_closed_cases_per_day": 0.0,
            "widgets_created": 17,
            "visualization_accessed": 0,
            "searches_executed": 0,
            "incidents_invoked_count": 0,
            "average_tasks_per_case": 0.0,
            "environments_count": 1,
            "custom_actions_created": 53,
            "average_insights_per_case": 0.0,
            "case_comments_added": 0,
            "version_number": "6.2.16.1",
            "dashboard_shows": 0,
            "theme_usages": [],
            "users_created": 6,
            "top_user_browsers": [
                "python-urllib3/1.26.11",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ("
                "KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
                "python-urllib3/1.26.14",
            ],
            "report_templates_edited": 7,
            "case_reports_generated": 0,
            "unique_users_last_day": 2,
            "average_users_per_day": 1.0,
            "widgets_edited": 17,
            "average_cases_per_day": 0.0001028974585703574,
            "custom_actions_edited": 53,
            "playbooks_created": 0,
        }

    def test_get_system_version_valid_response_success(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"system_version": "1.0.0"}
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_system_version()

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}{2}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCurrentSiemplifyVersion",
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == {"system_version": "1.0.0"}

    def test_get_system_version_invalid_response_raise_exception(self, mocker):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.get_system_version()

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_get_external_configuration_invalid_config_provider_raise_exception(
        self,
        config_provider="TEST",
        config_name="TEST",
    ):
        # arrange
        siemplify = Siemplify()
        file_content = '{"key": "value"}'
        open_method = "__builtin__.open"
        if sys.version_info >= (3, 7):
            open_method = "builtins.open"
        with patch(open_method, mock_open(read_data=file_content)) as mocked_open:
            with patch("json.loads") as mock_json_loads:
                mock_json_loads.return_value = file_content

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_external_configuration(
                config_provider=config_provider,
                config_name=config_name,
            )

        # assert
        assert "external config provider" in str(excinfo.value)

    def test_get_external_configuration_invalid_manager_class_raise_exception(
        self,
        mocker,
        config_provider="CyberarkVault",
        config_name="TEST",
    ):
        # arrange
        mock_response = mocker.Mock()
        siemplify = Siemplify()
        file_content = """{"CyberarkVault": {
                        "manager_module_name": "CyberarkVaultManager",
                        "manager_class_name": "PasswordVaultManager"
                                          }
                        }"""
        open_method = "__builtin__.open"
        mocker.patch.object(
            SiemplifyUtils,
            "link_brother_envrionment",
            return_value=None,
        )
        mocker.patch.object(Siemplify, "get_integration_version", return_value=None)
        mocker.patch("imp.load_source", return_value=None)
        if sys.version_info >= (3, 7):
            open_method = "builtins.open"
        with patch(open_method, mock_open(read_data=file_content)) as mocked_open:
            with patch("json.loads") as mock_json_loads:
                mock_json_loads.return_value = file_content

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_external_configuration(
                config_provider=config_provider,
                config_name=config_name,
            )

        # assert
        assert "Incorrect manager class name for provider" in str(excinfo.value)

    def test_get_external_configuration_import_error_raise_exception(
        self,
        mocker,
        config_provider="CyberarkVault",
        config_name="TEST",
    ):
        # arrange
        siemplify = Siemplify()
        file_content = """{"CyberarkVault": {
                        "manager_module_name": "CyberarkVaultManager",
                        "manager_class_name": "PasswordVaultManager"
                                          }
                        }"""
        open_method = "__builtin__.open"
        mocker.patch.object(
            SiemplifyUtils,
            "link_brother_envrionment",
            return_value=None,
        )
        mocker.patch.object(Siemplify, "get_integration_version", return_value=None)
        obj = mocker.patch("imp.load_source", return_value=None)
        obj.side_effect = ImportError()
        if sys.version_info >= (3, 7):
            open_method = "builtins.open"
        with patch(open_method, mock_open(read_data=file_content)) as mocked_open:
            with patch("json.loads") as mock_json_loads:
                mock_json_loads.return_value = file_content

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_external_configuration(
                config_provider=config_provider,
                config_name=config_name,
            )

        # assert
        assert "Module not found." in str(excinfo.value)

    def test_get_external_configuration_response_raise_exception(
        self,
        mocker,
        config_provider="CyberarkVault",
        config_name="TEST",
    ):
        # arrange
        mock_response = mocker.Mock()
        siemplify = Siemplify()
        file_content = """{"CyberarkVault": {
                        "manager_module_name": "CyberarkVaultManager",
                        "manager_class_name": "PasswordVaultManager"
                                          }
                        }"""
        open_method = "__builtin__.open"

        class Test:
            PasswordVaultManager = "test"

        instance = Test()
        mocker.patch.object(
            SiemplifyUtils,
            "link_brother_envrionment",
            return_value=None,
        )
        mocker.patch.object(Siemplify, "get_integration_version", return_value=None)
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)
        mock_response.raise_for_status.return_value = 200
        mocker.patch("imp.load_source", return_value=instance)
        if sys.version_info >= (3, 7):
            open_method = "builtins.open"
        with patch(open_method, mock_open(read_data=file_content)) as mocked_open:
            with patch("json.loads") as mock_json_loads:
                mock_json_loads.return_value = file_content

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.get_external_configuration(
                config_provider=config_provider,
                config_name=config_name,
            )

        # assert
        assert "object has no attribute" in str(excinfo.value)

    def test_add_attachment_valid_response_success(
        self,
        mocker,
        file_path="test.txt",
        case_id="3",
        alert_identifier="1",
        description=None,
        is_favorite=False,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        f = open("test.txt", "w")
        f.write("first line")
        f.close()
        attachment = Attachment.fromfile(
            file_path,
            case_id,
            alert_identifier,
            description,
            is_favorite,
        )
        attachment.case_identifier = case_id
        attachment.alert_identifier = alert_identifier
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.add_attachment(file_path, case_id, alert_identifier)

        # delete the created file
        os.remove("test.txt")

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AddAttachment?format=snake",
            ),
            json=attachment.__dict__,
        )

        # assert
        # assert the correct system version is returned
        assert response == {}

    def test_add_attachment_invalid_response_raise_exception(
        self,
        mocker,
        file_path="test.txt",
        case_id="1",
        alert_identifier="1",
        description=None,
        is_favorite=False,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        mock_response.raise_for_status.side_effect = Exception("Attachment size")

        # set the mock response to be returned by the session.get method
        f = open("test.txt", "w")
        f.write("first line")
        f.close()
        attachment = Attachment.fromfile(
            file_path,
            case_id,
            alert_identifier,
            description,
            is_favorite,
        )
        attachment.case_identifier = case_id
        attachment.alert_identifier = alert_identifier
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.add_attachment(
                file_path,
                case_id,
                alert_identifier,
                description,
                is_favorite,
            )

        # delete the created file
        os.remove("test.txt")

        # assert
        assert "Attachment size should" in str(excinfo.value)

    def test_add_attachment_invalid_response_raise_exception_else_option(
        self,
        mocker,
        file_path="test.txt",
        case_id="1",
        alert_identifier="1",
        description=None,
        is_favorite=False,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {}
        mock_response.raise_for_status.return_value = None
        mock_response.raise_for_status.side_effect = Exception()

        # set the mock response to be returned by the session.post method
        f = open("test.txt", "w")
        f.write("first line")
        f.close()
        attachment = Attachment.fromfile(
            file_path,
            case_id,
            alert_identifier,
            description,
            is_favorite,
        )
        attachment.case_identifier = case_id
        attachment.alert_identifier = alert_identifier
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        mocker.patch.object(
            siemplify.LOGGER,
            "error",
            return_value="Could not add attachment",
        )

        # act
        siemplify.add_attachment(
            file_path,
            case_id,
            alert_identifier,
            description,
            is_favorite,
        )

        # delete the created file
        os.remove("test.txt")

        # assert
        siemplify.LOGGER.error.assert_called_with("Could not add attachment: ")

    def test_add_or_update_case_task_valid_response_success(
        self,
        mocker,
        task={
            "alert_identifier": None,
            "creation_time_unix_time_in_ms": 1681721226699,
            "is_favorite": False,
            "owner": "@Administrator",
            "completion_date_time_unix_time_in_ms": None,
            "id": 2,
            "modification_time_unix_time_in_ms": 1681721226699,
            "last_modifier_full_name": "oriann barzely",
            "title": "asdsad",
            "priority": 0,
            "owner_comment": None,
            "case_id": 1,
            "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
            "content": "sd",
            "status": 0,
            "last_modifier": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
            "is_important": False,
            "completion_comment": None,
            "due_date_unix_time_ms": None,
            "owner_full_name": "@Administrator",
            "completor": None,
            "completor_full_name": None,
            "creator_full_name": "oriann barzely",
        },
    ):
        # arrange
        # create a mock response object
        task = Task(**task)

        mock_response = mocker.Mock()
        # mock_response.json.return_value = {"content" : "1"}
        mock_response.content = "1"
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.add_or_update_case_task(task)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AddOrUpdateCaseTask?format=snake",
            ),
            json=task.__dict__,
        )

        # assert
        # assert the correct system version is returned
        assert response == 1

    def test_get_attachment_valid_response_success(self, mocker) -> None:
        # arrange
        attachment_id = 1
        # create a mock response object
        mock_response = mocker.Mock()
        content: bytes = (
            b'{"FileContents": \n'
            b'        "iVBORw0KGgoAAAANSUhEUgAAAGMAAABoCAYAAADl\n'
            b'        /E5WAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsIAAA7CARUoSoAAAAVQSURBVHhe7Zs/aBtXHMd/5ymaKhlSsCDY2BlsJ5QEZcgQDCl1F5PFtENpCTaYbqZQAhm6GEyGgmkJXQ0xJiVLMAXjpYaICA8dIhJKY2exqEhRhoClTurk63v276TT6U4nnfSefi/v9wHj35NDBn3u931/7s6p/vObCwwJRvA3QwCWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQiWQQjCDz6XYa24D7s4CmcUvptdhLspHBoOLRm1POSOj3HQK+aLoSGjLwnt3JlagbU0DgxiyDK6iaKEZOahODmOAzMY3gQuu0GVCEl1H3KHr4RucxhOZ3QbS7FXd3xnmRRZ+mXEikg4EddfwTeHL+AIhx4z2S/g8ZgZNjTHlLiSO4iQX1wxl3BFlLoGj3MrUJy9ATP4kWlolVEoRUeKjJOBXMEoZSc7eja8nDJnWaUvpjrEk6lL0UGjqTNqsF0JFyGjiUWco0dG7SU8rGPtJ3UDHhgyuepAi4zCSUQ8Za+BWdsytWiQUYZnVSz9iK5Y5qZoQb2MWil0BTWTmeCuCKBcRrke1haj8Hma2yKIYhk1eF49wdpPBiY+kHsQg0SxjH+hFLqKynBEhaBhAg/hAssIQ+0OfCCHd33c8xArtp1Zc5bPw+mMXohYjXVF/QU8qmFtAPRlWAR9GelJuIPlh85Q5gw196drsH34tO0MzKQTYbWdIZawl7Fk4lEcUx/BZNjm7r+qUQ8K6EKxjDRMXMDST70Ez8M2g5ajfAIfT53f/mzlBH6vGbTm1IQGGRmsWjmq/s1RFUC5jMilqWEbMh2olwHjsIxPagTZrZj1xJ9qNMgQOkR3hD7LJLrjh3fcHh5aZMhnmb4NnzrgqPIMtnlldYYeGYK5sagn/U7g4eEOCxFokyG740HE3HEuZBPWLE8sfTIE42OL8HNEXEl2jzchV8xDAce9UCi1n0uZxhBeCQg/0Asl7kCxi1cL+JWAWHoQ0id8ahtLGu7ONp8UV8cUfGrQE0FD6gw/at7rM+klGQ8CMjwGEV2KXz9+m4fTL/dw4GP1Pox8fREHySEko5Xyux1YrIQ9ANeKlg44eAKn94o4iCIHzh9fgYOjJJCVQYf34C79CO4bWQe/8Nfg3nwEjS9wegFGtm7joHeGNIGbh7OxASNtV/4VIWe5+dmbPXAPsE4Ay4jlIjhbG+DcwmEbVwAWsBS45fdY9Y4dMn79CU5v3jv7ibty3fXzf3e6lMdP4nEms1j1hx0y5q5jIb7s/GuswhB/8xZLUx9joQ87ZFy6Cs401nt/NifcIAfNvzm3Rfx0hZjg9ytYZ8GZS77EtWTOELk/70WJWKJGRJWb95avOYDIOSLA279wpSWYvg7OJawTYM8EHhtVvoha/azr/YK75dsEzl/FIhn2yIiLqkZE9RA1YjPoei7kHqPPXbg9MmRUrYj4OSMYVSL3NzGiuo4aseFr7MqFwPXkmz0Pi2QIbn3SiJ+WqPLnfldR07rzdja+72uu8LBLhn+D5o+qwkssuokoeTziOwJZvd9hQ9gblsmQS9ZgVPmWprER5T+nEgzotNbDOhltUeWLKGelU+6rFSGxT0YwqhoR1Xlv4a6rFSGxUIbogCXPRhHcXzCiFpodE0SeVzWWsAvLSkRILL2fEYgcgTwiD52Io+7udSDy/4rBys5oPR6R9HD8oRC+00cISzuDJiyDECyDECyDECyDECyDECyDECyDECyDECyDECyDECyDECyDECyDDAD/A+CNxriJKoq1AAAAAElFTkSuQmCC","ContentType": "application/octet-stream","FileDownloadName": "",  "LastModified": None,  "EntityTag": None,  "EnableRangeProcessing": False}'
        )
        mock_response.content = content
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_attachment(attachment_id)
        response = response.getvalue()
        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AttachmentData",
                str(attachment_id),
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response == content

    def test_get_cases_by_ticket_id_valid_response_success(self, mocker, ticket_id="1"):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.text = "[1, 3, 5, 6, 9, 10, 11, 12, 14]"
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        cases_filter = CasesFilter(ticked_ids_free_search=ticket_id)
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_cases_by_ticket_id(ticket_id)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCasesByFilter?format=snake",
            ),
            json=cases_filter.__dict__,
        )

        # assert
        # assert the correct system version is returned
        assert response == [1, 3, 5, 6, 9, 10, 11, 12, 14]

    def test_get_cases_by_filter_valid_response_success(
        self,
        mocker,
        environments=None,
        analysts=None,
        statuses=None,
        case_names=None,
        tags=["test_tag"],
        priorities=None,
        stages=None,
        case_types=None,
        products=None,
        networks=None,
        ticked_ids_free_search="",
        case_ids_free_search="",
        wall_data_free_search="",
        entities_free_search="",
        start_time_unix_time_in_ms=-1,
        end_time_unix_time_in_ms=-1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.text = "[1, 3, 5, 6, 9, 10, 11, 12, 14]"
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
        case_filter = CasesFilter(
            environments,
            analysts,
            statuses,
            case_names,
            tags,
            priorities,
            stages,
            case_types,
            products,
            networks,
            ticked_ids_free_search,
            case_ids_free_search,
            wall_data_free_search,
            entities_free_search,
            start_time_unix_time_in_ms,
            end_time_unix_time_in_ms,
        )
        obj = Siemplify.generate_serialized_object(case_filter)
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_cases_by_filter(
            environments,
            analysts,
            statuses,
            case_names,
            tags,
            priorities,
            stages,
            case_types,
            products,
            networks,
            ticked_ids_free_search,
            case_ids_free_search,
            wall_data_free_search,
            entities_free_search,
            start_time_unix_time_in_ms,
            end_time_unix_time_in_ms,
        )

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCasesByFilter?format=snake",
            ),
            json=obj,
        )

        # assert
        # assert the correct system version is returned
        assert response == [1, 3, 5, 6, 9, 10, 11, 12, 14]

    def test_get_case_comments_valid_response_success(self, mocker, case_id="1"):
        # arrange
        # create a mock response object
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

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_case_comments(case_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCaseComments",
                case_id,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
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

    def test_fetch_case_comments_valid_response_success(
        self,
        mocker,
        case_id="1",
        time_filter="2",
        time_stamp="2",
    ):
        # arrange
        # create a mock response object
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

        # set the mock response to be returned by the session.get method
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.fetch_case_comments(case_id, time_filter, time_stamp)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}{2}".format(
                siemplify.API_ROOT,
                "external/v1/cases/comments",
                "?format=snake&caseId="
                + str(case_id)
                + "&spec.timeFilterType="
                + str(time_filter)
                + "&spec.fromTimestamp="
                + str(time_stamp),
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

    def test_get_case_tasks_valid_response_success(self, mocker, case_id="1"):
        # arrange
        # create a mock response object
        task_dicts = [
            {
                "alert_identifier": None,
                "creation_time_unix_time_in_ms": 1681721226699,
                "is_favorite": False,
                "owner": "@Administrator",
                "completion_date_time_unix_time_in_ms": None,
                "id": 2,
                "modification_time_unix_time_in_ms": 1681721226699,
                "last_modifier_full_name": "oriann barzely",
                "title": "asdsad",
                "priority": 0,
                "owner_comment": None,
                "case_id": 1,
                "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "content": "sd",
                "status": 0,
                "last_modifier": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "is_important": False,
                "completion_comment": None,
                "due_date_unix_time_ms": None,
                "owner_full_name": "@Administrator",
                "completor": None,
                "completor_full_name": None,
                "creator_full_name": "oriann barzely",
            },
            {
                "alert_identifier": None,
                "creation_time_unix_time_in_ms": 1681721429711,
                "is_favorite": False,
                "owner": "@Tier1",
                "completion_date_time_unix_time_in_ms": None,
                "id": 3,
                "modification_time_unix_time_in_ms": 1681721429711,
                "last_modifier_full_name": "oriann barzely",
                "title": "task2",
                "priority": 0,
                "owner_comment": None,
                "case_id": 1,
                "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "content": "sdf",
                "status": 0,
                "last_modifier": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "is_important": False,
                "completion_comment": None,
                "due_date_unix_time_ms": None,
                "owner_full_name": "@Tier1",
                "completor": None,
                "completor_full_name": None,
                "creator_full_name": "oriann barzely",
            },
        ]
        tasks = [Task(**task_dict) for task_dict in task_dicts]

        mock_response = mocker.Mock()
        temp = [
            {
                "alert_identifier": None,
                "creation_time_unix_time_in_ms": 1681721226699,
                "is_favorite": False,
                "owner": "@Administrator",
                "completion_date_time_unix_time_in_ms": None,
                "id": 2,
                "modification_time_unix_time_in_ms": 1681721226699,
                "last_modifier_full_name": "oriann barzely",
                "title": "asdsad",
                "priority": 0,
                "owner_comment": None,
                "case_id": 1,
                "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "content": "sd",
                "status": 0,
                "last_modifier": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "is_important": False,
                "completion_comment": None,
                "due_date_unix_time_ms": None,
                "owner_full_name": "@Administrator",
                "completor": None,
                "completor_full_name": None,
                "creator_full_name": "oriann barzely",
            },
            {
                "alert_identifier": None,
                "creation_time_unix_time_in_ms": 1681721429711,
                "is_favorite": False,
                "owner": "@Tier1",
                "completion_date_time_unix_time_in_ms": None,
                "id": 3,
                "modification_time_unix_time_in_ms": 1681721429711,
                "last_modifier_full_name": "oriann barzely",
                "title": "task2",
                "priority": 0,
                "owner_comment": None,
                "case_id": 1,
                "creator_user_id": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "content": "sdf",
                "status": 0,
                "last_modifier": "cd1c112a-0277-44a9-b68d-98ceef9b0399",
                "is_important": False,
                "completion_comment": None,
                "due_date_unix_time_ms": None,
                "owner_full_name": "@Tier1",
                "completor": None,
                "completor_full_name": None,
                "creator_full_name": "oriann barzely",
            },
        ]
        mock_response.text = json.dumps(temp)
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        # call the get_system_version method
        response = siemplify.get_case_tasks(case_id)

        # assert the correct API address is called
        siemplify.session.get.assert_called_with(
            "{0}/{1}/{2}{3}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/GetCaseTasks",
                case_id,
                "?format=snake",
            ),
        )

        # assert
        # assert the correct system version is returned
        assert response[0].__dict__ == tasks[0].__dict__

    def test_any_entity_in_custom_list(
        self,
        mocker,
        custom_list_items=[CustomList("test", "test", "test")],
    ):
        # arrange
        request_dict = {
            "identifier": "test",
            "creation_time": None,
            "modification_time": None,
            "additional_properties": None,
            "category": "test",
            "environment": "test",
        }
        mock_response = mocker.Mock()
        mock_response.text = "True"
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        response = siemplify.any_entity_in_custom_list(
            custom_list_items=custom_list_items,
        )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AnyEntityInCustomList?format=snake",
            ),
            json=[request_dict],
        )
        assert response

    def test_add_entities_to_custom_list(
        self,
        mocker,
        custom_list_items=[CustomList("test", "test", "test")],
    ):
        # arrange
        request_dict = {"identifier": "test", "category": "test", "environment": "test"}
        response_dict = {
            "identifier": "test",
            "creation_time": None,
            "modification_time": None,
            "additional_properties": None,
            "category": "test",
            "environment": "test",
        }
        mock_response = mocker.Mock()
        mock_response.json.return_value = [request_dict]
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        response = siemplify.add_entities_to_custom_list(
            custom_list_items=custom_list_items,
        )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/AddEntitiesToCustomList?format=snake",
            ),
            json=[response_dict],
        )
        assert isinstance(response[0], CustomList)

    def test_remove_entities_from_custom_list(
        self,
        mocker,
        custom_list_items=[CustomList("test", "test", "test")],
    ):
        # arrange
        request_dict = {"identifier": "test", "category": "test", "environment": "test"}
        response_dict = {
            "identifier": "test",
            "creation_time": None,
            "modification_time": None,
            "additional_properties": None,
            "category": "test",
            "environment": "test",
        }
        mock_response = mocker.Mock()
        mock_response.json.return_value = [request_dict]
        mock_response.raise_for_status.return_value = 200

        # act
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        response = siemplify.remove_entities_from_custom_list(
            custom_list_items=custom_list_items,
        )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/RemoveEntitiesFromCustomList?format=snake",
            ),
            json=[response_dict],
        )
        assert isinstance(response[0], CustomList)

    def test_add_entity_insight_valid_response_success(
        self,
        mocker,
        updated_entities={
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
                "ThreatSource": "TEST1234",
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
        },
        message="test",
        case_id=1,
        alert_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = True
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
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
        test_entity._update_internal_properties()

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_id,
            "triggered_by": "TEST1234",
            "title": "Entity insight",
            "content": message,
            "entity_identifier": "LAB@SIEMPLIFY.LOCAL",
            "severity": InsightSeverity.WARN,
            "type": InsightType.Entity,
            "entity_type": None,
            "additional_data": None,
            "additional_data_type": None,
            "additional_data_title": None,
            "original_requesting_user": None,
        }
        response = siemplify.add_entity_insight(test_entity, message, case_id, alert_id)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CreateCaseInsight?format=snake",
            ),
            json=request_dict,
        )

        # assert
        assert response

    def test_add_entity_insight_valid_response_success_else_option(
        self,
        mocker,
        updated_entities={
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
        },
        message="test",
        case_id=1,
        alert_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = True
        mock_response.raise_for_status.return_value = None

        # set the mock response to be returned by the session.get method
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
        test_entity._update_internal_properties()
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method
        request_dict = {
            "case_id": case_id,
            "alert_identifier": alert_id,
            "triggered_by": INSIGHT_DEFAULT_THREAT_SOURCE,
            "title": "Entity insight",
            "content": message,
            "entity_identifier": "LAB@SIEMPLIFY.LOCAL",
            "severity": InsightSeverity.WARN,
            "type": InsightType.Entity,
            "entity_type": None,
            "additional_data": None,
            "additional_data_type": None,
            "additional_data_title": None,
            "original_requesting_user": None,
        }
        response = siemplify.add_entity_insight(test_entity, message, case_id, alert_id)

        # assert the correct API address is called
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/CreateCaseInsight?format=snake",
            ),
            json=request_dict,
        )

        # assert
        # assert the correct system version is returned
        assert response == True

    def test_add_entity_insight_invalid_response_raise_exception(
        self,
        mocker,
        updated_entities={
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
        },
        message="test",
        case_id=1,
        alert_id=1,
    ):
        # arrange
        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # set the mock response to be returned by the session.get method
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
        test_entity._update_internal_properties()
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        # call the get_system_version method and assert that the correct exception is
        # raised
        with pytest.raises(Exception) as excinfo:
            siemplify.add_entity_insight(test_entity, message, case_id, alert_id)

        # assert
        assert "404: Not Found" in str(excinfo.value)

    def test_fetch_new_alerts_to_sync_success(self, mocker):
        # Arrange
        batch_size = 800
        environments = ["Default Environment"]

        mock_response = mocker.Mock()
        mock_response.json.return_value = []
        mock_response.raise_for_status.return_value = None
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # Act
        request_dict = {"batch_size": batch_size, "environments": environments}
        response = siemplify.fetch_new_alerts_to_sync(batch_size, environments)

        # Assert
        siemplify.session.get.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/sync/new-alerts?format=snake",
            ),
            json=request_dict,
        )
        assert response == []

    def test_fetch_new_alerts_to_sync_invalid_response_raise_exception(self, mocker):
        # Arrange
        batch_size = 800
        environments = ["Default Environment"]

        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # Act
        with pytest.raises(Exception) as exception_info:
            siemplify.fetch_new_alerts_to_sync(batch_size, environments)
        # Assert
        assert "404: Not Found" in str(exception_info.value)

    def test_update_new_alerts_sync_status_success(self, mocker):
        # Arrange
        results = []
        environments = ["Default Environment"]
        mock_response = mocker.Mock()
        mock_response.json.return_value = []
        mock_response.raise_for_status.return_value = None
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # Act
        request_dict = {"results": results, "environments": environments}
        response = siemplify.update_new_alerts_sync_status(results, environments)

        # Assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/sync/new-alerts/results?format=snake",
            ),
            json=request_dict,
        )
        assert response == []

    def test_update_new_alerts_sync_status_response_raise_exception(self, mocker):
        # Arrange
        results = []
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # Act
        with pytest.raises(Exception) as exception_info:
            siemplify.update_new_alerts_sync_status(results)

        # Assert
        assert "404: Not Found" in str(exception_info.value)

    def test_add_agent_connector_logs_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = None
        mock_response.raise_for_status.return_value = None
        agent_id = "5558C7D2-E1F3-4D58-919D-93598D8F41A6"
        connector_id = "1B06A731-2798-4E5E-88B8-503D7124C97B"
        logs_package = None

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        response = siemplify.add_agent_connector_logs(
            agent_id,
            connector_id,
            logs_package,
        )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}/{4}/{5}".format(
                siemplify.API_ROOT,
                "external/v1/sdk/agents",
                agent_id,
                "connectors",
                connector_id,
                "logs",
            ),
            json=logs_package,
        )
        assert response is None

    def test_add_agent_connector_logs_response_raise_exception(self, mocker):
        # Arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        agent_id = "5558C7D2-E1F3-4D58-919D-93598D8F41A6"
        connector_id = "1B06A731-2798-4E5E-88B8-503D7124C97B"
        logs_package = None

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        with pytest.raises(Exception) as exception_info:
            siemplify.add_agent_connector_logs(agent_id, connector_id, logs_package)

        # assert
        assert "404: Not Found" in str(exception_info.value)

    def test_get_temp_folder_path_creates_new_folder_success(self, mocker):
        # arrange
        temp_dir = f"/tmp/test_folder_{uuid.uuid4().hex}"
        mock_mkdtemp = mocker.patch("tempfile.mkdtemp", return_value=temp_dir)
        siemplify = Siemplify()

        # act
        result = siemplify.get_temp_folder_path()

        # assert
        mkdtemp_kwargs = mock_mkdtemp.call_args[1]
        assert "suffix" in mkdtemp_kwargs
        assert isinstance(mkdtemp_kwargs["suffix"], str)
        try:
            uuid.UUID(mkdtemp_kwargs["suffix"])
        except ValueError:
            pytest.fail("Suffix is expected to be a valid UUID")
        assert result == temp_dir

    def test_get_temp_folder_path_returns_existing_path_success(self):
        # arrange
        siemplify = Siemplify()
        existing_temp_folder_path = tempfile.mkdtemp()
        siemplify.temp_folder_path = existing_temp_folder_path

        # act
        result = siemplify.get_temp_folder_path()

        # assert
        assert result == existing_temp_folder_path

    def test_remove_temp_folder_temp_folder_is_not_set_success(self):
        # arrange
        siemplify = Siemplify()

        # act
        siemplify.remove_temp_folder()

    def test_remove_temp_folder_temp_folder_is_set_but_not_exists_success(self):
        # arrange
        siemplify = Siemplify()
        siemplify.temp_folder_path = f"/tmp/non_existing_path_{uuid.uuid4().hex}"

        # act
        siemplify.remove_temp_folder()

    def test_remove_temp_folder_success(self):
        # arrange
        siemplify = Siemplify()
        temp_folder_path = tempfile.mkdtemp()
        siemplify.temp_folder_path = temp_folder_path

        # act
        siemplify.remove_temp_folder()

        # assert
        assert not os.path.exists(temp_folder_path)

    def test_get_updated_sync_cases_metadata_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        json_result = [
            {"id": 1, "tracking_time_unix_time_in_ms": 100},
            {"id": 2, "tracking_time_unix_time_in_ms": 200},
            {"id": 3, "tracking_time_unix_time_in_ms": 300},
        ]
        mock_response.json.return_value = json_result
        mock_response.raise_for_status.return_value = None
        start_timestamp_unix_ms = 100
        items_count = 500
        allowed_environments = ["Default Environment"]
        vendor = "Google"
        request = {
            "start_timestamp_unix_ms": start_timestamp_unix_ms,
            "items_count": items_count,
            "allowed_environments": allowed_environments,
            "vendor": vendor,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        cases_metadata = siemplify.get_updated_sync_cases_metadata(
            start_timestamp_unix_ms,
            items_count,
            allowed_environments,
            vendor,
        )

        # assert
        siemplify.session.get.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/sync/cases/metadata",
            ),
            json=request,
        )
        assert cases_metadata
        assert len(cases_metadata) == 3
        for i in range(len(cases_metadata)):
            assert cases_metadata[i].case_id == str(json_result[i]["id"])
            assert cases_metadata[i].tracking_time == int(
                json_result[i]["tracking_time_unix_time_in_ms"],
            )

    def test_get_updated_sync_cases_metadata_response_raise_exception(self, mocker):
        # Arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        start_timestamp_unix_ms = 100
        items_count = 500
        allowed_environments = ["Default Environment"]
        vendor = "Google"

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        with pytest.raises(Exception) as exception_info:
            siemplify.get_updated_sync_cases_metadata(
                start_timestamp_unix_ms,
                items_count,
                allowed_environments,
                vendor,
            )

        # assert
        assert "404: Not Found" in str(exception_info.value)

    def test_get_sync_cases_no_case_ids_returns_empty_list_success(self):
        # arrange
        siemplify = Siemplify()

        # act + assert
        assert siemplify.get_sync_cases(None) == []
        assert siemplify.get_sync_cases([]) == []

    def test_get_sync_cases_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        json_result = [
            {
                "id": 1,
                "environment": "Default Environment",
                "priority": ApiSyncCasePriorityEnum.LOW,
                "stage": "Triage",
                "status": ApiSyncCaseStatusEnum.OPENED,
                "external_case_id": "external_1",
                "title": "Phishing Email",
            },
            {
                "id": 2,
                "environment": "Default Environment",
                "priority": ApiSyncCasePriorityEnum.HIGH,
                "stage": "Triage",
                "status": ApiSyncCaseStatusEnum.OPENED,
                "external_case_id": "external_1",
                "title": "Virus Found",
            },
        ]
        mock_response.json.return_value = json_result
        mock_response.raise_for_status.return_value = None
        case_ids = [1, 2]
        request = {"case_ids": case_ids}

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        sync_cases = siemplify.get_sync_cases(case_ids)

        # assert
        siemplify.session.get.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/sync/cases",
            ),
            json=request,
        )
        assert sync_cases
        assert len(sync_cases) == 2
        for i in range(len(sync_cases)):
            assert sync_cases[i].case_id == json_result[i]["id"]
            assert sync_cases[i].environment == json_result[i]["environment"]
            assert sync_cases[i].priority == json_result[i]["priority"]
            assert sync_cases[i].stage == json_result[i]["stage"]
            assert sync_cases[i].status == json_result[i]["status"]
            assert sync_cases[i].external_case_id == json_result[i]["external_case_id"]
            assert sync_cases[i].title == json_result[i]["title"]

    def test_get_sync_cases_response_raise_exception(self, mocker):
        # Arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        case_ids = [1, 2]

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        with pytest.raises(Exception) as exception_info:
            siemplify.get_sync_cases(case_ids)

        # assert
        assert "404: Not Found" in str(exception_info.value)

    def test_batch_update_case_id_matches_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        json_result = [1, 2]
        mock_response.json.return_value = json_result
        mock_response.raise_for_status.return_value = None
        case_ids_matches = [
            SyncCaseIdMatch(1, "external_1"),
            SyncCaseIdMatch(2, "external_2"),
        ]
        request = {
            "case_ids_matches": [
                {"case_id": 1, "external_case_id": "external_1"},
                {"case_id": 2, "external_case_id": "external_2"},
            ],
        }

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        updated_case_ids = siemplify.batch_update_case_id_matches(case_ids_matches)

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/sync/cases/matches",
            ),
            json=request,
        )
        assert updated_case_ids
        assert len(updated_case_ids) == 2
        assert set(updated_case_ids) == set(
            [match.case_id for match in case_ids_matches],
        )

    def test_batch_update_case_id_matches_response_raise_exception(self, mocker):
        # Arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        case_ids_matches = [
            SyncCaseIdMatch(1, "external_1"),
            SyncCaseIdMatch(2, "external_2"),
        ]

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        with pytest.raises(Exception) as exception_info:
            siemplify.batch_update_case_id_matches(case_ids_matches)

        # assert
        assert "404: Not Found" in str(exception_info.value)

    def test_get_updated_sync_alerts_metadata_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        json_result = [
            {"group_id": "NewAlert1", "tracking_time_unix_time_in_ms": 100},
            {"group_id": "NewAlert2", "tracking_time_unix_time_in_ms": 200},
            {"group_id": "NewAlert3", "tracking_time_unix_time_in_ms": 300},
        ]
        mock_response.json.return_value = json_result
        mock_response.raise_for_status.return_value = None
        start_timestamp_unix_ms = 100
        items_count = 500
        allowed_environments = ["Default Environment"]
        vendor = "Google"
        include_non_synced_alerts = False
        request = {
            "start_timestamp_unix_ms": start_timestamp_unix_ms,
            "items_count": items_count,
            "allowed_environments": allowed_environments,
            "vendor": vendor,
            "include_non_synced_alerts": include_non_synced_alerts,
        }
        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        alerts_metadata = siemplify.get_updated_sync_alerts_metadata(
            start_timestamp_unix_ms,
            items_count,
            allowed_environments,
            vendor,
            include_non_synced_alerts,
        )

        # assert
        siemplify.session.get.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/sync/alerts/metadata",
            ),
            json=request,
        )
        assert alerts_metadata
        assert len(alerts_metadata) == 3
        for i in range(len(alerts_metadata)):
            assert alerts_metadata[i].alert_group_id == str(json_result[i]["group_id"])
            assert alerts_metadata[i].tracking_time == int(
                json_result[i]["tracking_time_unix_time_in_ms"],
            )

    def test_get_updated_sync_alerts_metadata_response_raise_exception(self, mocker):
        # Arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        start_timestamp_unix_ms = 100
        items_count = 500
        allowed_environments = ["Default Environment"]
        vendor = "Google"
        include_non_synced_alerts = False

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        with pytest.raises(Exception) as exception_info:
            siemplify.get_updated_sync_alerts_metadata(
                start_timestamp_unix_ms,
                items_count,
                allowed_environments,
                vendor,
                include_non_synced_alerts,
            )

        # assert
        assert "404: Not Found" in str(exception_info.value)

    def test_get_sync_alerts_no_group_ids_returns_empty_list_success(self):
        # arrange
        siemplify = Siemplify()

        # act + assert
        assert siemplify.get_sync_alerts(None) == []
        assert siemplify.get_sync_alerts([]) == []

    def test_get_sync_alerts_valid_response_success(self, mocker):
        # arrange
        mock_response = mocker.Mock()
        json_result = [
            {
                "group_id": "NewAlertGroupId1",
                "id": "NewAlertId1",
                "case_id": 1,
                "environment": "Default Environment",
                "priority": ApiSyncAlertPriorityEnum.LOW,
                "status": ApiSyncAlertStatusEnum.OPENED,
                "ticket_id": "NewAlertTicketId1",
                "creation_time_unix_time_in_ms": 100,
                "close_comment": None,
                "close_reason": None,
                "close_root_cause": None,
                "close_usefulness": None,
                "siem_alert_id": None,
            },
            {
                "group_id": "NewAlertGroupId2",
                "id": "NewAlertId2",
                "case_id": 2,
                "environment": "Default Environment",
                "priority": ApiSyncAlertPriorityEnum.LOW,
                "status": ApiSyncAlertStatusEnum.OPENED,
                "ticket_id": "NewAlertTicketId2",
                "creation_time_unix_time_in_ms": 102,
                "close_comment": "Alert was closed because it is not relevant anymore",
                "close_reason": ApiSyncAlertCloseReasonEnum.MALICIOUS,
                "close_root_cause": "Legacy",
                "close_usefulness": ApiSyncAlertUsefulnessEnum.USEFUL,
                "siem_alert_id": "sa_58fa99e2-877d-4431-9b0a-eed09aa6d41b",
            },
        ]
        mock_response.json.return_value = json_result
        mock_response.raise_for_status.return_value = None
        alert_group_ids = ["NewAlertId1", "NewAlertId2"]
        request = {"alert_group_ids": alert_group_ids}

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        sync_alerts = siemplify.get_sync_alerts(alert_group_ids)

        # assert
        siemplify.session.get.assert_called_with(
            "{0}/{1}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/sync/alerts",
            ),
            json=request,
        )
        assert sync_alerts
        assert len(sync_alerts) == 2
        for i in range(len(sync_alerts)):
            assert sync_alerts[i].alert_group_id == json_result[i]["group_id"]
            assert sync_alerts[i].alert_id == json_result[i]["id"]
            assert sync_alerts[i].case_id == json_result[i]["case_id"]
            assert sync_alerts[i].environment == json_result[i]["environment"]
            assert sync_alerts[i].priority == json_result[i]["priority"]
            assert sync_alerts[i].status == json_result[i]["status"]
            assert sync_alerts[i].ticket_id == json_result[i]["ticket_id"]
            assert sync_alerts[i].creation_time == json_result[i]["creation_time_unix_time_in_ms"]
            assert sync_alerts[i].close_comment == json_result[i]["close_comment"]
            assert sync_alerts[i].close_reason == json_result[i]["close_reason"]
            assert sync_alerts[i].close_root_cause == json_result[i]["close_root_cause"]
            assert sync_alerts[i].close_usefulness == json_result[i]["close_usefulness"]
            assert sync_alerts[i].siem_alert_id == json_result[i]["siem_alert_id"]

    def test_get_sync_alerts_response_raise_exception(self, mocker):
        # Arrange
        mock_response = mocker.Mock()
        mock_response.json.return_value = {"error": "Invalid request"}
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        alert_group_ids = ["NewAlertId1", "NewAlertId2"]

        siemplify = Siemplify()
        mocker.patch.object(siemplify.session, "get", return_value=mock_response)

        # act
        with pytest.raises(Exception) as exception_info:
            siemplify.get_sync_alerts(alert_group_ids)

        # assert
        assert "404: Not Found" in str(exception_info.value)

    def test_set_case_sla_response_raise_exception_period_type(
        self,
        mocker,
        period_time=1,
        period_type="1",
        critical_period_time=None,
        critical_period_type=None,
        case_id=None,
    ):
        # arrange
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.set_case_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
            )

        # assert
        assert "SLA period type is invalid" in str(excinfo.value)

    def test_set_case_sla_response_raise_exception_critical_period_type(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=None,
        critical_period_type="1",
        case_id=None,
    ):
        # arrange
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.set_case_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
            )

        # assert
        assert "SLA time to critical period" in str(excinfo.value)

    def test_set_case_sla_response_success(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=1,
        critical_period_type="Minutes",
        case_id=None,
    ):
        # arrange
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        siemplify.set_case_sla(
            period_time,
            period_type,
            critical_period_time,
            critical_period_type,
            case_id,
        )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "sla",
            ),
            json=request,
        )

    def test_set_case_sla_response_exception_http_error(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=1,
        critical_period_type="Minutes",
        case_id=None,
    ):
        # arrange
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mock_response.content = "TEST_EXC"
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )

        # act
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        with pytest.raises(Exception) as excinfo:
            siemplify.set_case_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
            )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "sla",
            ),
            json=request,
        )

        assert isinstance(excinfo.value, Exception)
        assert "TEST_EXC" in str(excinfo.value)

    def test_set_case_sla_response_custom_exception_http_error(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=1,
        critical_period_type="Minutes",
        case_id="1",
    ):
        # arrange
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "404: Not Found",
        )
        mocker.patch("json.loads", return_value={"errors": {"TEST": "Invalid request"}})

        # act
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        with pytest.raises(Exception) as excinfo:
            siemplify.set_case_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
            )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "sla",
            ),
            json=request,
        )

        assert isinstance(excinfo.value, Exception)
        assert "." in str(excinfo.value)

    def test_set_alert_sla_response_raise_exception_period_type(
        self,
        mocker,
        period_time=1,
        period_type="1",
        critical_period_time=None,
        critical_period_type=None,
        case_id=None,
        alert_identifier="1",
    ):
        # arrange
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.set_alert_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
                alert_identifier,
            )

        # assert
        assert "SLA period type is invalid" in str(excinfo.value)

    def test_set_alert_sla_response_raise_exception_critical_period_type(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=None,
        critical_period_type="1",
        case_id=None,
        alert_identifier="1",
    ):
        # arrange
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        with pytest.raises(Exception) as excinfo:
            siemplify.set_alert_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
                alert_identifier,
            )

        # assert
        assert "SLA time to critical period" in str(excinfo.value)

    def test_set_alert_sla_response_success(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=1,
        critical_period_type="Minutes",
        case_id=None,
        alert_identifier="1",
    ):
        # arrange
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mock_response.raise_for_status.return_value = 200
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)

        # act
        siemplify.set_alert_sla(
            period_time,
            period_type,
            critical_period_time,
            critical_period_type,
            case_id,
            alert_identifier,
        )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}/{4}/{5}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "alerts",
                alert_identifier,
                "sla",
            ),
            json=request,
        )

    def test_set_alert_sla_response_custom_exception_http_error(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=1,
        critical_period_type="Minutes",
        case_id=None,
        alert_identifier="1",
    ):
        # arrange
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            {"errors": {"TEST": "Invalid request"}},
        )
        mocker.patch("json.loads", return_value={"errors": {"TEST": "Invalid request"}})

        # act
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        with pytest.raises(Exception) as excinfo:
            siemplify.set_alert_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
                alert_identifier,
            )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}/{4}/{5}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "alerts",
                alert_identifier,
                "sla",
            ),
            json=request,
        )

        assert isinstance(excinfo.value, Exception)
        assert "." in str(excinfo.value)

    def test_set_alert_sla_response_exception_http_error(
        self,
        mocker,
        period_time=1,
        period_type="Minutes",
        critical_period_time=1,
        critical_period_type="Minutes",
        case_id=None,
        alert_identifier="1",
    ):
        # arrange
        request = {
            "period_time": period_time,
            "period_type": period_type,
            "critical_period_time": critical_period_time,
            "critical_period_type": critical_period_type,
        }
        siemplify = Siemplify()
        mock_response = mocker.Mock()
        mock_response.content = "{'errors': {'TEST': 'Invalid request'}}"
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            {"errors": {"TEST": "Invalid request"}},
        )

        # act
        mocker.patch.object(siemplify.session, "post", return_value=mock_response)
        with pytest.raises(Exception) as excinfo:
            siemplify.set_alert_sla(
                period_time,
                period_type,
                critical_period_time,
                critical_period_type,
                case_id,
                alert_identifier,
            )

        # assert
        siemplify.session.post.assert_called_with(
            "{0}/{1}/{2}/{3}/{4}/{5}?format=snake".format(
                siemplify.API_ROOT,
                "external/v1/sdk/cases",
                case_id,
                "alerts",
                alert_identifier,
                "sla",
            ),
            json=request,
        )

        assert isinstance(excinfo.value, Exception)
        assert "Invalid request" in str(excinfo.value)
