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

import uuid
from typing import TYPE_CHECKING

from soar_sdk.SiemplifyJob import SiemplifyJob
from soar_sdk.SiemplifyUtils import is_python_37

if TYPE_CHECKING:
    import unittest.mock


def _create_siemplify_job(mocker: unittest.mock.Mock) -> SiemplifyJob:
    raw_context_data_with_bom = b'{"parameters": ""}'  # With BOM
    # Mock sys.stdin.buffer.read using patch
    if is_python_37():
        mocker.patch("sys.stdin.buffer.read", return_value=raw_context_data_with_bom)
    else:
        mocker.patch("sys.stdin.read", return_value=raw_context_data_with_bom)

    return SiemplifyJob()


class TestSiemplifyJob:
    def test_set_configuration_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        configuration_identifier = str(uuid.uuid4())
        property_name = "propertyName"
        property_value = "propertyValue"
        expected_body = {"property_value": property_value}
        expected_address = "{0}/{1}/{2}/{3}/{4}?format=snake".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/configuration",
            configuration_identifier,
            "properties",
            property_name,
        )
        mocker.patch.object(siemplify_job.session, "put", return_value=mock_response)

        # act
        result = siemplify_job.set_configuration_property(
            configuration_identifier,
            property_name,
            property_value,
        )

        # assert the correct API address is called
        siemplify_job.session.put.assert_called_with(
            expected_address,
            json=expected_body,
        )
        assert result is mock_response.json.return_value

    def test_set_configuration_property_remote_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        siemplify_job.is_remote = True

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        configuration_identifier = str(uuid.uuid4())
        property_name = "propertyName"
        property_value = "propertyValue"
        expected_body = {"property_value": property_value}
        expected_address = "{0}/{1}/{2}/{3}/{4}?format=snake".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/configuration",
            configuration_identifier,
            "properties",
            property_name,
        )
        mocker.patch.object(siemplify_job.session, "put", return_value=mock_response)

        # act
        result = siemplify_job.set_configuration_property(
            configuration_identifier,
            property_name,
            property_value,
        )

        # assert the correct API address is called
        siemplify_job.session.put.assert_called_with(
            expected_address,
            json=expected_body,
        )
        assert result is mock_response.json.return_value

    def test_set_connector_parameter_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        connector_instance_identifier = "name_" + str(uuid.uuid4())
        parameter_name = "ParameterName"
        parameter_value = "ParameterValue"
        expected_body = {"parameter_value": parameter_value}
        expected_address = "{0}/{1}/{2}/{3}/{4}?format=snake".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/connectors",
            connector_instance_identifier,
            "parameters",
            parameter_name,
        )
        mocker.patch.object(siemplify_job.session, "put", return_value=mock_response)

        # act
        result = siemplify_job.set_connector_parameter(
            connector_instance_identifier,
            parameter_name,
            parameter_value,
        )

        # assert the correct API address is called
        siemplify_job.session.put.assert_called_with(
            expected_address,
            json=expected_body,
        )
        assert result is mock_response.json.return_value

    def test_set_connector_parameter_remote_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        siemplify_job.is_remote = True

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        connector_instance_identifier = "name_" + str(uuid.uuid4())
        parameter_name = "ParameterName"
        parameter_value = "ParameterValue"
        expected_body = {"parameter_value": parameter_value}
        expected_address = "{0}/{1}/{2}/{3}/{4}?format=snake".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/connectors",
            connector_instance_identifier,
            "parameters",
            parameter_name,
        )
        mocker.patch.object(siemplify_job.session, "put", return_value=mock_response)

        # act
        result = siemplify_job.set_connector_parameter(
            connector_instance_identifier,
            parameter_name,
            parameter_value,
        )

        # assert the correct API address is called
        siemplify_job.session.put.assert_called_with(
            expected_address,
            json=expected_body,
        )
        assert result is mock_response.json.return_value

    def test_get_connector_parameters_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        connector_instance_identifier = "name_" + str(uuid.uuid4())
        expected_address = "{0}/{1}/{2}/{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/connectors",
            connector_instance_identifier,
            "parameters",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        result = siemplify_job.get_connector_parameters(connector_instance_identifier)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)
        assert result is mock_response.json.return_value

    def test_get_connector_parameters_remote_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        siemplify_job.is_remote = True

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        connector_instance_identifier = "name_" + str(uuid.uuid4())
        expected_address = "{0}/{1}/{2}/{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/connectors",
            connector_instance_identifier,
            "parameters",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        result = siemplify_job.get_connector_parameters(connector_instance_identifier)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)
        assert result is mock_response.json.return_value

    def test_send_mail_response_success(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        subject = "Test"
        message = "This is a test"
        recipients = "user@domain.com"
        attachment_file_name = "test.txt"
        attachment_content = "test"
        expected_body = {
            "subject": subject,
            "message": message,
            "recipients": recipients,
            "attachment_file_name": attachment_file_name,
            "attachment_content": attachment_content,
        }
        expected_address = "{0}/{1}{2}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/SendEmailWithAttachment",
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "post")

        # act
        siemplify_job.send_mail(
            subject,
            message,
            recipients,
            attachment_file_name,
            attachment_content,
        )

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_extract_job_param_response_failed(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        param_name = "TestParam"

        # act
        result = siemplify_job.extract_job_param(param_name)

        # assert
        assert result == None

    def test_get_faulted_connectors_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        start_unix_time = 1625086845
        end_unix_time = 1625089845
        expected_body = {
            "start_unix_time": start_unix_time,
            "end_unix_time": end_unix_time,
        }
        expected_address = "{0}/{1}{2}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetFailedConnectors",
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        result = siemplify_job.get_faulted_connectors(start_unix_time, end_unix_time)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )
        assert result is mock_response.json.return_value

    def test_get_faulted_jobs_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        number_of_hours = 7
        expected_address = "{0}/{1}/{2}{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetFailedJobs",
            number_of_hours,
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        result = siemplify_job.get_faulted_jobs(number_of_hours)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)
        assert result is mock_response.json.return_value

    def test_get_failed_etljobs_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        number_of_hours = 7
        expected_address = "{0}/{1}/{2}{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetFailedETLOperations",
            number_of_hours,
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        result = siemplify_job.get_failed_etljobs(number_of_hours)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)
        assert result is mock_response.json.return_value

    def test_get_failed_actions_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        number_of_hours = 7
        expected_address = "{0}/{1}/{2}{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetFailedActions",
            number_of_hours,
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        result = siemplify_job.get_failed_actions(number_of_hours)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)
        assert result is mock_response.json.return_value

    def test_save_publisher_logs_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        expected_body = ["test_log_1", "test_log_2", "test_log_3"]

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/AddAgentLogs?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.save_publisher_logs(expected_body)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_fetch_timestamp_response_success(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        expected_body = {"ContextType": 3, "Identifier": "", "PropertyKey": "timestamp"}

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = 1717606868990
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.fetch_timestamp()

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_save_timestamp_response_success(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        new_timestamp = 1717606868990
        expected_body = {
            "ContextType": 3,
            "Identifier": "",
            "PropertyKey": "timestamp",
            "PropertyValue": str(new_timestamp),
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = new_timestamp
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/SetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.save_timestamp(new_timestamp=new_timestamp)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_fetch_and_save_timestamp_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        new_timestamp = 1717606868990
        expected_body = {
            "ContextType": 3,
            "Identifier": "",
            "PropertyKey": "timestamp",
            "PropertyValue": str(new_timestamp),
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = new_timestamp
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/SetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.fetch_and_save_timestamp(new_timestamp=new_timestamp)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_set_scoped_job_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        property_key = "TestKey"
        property_value = "TestValues"
        expected_body = {
            "ContextType": 3,
            "Identifier": None,
            "PropertyKey": property_key,
            "PropertyValue": property_value,
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/SetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.set_scoped_job_context_property(property_key, property_value)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_get_scoped_job_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        property_key = "TestKey"
        expected_body = {
            "ContextType": 3,
            "Identifier": None,
            "PropertyKey": property_key,
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.get_scoped_job_context_property(property_key)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_try_set_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        property_key = "TestKey"
        property_value = "TestValue"
        identifier = None
        context_type = 3
        expected_body = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
            "PropertyValue": property_value,
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/TrySetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.try_set_context_property(
            context_type,
            identifier,
            property_key,
            property_value,
        )

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_set_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        property_key = "TestKey"
        property_value = "TestValue"
        identifier = None
        context_type = 3
        expected_body = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
            "PropertyValue": property_value,
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/SetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.set_context_property(
            context_type,
            identifier,
            property_key,
            property_value,
        )

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_get_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        property_key = "TestKey"
        identifier = None
        context_type = 3
        expected_body = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.get_context_property(context_type, identifier, property_key)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_set_job_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        property_key = "TestKey"
        property_value = "TestValue"
        identifier = None
        context_type = 3
        expected_body = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
            "PropertyValue": property_value,
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/SetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.set_job_context_property(identifier, property_key, property_value)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_get_job_context_property_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        property_key = "TestKey"
        identifier = None
        context_type = 3
        expected_body = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
        }

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/GetContextProperty",
        )
        mocker.patch.object(siemplify_job.session, "post", return_value=mock_response)

        # act
        siemplify_job.get_job_context_property(identifier, property_key)

        # assert the correct API address is called
        siemplify_job.session.post.assert_called_with(
            expected_address,
            json=expected_body,
        )

    def test_get_system_info_response_success(self, mocker: unittest.mock.Mock) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        start_time_unixtime_ms = 1717606868990

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}/{2}{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/SystemInfo",
            start_time_unixtime_ms,
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        siemplify_job.get_system_info(start_time_unixtime_ms)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)

    def test_get_configuration_by_provider_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        identifier = "Test"

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}/{2}{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/configuration",
            identifier,
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        siemplify_job.get_configuration_by_provider(identifier)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)

    def test_get_configuration_response_success(
        self,
        mocker: unittest.mock.Mock,
    ) -> None:
        # arrange
        siemplify_job = _create_siemplify_job(mocker)
        provider = "Test"

        # create a mock response object
        mock_response = mocker.Mock()
        mock_response.json.return_value = "return_value"
        expected_address = "{0}/{1}/{2}{3}".format(
            siemplify_job.API_ROOT,
            "external/v1/sdk/configuration",
            provider,
            "?format=snake",
        )
        mocker.patch.object(siemplify_job.session, "get", return_value=mock_response)

        # act
        siemplify_job.get_configuration(provider)

        # assert the correct API address is called
        siemplify_job.session.get.assert_called_with(expected_address)
