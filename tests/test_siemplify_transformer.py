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
import pytest

from SiemplifyExtensionTypesBase import SiemplifyExtensionTypesBase, EXECUTION_STATE_COMPLETED
from SiemplifyTransformer import SiemplifyTransformer

# A base context that can be used for tests
BASE_CONTEXT = {
    "parameters": {
        "input": "myinput",
        "param1": "value1",
        "param2": "",
        "param3": None,
        "param4": "value4",
    }
}


class TestSiemplifyTransformer:
    @pytest.fixture
    def mock_stdin_context(self):
        """
        Provides a mocked stdin context as a JSON string.
        """
        return json.dumps(BASE_CONTEXT)

    def test_init(self, mock_stdin_context):
        """
        Test that the SiemplifyTransformer class initializes correctly, inheriting from SiemplifyExtensionTypesBase.
        """
        # Arrange & Act
        transformer = SiemplifyTransformer(mock_stdin=mock_stdin_context)

        # Assert
        assert isinstance(transformer, SiemplifyTransformer)
        assert isinstance(transformer, SiemplifyExtensionTypesBase)
        assert transformer.parameters == BASE_CONTEXT["parameters"]

    def test_end_method_from_base_class(self, mock_stdin_context, mocker):
        """
        Test that a SiemplifyTransformer instance can correctly use methods from its base class,
        like the end() method.
        """
        # Arrange
        transformer = SiemplifyTransformer(mock_stdin=mock_stdin_context)
        mocker.patch.object(transformer, "remove_temp_folder")
        mocker.patch.object(transformer, "end_script")

        # Act
        transformer.end("TRANSFORMED_VALUE")

        # Assert
        assert transformer.result.result_value == json.dumps("TRANSFORMED_VALUE")
        assert transformer.result.execution_state == EXECUTION_STATE_COMPLETED
        transformer.remove_temp_folder.assert_called_once()
        transformer.end_script.assert_called_once()

    def test_extract_param_from_base_class(self, mock_stdin_context, mocker):
        """
        Test that a SiemplifyTransformer instance can correctly use methods from its base class,
        like the extract_param() method.
        """
        # Arrange
        mock_extract = mocker.patch("SiemplifyUtils.extract_script_param")
        transformer = SiemplifyTransformer(mock_stdin=mock_stdin_context)

        # Act
        transformer.extract_param("param1", is_mandatory=True)

        # Assert
        mock_extract.assert_called_once_with(
            siemplify=transformer,
            input_dictionary=transformer.parameters,
            param_name="param1",
            default_value=None,
            input_type=str,
            is_mandatory=True,
            print_value=True,
        )

    @pytest.mark.parametrize(
        "param_name, param_value, expected_value",
        [
            # Case 1: The parameter is "input", its value should be deserialized
            (
                SiemplifyTransformer.TRANSFORMER_INPUT_PARAMETER_NAME,
                '{"key": "value"}',
                {"key": "value"},
            ),
            (
                SiemplifyTransformer.TRANSFORMER_INPUT_PARAMETER_NAME,
                '[1, 2, "three"]',
                [1, 2, "three"],
            ),
            # Case 2: The parameter is not "input", its value should be returned as-is
            ("another_param", "just a string", "just a string"),
            ("some_other_param", '{"key": "value"}', '{"key": "value"}'),
        ],
    )
    def test_handle_input_serialization(
        self, param_name, param_value, expected_value, mock_stdin_context
    ):
        # Arrange
        transformer = SiemplifyTransformer(mock_stdin=mock_stdin_context)

        # Act
        result = transformer.handle_input_serialization(param_name, param_value)

        # Assert
        assert result == expected_value

    def test_extract_param_deserializes_input_parameter(self, mock_stdin_context: str, mocker):
        # Arrange
        # The base class extract_param will return the raw value of the 'input' parameter,
        # which is a JSON-serialized string.
        mocked_value = json.dumps(BASE_CONTEXT["parameters"]["input"])
        mocker.patch.object(SiemplifyExtensionTypesBase, "extract_param", return_value=mocked_value)
        transformer = SiemplifyTransformer(mock_stdin=mock_stdin_context)

        # Act
        deserialized_input = transformer.extract_param(
            SiemplifyTransformer.TRANSFORMER_INPUT_PARAMETER_NAME
        )

        # Assert
        # The transformer's extract_param should deserialize the value from the base class.
        assert deserialized_input == BASE_CONTEXT["parameters"]["input"]

    def test_extract_param_does_not_deserialize_other_parameters(
        self, mock_stdin_context: str, mocker
    ):
        # Arrange
        mocked_value = BASE_CONTEXT["parameters"]["param1"]
        mocker.patch.object(SiemplifyExtensionTypesBase, "extract_param", return_value=mocked_value)
        transformer = SiemplifyTransformer(mock_stdin=mock_stdin_context)

        # Act
        regular_param_value = transformer.extract_param("param1")

        # Assert
        SiemplifyExtensionTypesBase.extract_param.assert_called_once()
        assert isinstance(regular_param_value, str)
        assert regular_param_value == mocked_value
