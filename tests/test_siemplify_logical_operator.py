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
from typing import Any

import pytest

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED
from soar_sdk.SiemplifyExtensionTypesBase import SiemplifyExtensionTypesBase
from soar_sdk.SiemplifyLogicalOperator import SiemplifyLogicalOperator

# A base context that can be used for tests
BASE_CONTEXT = {
    "parameters": {
        SiemplifyLogicalOperator.LEFT_SIDE_PARAMETER_NAME: "value1",
        SiemplifyLogicalOperator.RIGHT_SIDE_PARAMETER_NAME: "value2",
        "param3": "value3",
    },
}


class TestSiemplifyLogicalOperator:
    @pytest.fixture
    def mock_stdin_context(self) -> str:
        """Provides a mocked stdin context as a JSON string."""
        return json.dumps(BASE_CONTEXT)

    def test_init(self, mock_stdin_context: str) -> None:
        """Test that the SiemplifyLogicalOperator class initializes correctly, inheriting from SiemplifyExtensionTypesBase."""
        # Arrange & Act
        logical_operator = SiemplifyLogicalOperator(mock_stdin=mock_stdin_context)

        # Assert
        assert isinstance(logical_operator, SiemplifyLogicalOperator)
        assert isinstance(logical_operator, SiemplifyExtensionTypesBase)
        assert logical_operator.parameters == BASE_CONTEXT["parameters"]

    def test_end_method_from_base_class(self, mock_stdin_context: str, mocker: Any) -> None:
        """Test that a SiemplifyLogicalOperator instance can correctly use methods from its base class,
        like the end() method. The result of a logical operator should be a boolean.
        """
        # Arrange
        logical_operator = SiemplifyLogicalOperator(mock_stdin=mock_stdin_context)
        mocker.patch.object(logical_operator, "remove_temp_folder")
        mocker.patch.object(logical_operator, "end_script")

        # Act
        logical_operator.end(True)

        # Assert
        assert logical_operator.result.result_value == json.dumps(True)
        assert logical_operator.result.execution_state == EXECUTION_STATE_COMPLETED
        logical_operator.remove_temp_folder.assert_called_once()
        logical_operator.end_script.assert_called_once()

    def test_extract_param_from_base_class(self, mock_stdin_context: str, mocker: Any) -> None:
        """Test that a SiemplifyLogicalOperator instance can correctly use methods from its base class,
        like the extract_param() method.
        """
        # Arrange
        mock_extract = mocker.patch("soar_sdk.SiemplifyUtils.extract_script_param")
        logical_operator = SiemplifyLogicalOperator(mock_stdin=mock_stdin_context)

        # Act
        logical_operator.extract_param("param3", is_mandatory=True)

        # Assert
        mock_extract.assert_called_once_with(
            siemplify=logical_operator,
            input_dictionary=logical_operator.parameters,
            param_name="param3",
            default_value=None,
            input_type=str,
            is_mandatory=True,
            print_value=True,
        )

    @pytest.mark.parametrize(
        "param_name",
        [
            SiemplifyLogicalOperator.LEFT_SIDE_PARAMETER_NAME,
            SiemplifyLogicalOperator.RIGHT_SIDE_PARAMETER_NAME,
        ],
    )
    def test_extract_param_deserializes(
        self, mock_stdin_context: str, mocker: Any, param_name: str
    ) -> None:
        """Test that extract_param for a logical operator deserializes a JSON string."""
        # Arrange
        original_value = BASE_CONTEXT["parameters"].get(param_name, "default")
        mocked_value = json.dumps(original_value)
        mocker.patch.object(SiemplifyExtensionTypesBase, "extract_param", return_value=mocked_value)
        logical_operator = SiemplifyLogicalOperator(mock_stdin=mock_stdin_context)

        # Act
        param_value = logical_operator.extract_param(param_name)

        # Assert
        SiemplifyExtensionTypesBase.extract_param.assert_called_once()
        assert param_value == original_value
