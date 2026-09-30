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

import base64
import json
import os
from typing import Any

import pytest

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED
from soar_sdk.SiemplifyExtensionTypesBase import SiemplifyExtensionTypesBase

# A base context that can be used for tests
BASE_CONTEXT = {
    "parameters": {
        "param1": "value1",
        "param2": "",
        "param3": None,
        "param4": "value4",
    },
}


class TestSiemplifyExtensionTypesBase:
    @pytest.fixture
    def mock_stdin_context(self) -> str:
        """Provides a mocked stdin context as a JSON string."""
        return json.dumps(BASE_CONTEXT)

    def test_init_with_mock_stdin(self, mock_stdin_context: str) -> None:
        # Arrange & Act
        base = SiemplifyExtensionTypesBase(mock_stdin=mock_stdin_context)

        # Assert
        assert base.parameters == BASE_CONTEXT["parameters"]

    @pytest.mark.parametrize(
        "cli_args, expected_attrs",
        [
            (["--logPath", "/var/log/test.log"], {"_log_path": "/var/log/test.log"}),
            (["--debugMode"], {"debug_mode": True}),
            (["--structuredLogger"], {"use_structured_logger": True}),
            (
                ["--baggage", base64.b64encode(b"key=value").decode("utf-8")],
                {"baggage": "key=value"},
            ),
        ],
    )
    def test_init_with_cli_args(
        self,
        mock_stdin_context: str,
        mocker: Any,
        cli_args: list[str],
        expected_attrs: dict[str, Any],
    ) -> None:
        # Arrange
        mocker.patch("sys.argv", ["script.py"] + cli_args)

        # Act
        base = SiemplifyExtensionTypesBase(mock_stdin=mock_stdin_context)

        # Assert
        for attr, value in expected_attrs.items():
            assert getattr(base, attr) == value

    def test_init_with_baggage_and_structured_logger(
        self,
        mock_stdin_context: str,
        mocker: Any,
    ) -> None:
        # Arrange
        mock_load_baggage = mocker.patch(
            "soar_sdk.SiemplifyExtensionTypesBase.LoadOpenTelemetryBaggage"
        )
        mocker.patch(
            "sys.argv",
            [
                "script.py",
                "--structuredLogger",
                "--baggage",
                base64.b64encode(b"key=value").decode("utf-8"),
            ],
        )

        # Act
        SiemplifyExtensionTypesBase(mock_stdin=mock_stdin_context)

        # Assert
        mock_load_baggage.assert_called_once_with("key=value")

    def test_extract_param(self, mock_stdin_context: str, mocker: Any) -> None:
        # Arrange
        mock_extract = mocker.patch("soar_sdk.SiemplifyUtils.extract_script_param")
        base = SiemplifyExtensionTypesBase(mock_stdin=mock_stdin_context)

        # Act
        base.extract_param("param1", is_mandatory=True)

        # Assert
        mock_extract.assert_called_once_with(
            siemplify=base,
            input_dictionary=base.parameters,
            param_name="param1",
            default_value=None,
            input_type=str,
            is_mandatory=True,
            print_value=True,
        )

    def test_temp_folder_management(self, mock_stdin_context: str) -> None:
        # Arrange
        base = SiemplifyExtensionTypesBase(mock_stdin=mock_stdin_context)

        # Act
        temp_path = base.get_temp_folder_path()

        # Assert
        assert os.path.exists(temp_path)

        # Act
        base.remove_temp_folder()

        # Assert
        assert not os.path.exists(temp_path)

    def test_end(self, mock_stdin_context: str, mocker: Any) -> None:
        # Arrange
        base = SiemplifyExtensionTypesBase(mock_stdin=mock_stdin_context)
        mocker.patch.object(base, "remove_temp_folder")
        mocker.patch.object(base, "end_script")

        # Act
        base.end("FINAL_RESULT")

        # Assert
        assert base.result.result_value == json.dumps("FINAL_RESULT")
        assert base.result.execution_state == EXECUTION_STATE_COMPLETED
        base.remove_temp_folder.assert_called_once()
        base.end_script.assert_called_once()

    def test_logger_property(self, mock_stdin_context: str, mocker: Any) -> None:
        # Arrange
        mock_logger_class = mocker.patch(
            "soar_sdk.SiemplifyExtensionTypesBase.SiemplifyLogger.SiemplifyLogger"
        )
        base = SiemplifyExtensionTypesBase(mock_stdin=mock_stdin_context)
        base._log_path = "/fake/log/path.log"
        base.debug_mode = True
        base.use_structured_logger = True

        # Act
        logger1 = base.LOGGER
        logger2 = base.LOGGER

        # Assert
        assert logger1 is logger2  # Check for singleton behavior within the instance
        mock_logger_class.assert_called_once_with(
            log_path=base._log_path,
            log_location=base.log_location,
            debug_mode=base.debug_mode,
            use_structured_logger=base.use_structured_logger,
        )
