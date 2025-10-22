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

import getopt
import json
import os
import shutil
import signal
import sys
import tempfile
import uuid
from typing import Any

import SiemplifyLogger
import SiemplifyUtils
from ScriptResult import EXECUTION_STATE_COMPLETED, ScriptResult
from SiemplifyConstants import SiemplifyConstants

# CONSTS
LOG_LOCATION = "SDK_Transformers"

SiemplifyUtils.override_stdout()


class SiemplifyExtensionTypesBase:
    def __init__(self, mock_stdin: str | None = None) -> None:
        if mock_stdin is not None:
            self.context_data = json.loads(mock_stdin)
        else:
            raw_context = self.get_script_context()
            self.context_data = json.loads(raw_context.decode(SiemplifyConstants.DECODE_FORMAT))

        self._result: ScriptResult = ScriptResult([])
        self.parameters: dict[str, Any] = self.context_data.get(SiemplifyConstants.PARAMETERS_KEY)
        self._logger: SiemplifyLogger.SiemplifyLogger | None = None
        self._logs_collector: Any | None = None
        self._log_path: str | None = None
        self.temp_folder_path: str | None = None
        options, _ = getopt.gnu_getopt(sys.argv[1:], "", SiemplifyConstants.ARG_OPTIONS)

        signal.signal(signal.SIGTERM, self.termination_signal_handler)
        signal.signal(signal.SIGINT, self.cancellation_signal_handler)

        for name, value in options:
            if name == SiemplifyConstants.LOG_PATH_NAME:
                self._log_path = value.strip('"')

    @property
    def result(self) -> ScriptResult:
        return self._result

    @property
    def LOGGER(self) -> SiemplifyLogger.SiemplifyLogger:
        if not self._logger:
            self._logger = SiemplifyLogger.SiemplifyLogger(
                self._log_path,
                log_location=self.log_location,
                logs_collector=self._logs_collector,
            )
        return self._logger

    @property
    def log_location(self) -> str:
        return LOG_LOCATION

    @staticmethod
    def get_script_context() -> bytes:
        return sys.stdin.buffer.read()

    def termination_signal_handler(self, sig: int, _: Any) -> None:
        self.LOGGER.warn(f"Termination signal [{sig}] received, exiting...")
        sys.exit(-SiemplifyConstants.SIGNAL_CODES[sig])

    def cancellation_signal_handler(self, sig: int, _: Any) -> None:
        self.LOGGER.warn(
            f"Cancellation signal [{sig}] received, ignoring to finish execution gracefully.",
        )

    def extract_param(
        self,
        param_name: str,
        default_value: Any | None = None,
        input_type: type = str,
        is_mandatory: bool = False,
        print_value: bool = True,
    ) -> Any:
        return SiemplifyUtils.extract_script_param(
            siemplify=self,
            input_dictionary=self.parameters,
            param_name=param_name,
            default_value=default_value,
            input_type=input_type,
            is_mandatory=is_mandatory,
            print_value=print_value,
        )

    def end(self, result_value: Any) -> None:
        self.result.result_value = json.dumps(result_value)
        self.result.execution_state = EXECUTION_STATE_COMPLETED
        self.remove_temp_folder()
        self.end_script()

    def get_temp_folder_path(self) -> str:
        if not self.temp_folder_path:
            self.temp_folder_path = tempfile.mkdtemp(suffix=str(uuid.uuid4()))
        return self.temp_folder_path

    def remove_temp_folder(self) -> None:
        if self.temp_folder_path and os.path.exists(self.temp_folder_path):
            shutil.rmtree(self.temp_folder_path)

    def end_script(self) -> None:
        output_object = self._build_output_object()
        SiemplifyUtils.real_stdout.write(json.dumps(output_object))
        SiemplifyUtils.real_stdout.flush()
        sys.exit(0)

    def _build_output_object(self) -> dict[str, Any]:
        output_object = {
            "Message": self.result.message,
            "ResultObjectJson": None,
            "ResultValue": self.result.result_value,
            "DebugOutput": SiemplifyUtils.my_stdout.getvalue(),
            "ExecutionState": self.result.execution_state,
        }
        return output_object
