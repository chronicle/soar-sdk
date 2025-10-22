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

from SiemplifyExtensionTypesBase import SiemplifyExtensionTypesBase


class SiemplifyTransformer(SiemplifyExtensionTypesBase):
    """The SiemplifyTransformer class is used to transform execution."""

    TRANSFORMER_INPUT_PARAMETER_NAME = "input"

    def __init__(self, mock_stdin: str | None = None) -> None:
        super().__init__(mock_stdin)

    def extract_param(
        self,
        param_name: str,
        default_value: Any | None = None,
        input_type: type = str,
        is_mandatory: bool = False,
        print_value: bool = True,
    ) -> Any:
        parameter_value = super().extract_param(
            param_name,
            default_value,
            input_type,
            is_mandatory,
            print_value,
        )
        return self.handle_input_serialization(param_name, parameter_value)

    def handle_input_serialization(self, param_name: str, param_value: str) -> Any:
        if param_name == self.TRANSFORMER_INPUT_PARAMETER_NAME:
            param_value = json.loads(param_value)
        return param_value
