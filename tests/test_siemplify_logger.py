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

import io

import soar_sdk.SiemplifyLogger
import soar_sdk.SiemplifyUtils


def test_version_safe_exception_prints_traceback():
    # type: () -> None
    error_message = "__ExceptionMessage__"

    if not soar_sdk.SiemplifyUtils.is_python_37():  # Assert python 2 doesn't fail unexpectedly
        raise_error_and_log_exception_tb(error_message)
        return

    from unittest.mock import patch

    with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
        raise_error_and_log_exception_tb(error_message)
        output = mock_stdout.getvalue()

        assert error_message in output
        assert __file__ in output


def raise_error_and_log_exception_tb(error_message):
    # type: (str) -> None
    try:
        raise ValueError(error_message)
    except ValueError as e:
        soar_sdk.SiemplifyLogger.version_safe_print_exception(e)
