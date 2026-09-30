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

import logging
from typing import Any
from unittest.mock import MagicMock, mock_open, patch

from opentelemetry.baggage import get_all, set_baggage
from opentelemetry.context import attach, detach
import pytest

from soar_sdk.OtelLoggingUtils import (
    LoadOpenTelemetryBaggage,
    LoadStructuredLogHandler,
    TraceFilter,
    _load_baggage_soar_labels,
    _try_get_process_memory_usage,
)

SOAR_LABELS = {"script_execution_id": "396cab54-850d-4541-bb20-4fae1c7e8888"}
SOAR_LABELS_BAGGAGE_KEY = "soarLabels"
BAGGAGE_SOAR_LABELS = (
    "eyJzY3JpcHRfZXhlY3V0aW9uX2lkIjoiMzk2Y2FiNTQtODUwZC00NTQxLWJiMjAtNGZhZTFjN2U4ODg4In0%3D"
)


@pytest.mark.parametrize(
    "soar_labels, expected",
    [
        (BAGGAGE_SOAR_LABELS, SOAR_LABELS),
        ("eyJoZWxsbyI6ICJ3b3JsZCJ9", {"hello": "world"}),
    ],
)
def test_load_soar_labels(soar_labels: str, expected: dict[str, str]) -> None:
    token = attach(set_baggage(SOAR_LABELS_BAGGAGE_KEY, soar_labels))
    try:
        assert _load_baggage_soar_labels() == expected
    finally:
        detach(token)


def test_load_structured_log_handler() -> None:
    root_logger = logging.getLogger()
    LoadStructuredLogHandler(root_logger)
    assert any(handler.name == "StructuredLogHandler" for handler in root_logger.handlers)


@pytest.mark.parametrize(
    "baggage, expected",
    [
        (
            "cloud_sql_tag=%7B%22Action%22%3A%22UserId%3A%205%22%2C%22Controller%22%3A8%2C%22Route%22%3A%22POST%3A%20%22%7D,"
            "soarLabels=eyJzY3JpcHRfZXhlY3V0aW9uX2lkIjoiZWMxMmViYzItNTZiYS00N2VhLTk2YzYtNTRiNDMxODkzM2RlIn0%3D",
            {
                "cloud_sql_tag": "%7B%22Action%22%3A%22UserId%3A%205%22%2C%22Controller%22%3A8%2C%22Route%22%3A%22POST%3A%20%22%7D",
                "soarLabels": "eyJzY3JpcHRfZXhlY3V0aW9uX2lkIjoiZWMxMmViYzItNTZiYS00N2VhLTk2YzYtNTRiNDMxODkzM2RlIn0%3D",
            },
        )
    ],
)
def test_load_otel_baggage(baggage: str, expected: dict[str, str]) -> None:
    LoadOpenTelemetryBaggage(baggage)
    assert get_all() == expected


@patch("psutil.Process")
def test_try_get_process_memory_usage_normal(mock_psutil_proc: MagicMock) -> None:
    mock_instance = MagicMock()
    mock_instance.memory_info.return_value.rss = 60
    mock_psutil_proc.return_value = mock_instance
    with patch("builtins.open", mock_open(read_data="100")) as mocked_file:
        result = _try_get_process_memory_usage()

        assert result == 60.0
        mocked_file.assert_called_once_with("/sys/fs/cgroup/memory.max", "r")


def test_try_get_process_memory_usage_max_limit() -> None:
    with patch("builtins.open", mock_open()) as mocked_file:
        mocked_file.side_effect = [
            mock_open(read_data="max").return_value,
        ]

        assert _try_get_process_memory_usage() == 0.0


def test_try_get_process_memory_usage_exception() -> None:
    with patch("builtins.open", side_effect=FileNotFoundError):
        assert _try_get_process_memory_usage() == 0.0


@patch.object(TraceFilter, "PROJECT_ID", "test-project")
def test_trace_filter_populates_trace_info() -> None:
    record = create_log_record()
    assert (
        TraceFilter(
            traceparent="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ).filter(record)
        is True
    )
    assert record.trace == "projects/test-project/traces/4bf92f3577b34da6a3ce929d0e0e4736"
    assert record.span_id == "00f067aa0ba902b7"


@patch.object(TraceFilter, "PROJECT_ID", "test-project")
def test_trace_filter_handles_malformed_traceparent() -> None:
    record = create_log_record()
    assert TraceFilter(traceparent="0001").filter(record) is True
    assert hasattr(record, "trace") is False


def create_log_record(
    name: str = "test_logger",
    level: int = logging.INFO,
    pathname: str = "test.py",
    lineno: int = 1,
    msg: str = "This is a test log message",
    args: tuple[Any, ...] = (),
    exc_info: Any | None = None,
) -> logging.LogRecord:
    return logging.LogRecord(
        name=name,
        level=level,
        pathname=pathname,
        lineno=lineno,
        msg=msg,
        args=args,
        exc_info=exc_info,
    )
