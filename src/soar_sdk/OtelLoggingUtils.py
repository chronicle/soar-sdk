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
import logging
import os
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from sys import stderr
from typing import Any, Sequence

import psutil
from SiemplifyUtils import get_project_id, is_package_installed

GOOGLE_LIBRARY_NAME = "google.cloud.logging"
REQUESTS_LIBRARY_NAME = "opentelemetry.instrumentation.requests"
SOAR_LABELS_BAGGAGE_KEY = "soarLabels"
TRACE_ID_FORMAT_SPECIFIER = "032x"
SPAN_ID_FORMAT_SPECIFIER = "016x"


class TraceFilter(logging.Filter):
    PROJECT_ID = get_project_id()

    def __init__(self, traceparent: str | None = None) -> None:
        self.traceparent = traceparent or ""

    def _trace_parts(self, index: int) -> str | None:
        parts = self.traceparent.split("-")
        return parts[index] if len(parts) > index else None

    @property
    def trace_id(self) -> str | None:
        return self._trace_parts(1)

    @property
    def span_id(self) -> str | None:
        return self._trace_parts(2)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if self.PROJECT_ID:
                if self.trace_id:
                    record.trace = f"projects/{self.PROJECT_ID}/traces/{self.trace_id}"
                if self.span_id:
                    record.span_id = self.span_id
        except Exception:
            pass
        return True


class MemUsageFilter(logging.Filter):
    SAMPLE_INTERVAL_SECONDS: int = 5

    def __init__(self) -> None:
        self._last_sample: datetime = datetime.min.replace(tzinfo=timezone.utc)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            now = datetime.now(timezone.utc)
            if now - self._last_sample >= timedelta(seconds=self.SAMPLE_INTERVAL_SECONDS):
                if not hasattr(record, "labels"):
                    record.labels = {}
                record.labels["pid"] = f"{os.getpid()}"
                usage = _try_get_process_memory_usage()
                if usage > 0.0:
                    record.labels.update({"mem_usage": f"{usage:.2f}%"})
                self._last_sample = now
        except Exception:
            pass

        return True


def _try_get_process_memory_usage() -> float:
    pod_memory_limit_path = "/sys/fs/cgroup/memory.max"

    try:
        with open(pod_memory_limit_path, "r") as f:
            limit_raw = f.read().strip()
        if limit_raw == "max":
            return 0.0

        pod_limit = int(limit_raw)
        process_used = psutil.Process(os.getpid()).memory_info().rss
        return round((process_used / pod_limit) * 100, 2)
    except Exception:
        return 0.0


def _load_baggage_key(baggage_key: str) -> str | None:
    try:
        from opentelemetry.baggage import get_baggage

        baggage = get_baggage(baggage_key)
        if baggage:
            return urllib.parse.unquote(baggage.strip('"').encode("utf-8"))
    except Exception as ex:
        stderr.write(
            f"{_load_baggage_key.__name__} FAILED for key '{baggage_key}': {type(ex).__name__}: {ex}"
        )
    return None


def _load_baggage_soar_labels() -> dict[str, str] | None:
    b64_soar_labels = _load_baggage_key(SOAR_LABELS_BAGGAGE_KEY)
    if b64_soar_labels:
        return {k: v for k, v in json.loads(base64.b64decode(b64_soar_labels)).items()}
    return None


def LoadOpenTelemetryBaggage(baggage: str) -> None:
    if not is_package_installed(GOOGLE_LIBRARY_NAME):
        return

    try:
        from opentelemetry.baggage import set_baggage
        from opentelemetry.context import attach

        for pair in baggage.split(","):
            if "=" in pair:
                key, val = pair.split("=", 1)
                attach(set_baggage(key.strip(), val.strip()))

    except Exception as ex:
        stderr.write(
            f"LOGGER: {LoadOpenTelemetryBaggage.__name__} FAILED: {type(ex).__name__}: {ex}. "
            f"Baggage: '{baggage}'"
        )


def LoadStructuredLogHandler(
    logger: logging.Logger,
    min_severity: int = logging.INFO,
    traceparent: str | None = None,
) -> None:
    if not is_package_installed(GOOGLE_LIBRARY_NAME):
        logger.warning(
            f"The '{GOOGLE_LIBRARY_NAME}' library is not installed. "
            "Structured GCP logging will be disabled."
        )
        return

    try:
        import google.cloud.logging_v2
        from google.cloud.logging.handlers import StructuredLogHandler

        google.cloud.logging_v2._instrumentation_emitted = True
        handler = StructuredLogHandler(labels=_load_baggage_soar_labels())
        handler.set_name(handler.__class__.__name__)
        handler.setLevel(min_severity)
        logger.addHandler(handler)
        logger.addFilter(TraceFilter(traceparent=traceparent))
        logger.addFilter(MemUsageFilter())
    except ImportError:
        logger.warning(
            f"Failed to import from '{GOOGLE_LIBRARY_NAME}', though it appears to be installed. "
            "Structured GCP logging will be disabled.",
            exc_info=True,
        )
    except Exception:
        logger.warning(
            "Failed to initialize logger handler google.cloud.logging.handlers.StructuredLogHandler. "
            "Structured GCP logging will be disabled.",
            exc_info=True,
        )


def LoadRequestsInstrumentation() -> None:
    if not is_package_installed(REQUESTS_LIBRARY_NAME):
        return

    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
        from opentelemetry.sdk.trace.export import (
            BatchSpanProcessor,
            SpanExporter,
            SpanExportResult,
        )

        project_id = get_project_id()
        soar_baggage = _load_baggage_soar_labels()

        def response_hook(span: Any, request: Any, response: Any) -> None:
            if response.content:
                span.set_attribute("http.response.body.responseSize", len(response.content))

        class GCPStructuredLogTraceExporter(SpanExporter):
            def _calc_latency(self, span: ReadableSpan) -> str:
                duration_in_seconds = (span.end_time - span.start_time) / 1e9
                return f"{duration_in_seconds:.9f}".rstrip("0").rstrip(".") + "s"

            def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
                for span in spans:
                    ctx = span.get_span_context()
                    trace_id = f"projects/{project_id}/traces/{format(ctx.trace_id, TRACE_ID_FORMAT_SPECIFIER)}"
                    span_id = format(ctx.span_id, SPAN_ID_FORMAT_SPECIFIER)

                    structured_log = {
                        "message": f"Request Trace: {span.name}",
                        "severity": "DEBUG",
                        "logging.googleapis.com/labels": soar_baggage,
                        "logging.googleapis.com/trace": trace_id,
                        "logging.googleapis.com/spanId": span_id,
                        "logging.googleapis.com/trace_sampled": True,
                        "httpRequest": {
                            "requestMethod": span.attributes.get("http.method"),
                            "requestUrl": span.attributes.get("http.url"),
                            "status": span.attributes.get("http.status_code"),
                            "userAgent": span.attributes.get("user_agent.original"),
                            "responseSize": span.attributes.get(
                                "http.response.body.responseSize",
                            ),
                            "latency": self._calc_latency(span),
                        },
                    }

                    stderr.write(json.dumps(structured_log) + "\n")

                return SpanExportResult.SUCCESS

        tracer_provider = TracerProvider()
        processor = BatchSpanProcessor(GCPStructuredLogTraceExporter())
        tracer_provider.add_span_processor(processor)
        trace.set_tracer_provider(tracer_provider)

        RequestsInstrumentor().instrument(response_hook=response_hook)
    except Exception as ex:
        stderr.write(
            f"LOGGER: {LoadRequestsInstrumentation.__name__} FAILED: {type(ex).__name__}: {ex}."
        )
