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

from typing import TYPE_CHECKING, Any

from urllib3.util.retry import Retry

if TYPE_CHECKING:
    import SiemplifyLogger

DEFAULT_LABELS = {"module": "RemotePythonExecutorProxy"}
HAS_ALLOWED_METHODS = hasattr(Retry, "DEFAULT_ALLOWED_METHODS")


class SDKRetryPolicy(Retry):
    def __init__(self, logger: SiemplifyLogger.SiemplifyLogger, **kwargs: Any) -> None:
        self.logger = logger

        # Enforce our specific SDK retry defaults if not overridden by urllib3 cloning
        kwargs.setdefault("total", 3)  # Total retries to allow (4 attempts total)
        kwargs.setdefault("status_forcelist", [502, 503, 504])
        kwargs.setdefault("backoff_factor", 5)

        if HAS_ALLOWED_METHODS:
            kwargs.setdefault("allowed_methods", ["GET", "POST", "PUT", "DELETE"])
        else:
            kwargs.setdefault("method_whitelist", ["GET", "POST", "PUT", "DELETE"])

        super(SDKRetryPolicy, self).__init__(**kwargs)

    def new(self, **kw: Any) -> SDKRetryPolicy:
        kw["logger"] = self.logger
        return super(SDKRetryPolicy, self).new(**kw)

    def increment(
        self,
        method: str | None = None,
        url: str | None = None,
        response: Any | None = None,
        error: Any | None = None,
        _pool: Any | None = None,
        _stacktrace: Any | None = None,
    ) -> Retry:
        try:
            new_retry = super(SDKRetryPolicy, self).increment(
                method,
                url,
                response,
                error,
                _pool,
                _stacktrace,
            )

            failed_attempt = len(new_retry.history or [])
            delay = new_retry.get_backoff_time()
            reason = f"Status code: {response.status}" if response else str(error)

            self.logger.warn(
                "RETRY_HTTP_REQUEST: Attempt {0} failed due to bad request status: {1}. Waiting {2}s to retry.".format(
                    failed_attempt,
                    reason,
                    delay,
                ),
                labels=DEFAULT_LABELS,
            )

            return new_retry

        except Exception:
            self.logger.error(
                "SDK HTTP request exhausted all retries for path: {0}".format(url),
                labels=DEFAULT_LABELS,
            )
            raise
