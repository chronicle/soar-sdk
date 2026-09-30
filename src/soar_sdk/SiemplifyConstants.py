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

import signal


class SiemplifyConstants:
    SIGNAL_CODES = {signal.SIGTERM: 143, signal.SIGINT: 130}
    REQUEST_CA_BUNDLE = "REQUESTS_CA_BUNDLE"
    NO_CONTENT_STATUS_CODE = 204
    DECODE_FORMAT = "utf-8-sig"
    PARAMETERS_KEY = "parameters"
    USE_ELASTIC_OPTION = "useElastic"
    LOG_PATH_OPTION = "logPath="
    LOG_PATH_NAME = "--logPath"
    DEBUG_MODE_NAME = "--debugMode"
    FEAT_SDK_RETRIES_NAME = "--featSDKRetries"
    STRUCTURED_LOGGER_NAME = "--structuredLogger"
    BAGGAGE_NAME = "--baggage"
    ALERT_LAZY_LOADING = "--alertLazyLoadingEnabled"
    ARG_OPTIONS = [
        USE_ELASTIC_OPTION,
        LOG_PATH_OPTION,
        "correlationId=",
        "traceId=",
        "baggage=",
        "onePlatformSupport",
        "dataplaneSupport",
        "filesDataplaneSupport",
        "alertLazyLoadingEnabled",
        "debugMode",
        "structuredLogger",
        "featSDKRetries",
    ]


SIGNAL_CODES = SiemplifyConstants.SIGNAL_CODES
REQUEST_CA_BUNDLE = SiemplifyConstants.REQUEST_CA_BUNDLE
NO_CONTENT_STATUS_CODE = SiemplifyConstants.NO_CONTENT_STATUS_CODE
DECODE_FORMAT = SiemplifyConstants.DECODE_FORMAT
PARAMETERS_KEY = SiemplifyConstants.PARAMETERS_KEY
USE_ELASTIC_OPTION = SiemplifyConstants.USE_ELASTIC_OPTION
LOG_PATH_OPTION = SiemplifyConstants.LOG_PATH_OPTION
LOG_PATH_NAME = SiemplifyConstants.LOG_PATH_NAME
DEBUG_MODE_NAME = SiemplifyConstants.DEBUG_MODE_NAME
FEAT_SDK_RETRIES_NAME = SiemplifyConstants.FEAT_SDK_RETRIES_NAME
STRUCTURED_LOGGER_NAME = SiemplifyConstants.STRUCTURED_LOGGER_NAME
BAGGAGE_NAME = SiemplifyConstants.BAGGAGE_NAME
ALERT_LAZY_LOADING = SiemplifyConstants.ALERT_LAZY_LOADING
ARG_OPTIONS = SiemplifyConstants.ARG_OPTIONS
X_GOOG_API_VERSION = "x-goog-api-version"
V1_ALPHA_API_VERSION = "v1alpha"
