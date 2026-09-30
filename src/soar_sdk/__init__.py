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

import sys
from pathlib import Path

_sdk_path = str(Path(__file__).parent.resolve())
if _sdk_path not in sys.path:
    sys.path.insert(0, _sdk_path)

_MODULE_NAMES: list[str] = [
    "SiemplifyConstants",
    "SiemplifyUtils",
    "SiemplifyLogger",
    "SiemplifySdkConfig",
    "CaseAlertsProvider",
    "EnvironmentData",
    "GcpTokenProvider",
    "OtelLoggingUtils",
    "PersistentFileStorageMixin",
    "ScriptResult",
    "SDKRetryPolicy",
    "SiemplifyBaseDataModel",
    "SiemplifyConnectorsDataModel",
    "SiemplifyCaseWallDataModel",
    "SiemplifyDataModel",
    "SiemplifyAddressProvider",
    "CaseAlertsProvider",
    "SiemplifyBase",
    "Siemplify",
    "SiemplifyExtensionTypesBase",
    "SiemplifyConnectors",
    "SiemplifyJob",
    "SiemplifyAction",
    "SiemplifyLogicalOperator",
    "SiemplifyPublisherUtils",
    "SiemplifyTransformer",
    "SiemplifyVaultUtils",
]

for _name in _MODULE_NAMES:
    try:
        _mod = __import__(f"soar_sdk.{_name}", fromlist=[_name])
        sys.modules[_name] = _mod
    except ImportError:
        pass
