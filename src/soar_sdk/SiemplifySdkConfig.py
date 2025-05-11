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

import configparser
from os import environ, getenv, path
from typing import Any

ONE_PLATFORM_URL_DOMAIN: str = "ONE_PLATFORM_URL_DOMAIN"
ONE_PLATFORM_URL_PROJECT: str = "ONE_PLATFORM_URL_PROJECT"
ONE_PLATFORM_URL_LOCATION: str = "ONE_PLATFORM_URL_LOCATION"
ONE_PLATFORM_URL_INSTANCE: str = "ONE_PLATFORM_URL_INSTANCE"


class SiemplifySdkConfig:
    config_file_path = path.join(path.dirname(__file__), "sdk_config.ini")

    def __init__(self) -> None:
        self._config = configparser.ConfigParser()
        self._config.read(self.config_file_path)
        self.is_remote_publisher_sdk = self._config.getboolean(
            "ExecutionConfig",
            "IsRemotePublisherSdk",
            fallback=False,
        )
        self.api_root_uri = (
            self._build_remote_api_server_uri()
            if self.is_remote_publisher_sdk
            else self._build_api_server_uri()
        )
        self.run_folder_path = self._config.get("ExecutionConfig", "runFolderPath")
        self.ignore_ca_bundle = self._config.getboolean(
            "ExecutionConfig",
            "IgnoreCaBundle",
            fallback=False,
        )
        self.file_storage_api_root_uri = (
            self.api_root_uri
            if self.is_remote_publisher_sdk
            else self._build_api_server_uri_for_remote_file_storage()
        )
        self.one_platform_api_root_uri_format = self._build_1p_api_server_uri_format()
        self.gcp_auth_required = self._gcp_auth_required()

    def _build_api_server_uri(self) -> str:
        return f"{self.__build_server_uri()}/api"

    def _build_api_server_uri_for_remote_file_storage(self) -> str:
        use_ssl_env = self._safe_cast(getenv("APP_USE_SSL"), bool)
        use_ssl = (
            use_ssl_env
            if use_ssl_env is not None
            else self._config.getboolean("ServerService", "UseSsl", fallback=True)
        )
        is_production = getenv(
            "CLIENT_ADDRESS",
        )  # when CLIENT_ADDRESS env var exists, the environment is not local
        _scheme = "https" if use_ssl else "http"
        return f"{_scheme}://webhooks" if is_production else "https://localhost:8310"

    def _build_remote_api_server_uri(self) -> str | None:
        publisher_suffix = "pub/api"
        publisher_api_root = environ.get("SERVER_API_ROOT")
        if not publisher_api_root or not publisher_api_root.endswith(publisher_suffix):
            return None
        api_root = publisher_api_root.rstrip(publisher_suffix)
        return f"{api_root}/api"

    def _build_1p_api_server_uri_format(self) -> str:
        project = getenv(
            ONE_PLATFORM_URL_PROJECT,
            self._config.get("ServerService", "Project", fallback="project"),
        )
        location = getenv(
            ONE_PLATFORM_URL_LOCATION,
            self._config.get("ServerService", "Location", fallback="location"),
        )
        instance = getenv(
            ONE_PLATFORM_URL_INSTANCE,
            self._config.get("ServerService", "Instance", fallback="instance"),
        )
        domain = getenv(ONE_PLATFORM_URL_DOMAIN)

        if domain:
            server_address = "https://" + domain
        else:
            server_address = self.__build_server_uri()

        return (
            server_address
            + "/{}"
            + f"/projects/{project}/locations/{location}/instances/{instance}"
        )

    def __build_server_uri(self) -> str:
        use_ssl_env = self._safe_cast(getenv("APP_USE_SSL"), bool)
        use_ssl = (
            use_ssl_env
            if use_ssl_env is not None
            else self._config.getboolean("ServerService", "UseSsl", fallback=True)
        )
        _scheme = "https" if use_ssl else "http"
        _host = getenv(
            "APP_IP",
            self._config.get("ServerService", "Host", fallback="localhost"),
        )
        _port = self._safe_cast(getenv("APP_PORT"), int) or self._config.getint(
            "ServerService",
            "Port",
            fallback=8443,
        )
        return f"{_scheme}://{_host}:{_port}"

    def _gcp_auth_required(self) -> bool:
        domain = getenv(ONE_PLATFORM_URL_DOMAIN)
        return domain is not None

    @staticmethod
    def _safe_cast(val: str, to_type: type, default: Any | None = None) -> Any | None:
        try:
            _val = eval(val)
            return _val if type(_val) == to_type else default
        except (ValueError, TypeError, NameError):
            return default
