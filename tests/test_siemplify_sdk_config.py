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
from os import environ
from typing import Any

import pytest

from soar_sdk.SiemplifySdkConfig import SiemplifySdkConfig


class TestSiemplifySdkConfig:
    def test_build_remote_api_server_uri_success(self, mocker: Any) -> None:
        # arrange
        sdk_config = SiemplifySdkConfig()
        publisher_api_root = "https://this-is-server.com/pub/api"
        mocker.patch("os.environ.get", return_value=publisher_api_root)

        # act
        result = sdk_config._build_remote_api_server_uri()

        # assert
        assert result == "https://this-is-server.com/api"

    @pytest.mark.parametrize(
        "publisher_api_root",
        ["https://this-is-server.com/api", "bad_url", None],
    )
    def test_build_remote_api_server_uri_return_none(
        self, publisher_api_root: str | None, mocker: Any
    ) -> None:
        # arrange
        sdk_config = SiemplifySdkConfig()
        mocker.patch("os.environ.get", return_value=publisher_api_root)

        # act
        result = sdk_config._build_remote_api_server_uri()

        # assert
        assert result is None

    @pytest.mark.parametrize(
        "use_ssl, host, port, uri",
        [
            ("True", "this-is-server.com", "443", "https://this-is-server.com:443/api"),
            (
                "False",
                "this-is-server.com",
                "8080",
                "http://this-is-server.com:8080/api",
            ),
        ],
    )
    def test_build_api_server_uri_success(
        self, use_ssl: str, host: str, port: str, uri: str, mocker: Any
    ) -> None:
        # arrange
        sdk_config = SiemplifySdkConfig()
        mock_dict = {"APP_USE_SSL": use_ssl, "APP_IP": host, "APP_PORT": port}
        mocker.patch.dict(environ, mock_dict)

        # act
        result = sdk_config._build_api_server_uri()

        # assert
        assert result == uri

    def test_build_api_server_uri_fallbacks(self) -> None:
        # arrange
        sdk_config = SiemplifySdkConfig()
        # empty config
        sdk_config._config = configparser.ConfigParser()
        # act
        result = sdk_config._build_api_server_uri()

        # assert
        assert result in ("https://127.0.0.1:8443/api", "https://localhost:8443/api")

    def test_build_api_server_uri_1p_success(self, mocker: Any) -> None:
        # arrange
        sdk_config = SiemplifySdkConfig()
        mock_dict = {
            "APP_USE_SSL": "True",
            "APP_IP": "this-is-server.com",
            "APP_PORT": "8443",
            "ONE_PLATFORM_URL_PROJECT": "myProject",
            "ONE_PLATFORM_URL_LOCATION": "myLocation",
            "ONE_PLATFORM_URL_INSTANCE": "myInstance",
        }
        mocker.patch.dict(environ, mock_dict)

        # act
        result = sdk_config._build_1p_api_server_uri_format()

        # assert
        assert (
            result
            == "https://this-is-server.com:8443/{}/projects/myProject/locations/myLocation/instances/myInstance"
        )

    def test_build_api_server_uri_1p_with_domain_success(self, mocker: Any) -> None:
        # arrange
        mock_dict = {
            "APP_USE_SSL": "True",
            "APP_IP": "this-is-server.com",
            "APP_PORT": "8443",
            "ONE_PLATFORM_URL_PROJECT": "myProject",
            "ONE_PLATFORM_URL_LOCATION": "myLocation",
            "ONE_PLATFORM_URL_INSTANCE": "myInstance",
            "ONE_PLATFORM_URL_DOMAIN": "myDomain",
        }
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig(dataplane_support=True)

        # act
        result = sdk_config._build_1p_api_server_uri_format()

        # assert
        assert (
            result
            == "https://myDomain/{}/projects/myProject/locations/myLocation/instances/myInstance"
        )

    def test_build_api_server_uri_1p_with_domain_no_dataplane_success(self, mocker: Any) -> None:
        # arrange
        mock_dict = {
            "APP_USE_SSL": "True",
            "APP_IP": "this-is-server.com",
            "APP_PORT": "8443",
            "ONE_PLATFORM_URL_PROJECT": "myProject",
            "ONE_PLATFORM_URL_LOCATION": "myLocation",
            "ONE_PLATFORM_URL_INSTANCE": "myInstance",
            "ONE_PLATFORM_URL_DOMAIN": "myDomain",
        }
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig(dataplane_support=False)

        # act
        result = sdk_config._build_1p_api_server_uri_format()

        # assert
        assert (
            result
            == "https://this-is-server.com:8443/{}/projects/myProject/locations/myLocation/instances/myInstance"
        )

    def test_gcp_auth_required_true(self, mocker: Any) -> None:
        # arrange
        mock_dict = {"ONE_PLATFORM_URL_DOMAIN": "myDomain"}
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig(True)

        # assert
        assert sdk_config.gcp_auth_required is True

    def test_gcp_auth_required_false_no_dataplane(self, mocker: Any) -> None:
        # arrange
        mock_dict = {"ONE_PLATFORM_URL_DOMAIN": "myDomain"}
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig(False)

        # assert
        assert sdk_config.gcp_auth_required is False

    def test_gcp_auth_required_false(self, mocker: Any) -> None:
        # arrange
        mock_dict = {}
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig()

        # assert
        assert sdk_config.gcp_auth_required is False

    def test_remote_gcp_auth_required_true(self, mocker: Any) -> None:
        mock_dict = {
            "ONE_PLATFORM_URL_DOMAIN": "myDomain",
            "GOOGLE_APPLICATION_CREDENTIALS": "agent_key.json",
        }
        mocker.patch.dict(environ, mock_dict)
        mocker.patch("os.path.isfile", return_value=True)
        sdk_config = SiemplifySdkConfig()

        # assert
        assert sdk_config.remote_gcp_auth_required is True

    def test_remote_gcp_auth_required_false(self, mocker: Any) -> None:
        mock_dict = {
            "ONE_PLATFORM_URL_DOMAIN": "myDomain",
            "GOOGLE_APPLICATION_CREDENTIALS": "agent_key.json",
        }
        mocker.patch.dict(environ, mock_dict)
        mocker.patch("os.path.isfile", return_value=False)
        sdk_config = SiemplifySdkConfig()

        # assert
        assert sdk_config.remote_gcp_auth_required is False

    def test_build_api_server_uri_1p_remote_no_dp_success(self, mocker: Any) -> None:
        # arrange
        mock_dict = {
            "ONE_PLATFORM_URL_PROJECT": "myProject",
            "ONE_PLATFORM_URL_LOCATION": "myLocation",
            "ONE_PLATFORM_URL_INSTANCE": "myInstance",
            "ONE_PLATFORM_URL_DOMAIN": "google.apis.com",
        }
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig()
        sdk_config.is_remote_publisher_sdk = True
        mocker.patch.object(
            SiemplifySdkConfig,
            "remote_gcp_auth_required",
            new_callable=mocker.PropertyMock,
        ).return_value = True

        # act
        result = sdk_config._build_1p_api_server_uri_format()

        # assert
        assert (
            result
            == "https://google.apis.com/{}/projects/myProject/locations/myLocation/instances/myInstance"
        )

    def test_build_api_server_uri_1p_remote_no_dp_no_gcp_auth_success(self, mocker: Any) -> None:
        # arrange
        sdk_config = SiemplifySdkConfig()
        mock_dict = {
            "ONE_PLATFORM_URL_PROJECT": "myProject",
            "ONE_PLATFORM_URL_LOCATION": "myLocation",
            "ONE_PLATFORM_URL_INSTANCE": "myInstance",
            "ONE_PLATFORM_URL_DOMAIN": "google.apis.com",
            "SERVER_API_ROOT": "https://myXlb.com/pub/api",
        }
        mocker.patch.dict(environ, mock_dict)
        sdk_config.is_remote_publisher_sdk = True
        mocker.patch.object(
            SiemplifySdkConfig,
            "remote_gcp_auth_required",
            new_callable=mocker.PropertyMock,
        ).return_value = False

        # act
        result = sdk_config._build_1p_api_server_uri_format()

        # assert
        assert (
            result
            == "https://myXlb.com/{}/projects/myProject/locations/myLocation/instances/myInstance"
        )

    def test_resource_path_uses_env_variables(self, mocker: Any) -> None:
        # arrange
        sdk_config = SiemplifySdkConfig()
        mock_dict = {
            "ONE_PLATFORM_URL_PROJECT": "env_project",
            "ONE_PLATFORM_URL_LOCATION": "env_location",
            "ONE_PLATFORM_URL_INSTANCE": "env_instance",
        }
        mocker.patch.dict(environ, mock_dict)

        # act
        result = sdk_config._resource_path

        # assert
        assert result == "/projects/env_project/locations/env_location/instances/env_instance"

    def test_resource_path_falls_back_to_config(self, mocker: Any) -> None:
        # arrange
        mocker.patch.dict(environ, {}, clear=True)
        sdk_config = SiemplifySdkConfig()
        sdk_config._config = configparser.ConfigParser()
        sdk_config._config.add_section("ServerService")
        sdk_config._config.set("ServerService", "Project", "cfg_project")
        sdk_config._config.set("ServerService", "Location", "cfg_location")
        sdk_config._config.set("ServerService", "Instance", "cfg_instance")

        # act
        result = sdk_config._resource_path

        # assert
        assert result == "/projects/cfg_project/locations/cfg_location/instances/cfg_instance"

    def test_resource_path_default_fallbacks(self, mocker: Any) -> None:
        # arrange
        mocker.patch.dict(environ, {}, clear=True)
        sdk_config = SiemplifySdkConfig()
        sdk_config._config = configparser.ConfigParser()

        # act
        result = sdk_config._resource_path

        # assert
        assert result == "/projects/project/locations/location/instances/instance"

    def test_one_platform_api_files_uri_format_success(self, mocker: Any) -> None:
        # arrange
        mock_dict = {
            "ONE_PLATFORM_URL_DOMAIN": "myfiles.domain.com",
            "ONE_PLATFORM_URL_PROJECT": "myProject",
            "ONE_PLATFORM_URL_LOCATION": "myLocation",
            "ONE_PLATFORM_URL_INSTANCE": "myInstance",
        }
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig()

        # act
        result = sdk_config.one_platform_api_files_uri_format

        # assert
        assert (
            result
            == "https://myfiles.domain.com/{}/v1alpha/projects/myProject/locations/myLocation/instances/myInstance"
        )
