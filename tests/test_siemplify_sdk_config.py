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

import configparser
from os import environ

import pytest

from soar_sdk.SiemplifySdkConfig import SiemplifySdkConfig


class TestSiemplifySdkConfig:
    def test_build_remote_api_server_uri_success(self, mocker):
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
    def test_build_remote_api_server_uri_return_none(self, publisher_api_root, mocker):
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
    def test_build_api_server_uri_success(self, use_ssl, host, port, uri, mocker):
        # arrange
        sdk_config = SiemplifySdkConfig()
        mock_dict = {"APP_USE_SSL": use_ssl, "APP_IP": host, "APP_PORT": port}
        mocker.patch.dict(environ, mock_dict)

        # act
        result = sdk_config._build_api_server_uri()

        # assert
        assert result == uri

    def test_build_api_server_uri_fallbacks(self):
        # arrange
        sdk_config = SiemplifySdkConfig()
        # empty config
        sdk_config._config = configparser.ConfigParser()
        # act
        result = sdk_config._build_api_server_uri()

        # assert
        assert (
            result == "https://127.0.0.1:8443/api"
            or result == "https://localhost:8443/api"
        )

    def test_build_api_server_uri_1p_success(self, mocker):
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
            result == "https://this-is-server.com:8443/{"
            "}/projects/myProject/locations/myLocation/instances/myInstance"
        )

    def test_build_api_server_uri_1p_with_domain_success(self, mocker):
        # arrange
        sdk_config = SiemplifySdkConfig()
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

        # act
        result = sdk_config._build_1p_api_server_uri_format()

        # assert
        assert (
            result
            == "https://myDomain/{}/projects/myProject/locations/myLocation/instances"
            "/myInstance"
        )

    def test_gcp_auth_required_true(self, mocker):
        # arrange
        mock_dict = {"ONE_PLATFORM_URL_DOMAIN": "myDomain"}
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig()

        # assert
        assert sdk_config.gcp_auth_required == True

    def test_gcp_auth_required_true(self, mocker):
        # arrange
        mock_dict = {}
        mocker.patch.dict(environ, mock_dict)
        sdk_config = SiemplifySdkConfig()

        # assert
        assert sdk_config.gcp_auth_required == False
