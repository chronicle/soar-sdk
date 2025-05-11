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
import datetime
import getopt
import json
import os
import signal
import sys
from typing import Any
from urllib.parse import urlparse

import requests
import SiemplifyLogger
import SiemplifyUtils
from GcpTokenProvider import GcpTokenProvider
from SiemplifyAddressProvider import SiemplifyAddressProvider
from SiemplifyPublisherUtils import SiemplifySession
from SiemplifySdkConfig import SiemplifySdkConfig

HEADERS: dict[str, str] = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}
REQUEST_CA_BUNDLE: str = "REQUESTS_CA_BUNDLE"
NO_CONTENT_STATUS_CODE: int = 204


class SiemplifyBase:
    TIMESTAMP_KEY: str = "timestamp"
    SIGNAL_CODES: dict[int, int] = {signal.SIGTERM: 143, signal.SIGINT: 130}

    def __init__(self, is_connector: bool = False):
        self.api_key: str | None = None
        self.sdk_config: SiemplifySdkConfig = SiemplifySdkConfig()
        self.RUN_FOLDER: str = self.sdk_config.run_folder_path
        self.script_name: str = ""
        self._logger: SiemplifyLogger.SiemplifyLogger | None = None
        self._logs_collector: SiemplifyLogger.FileLogsCollector | None = None
        self._log_path: str | None = None
        self.API_ROOT: str = self.sdk_config.api_root_uri
        self.FILE_STORAGE_API_ROOT: str = self.sdk_config.file_storage_api_root_uri
        self.FILE_SYSTEM_CONTEXT_PATH: str = os.path.join(
            self.RUN_FOLDER,
            "context_file.json",
        )
        self.is_locally_scheduled_remote_connector: bool = False
        self._one_platform_support: bool = False

        options, _ = getopt.gnu_getopt(
            sys.argv[1:],
            "",
            [
                "useElastic",
                "logPath=",
                "correlationId=",
                "traceId=",
                "baggage=",
                "onePlatformSupport",
            ],
        )

        signal.signal(signal.SIGTERM, self.termination_signal_handler)
        signal.signal(signal.SIGINT, self.cancellation_signal_handler)

        for name, value in options:
            if name == "--logPath":
                self._log_path = value.strip('"')
            elif name == "--correlationId":
                HEADERS.update({"correlation_id": value.strip('"')})
            elif name == "--traceId":
                HEADERS.update({"traceparent": value.strip('"')})
            elif name == "--baggage":
                HEADERS.update(
                    {
                        "baggage": base64.b64decode(
                            value.strip('"').encode("utf-8"),
                        ).decode("utf-8"),
                    },
                )
            elif name == "--onePlatformSupport":
                self._one_platform_support = True

        if not self.sdk_config.is_remote_publisher_sdk:
            # Checking Environment Variables
            # For action runs we get api key as first param, for connectors we get
            # api key as second param and isTest as first param
            if is_connector:
                self.api_key = sys.argv[2]
            else:
                self.api_key = sys.argv[1]
            if REQUEST_CA_BUNDLE in os.environ:
                if self.sdk_config.ignore_ca_bundle:
                    del os.environ[REQUEST_CA_BUNDLE]
                else:
                    self.LOGGER.warning(
                        f"Environment Variables cannot contain key {REQUEST_CA_BUNDLE}, please remove "
                        "it.",
                    )

            # Create regular session
            self.session = self.create_session(self.api_key, HEADERS)

            # Create file storage session
            self.file_storage_session = self.create_session(self.api_key)

        else:
            # Create custom Session
            # Publisher mode not send the requests
            self.session = SiemplifySession()
            # File storage is intentionally not initialized here
            # Initialization occurs in SiemlifyAction
            self.file_storage_session = None

        self.address_provider = SiemplifyAddressProvider(
            self.sdk_config,
            self._one_platform_support,
        )
        if self.sdk_config.gcp_auth_required:
            GcpTokenProvider.add_gcp_token(self)

    def _init_remote_session(self, key: str) -> None:
        self.api_key = key
        self.remote_agent_proxy: str | None = os.environ.get("PROXY_ADDRESS")
        self.session = self._create_remote_session(self.api_key, HEADERS)

    def _create_remote_session(self, key: str, headers: dict = {}) -> requests.Session:
        """Create a remote requests session to be used from the Agent
        :param key: API key for remote calls
        :param headers: headers to use when initializing the session
        :return: siemplify remote session
        """
        session = requests.Session()
        if self.remote_agent_proxy:
            self.LOGGER.info("SDK session is set with proxy")
            session.proxies = {
                "http": self.remote_agent_proxy,
                "https": self.remote_agent_proxy,
            }
        session.verify = (
            str(os.environ.get("VERIFY_SSL", True)).lower() == str(True).lower()
        )
        self.LOGGER.info(f"SDK session verify ssl is {self.session.verify}")
        headers.update({"AppKey": key})
        session.headers.update(headers)
        return session

    @property
    def platform_url(self) -> str:
        """Returns the URL to the instance"""
        if not self.sdk_config.is_remote_publisher_sdk:
            platfrom_url = os.environ.get("CLIENT_ADDRESS", None)
            if not platfrom_url:
                raise Exception("Environment CLIENT_ADDRESS not found")
        else:
            platfrom_url = self.sdk_config.api_root_uri
            print(platfrom_url)
            if not platfrom_url:
                raise Exception("Environment SERVER_API_ROOT not found or malformed")

        if not platfrom_url.startswith("http"):
            platfrom_url = "https://" + platfrom_url

        parsed = urlparse(platfrom_url)
        return f"{parsed.scheme}://{parsed.netloc}/"

    @property
    def run_folder(self) -> str:
        r"""Build run_folder base on script name
        :return: {string} full path (e.g.
        C:\Siemplify_Server\Scripting\SiemplifyAction\<script name>)
        """
        path = os.path.join(self.RUN_FOLDER, self.__class__.__name__)

        if not self.script_name:
            raise Exception(
                "Cannot build run_folder when script_name has not been defined first. "
                "Try addind: siemplify.script_name='name'",
            )

        path = os.path.join(path, self.script_name)

        if not os.path.exists(path):
            os.makedirs(path)

        return path

    @property
    def log_location(self) -> str:
        return "smp_python"

    @property
    def LOGGER(self) -> SiemplifyLogger.SiemplifyLogger:
        if not self._logger:
            self._logger = SiemplifyLogger.SiemplifyLogger(
                self._log_path,
                log_location=self.log_location,
                logs_collector=self._logs_collector,
            )

        return self._logger

    @staticmethod
    def validate_siemplify_error(response: requests.Response) -> None:
        """Validate error
        :param response: {response}
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise Exception(f"{e}: {response.content}")

    @staticmethod
    def create_session(app_key: str, headers: dict = {}) -> requests.Session:
        """Create default siemplify requests session
        :param app_key: the SDK app key
        :param headers: headers to use when initializing the session
        :return: siemplify session
        """
        session = requests.Session()
        session.verify = False
        headers.update({"AppKey": app_key})
        session.headers.update(headers)
        return session

    def set_logs_collector(
        self,
        logs_collector: SiemplifyLogger.FileLogsCollector | None,
    ) -> None:
        self._logs_collector = logs_collector

    def fetch_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool | str = False,
        context_type: int | None = None,
        identifier: str | None = None,
    ) -> int | datetime.datetime:
        """Get timestamp
        :param datetime_format: {boolean} if datetime - return timestamp as datetime
        :param timezone: NOT SUPPORTED anymore!
        :return: {unix time/ datetime}
        """
        last_run_time = 0
        try:
            last_run_time = self.get_context_property(
                context_type,
                identifier,
                self.TIMESTAMP_KEY,
            )
        except Exception as e:
            raise Exception(f"Failed reading timestamps from db, ERROR: {e}")
        if last_run_time == None:
            last_run_time = 0
        try:
            last_run_time = int(last_run_time)
        except:
            last_run_time = SiemplifyUtils.convert_string_to_unix_time(last_run_time)

        if datetime_format:
            last_run_time = SiemplifyUtils.convert_unixtime_to_datetime(last_run_time)

            # SiemplifyUtils.convert_timezone is unsupported for DST, so was removed
            if timezone:
                last_run_time = SiemplifyUtils.convert_timezone(last_run_time, timezone)
        else:
            last_run_time = int(last_run_time)

        return last_run_time

    def save_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool | str = False,
        new_timestamp: int | datetime.datetime = SiemplifyUtils.unix_now(),
        context_type: int | None = None,
        identifier: str | None = None,
    ) -> None:
        """Save timestamp
        :param datetime_format: {boolean} if datetime - return timestamp as datetime
        :param timezone:  NOT SUPPORTED anymore!
        :param new_timestamp: {long} unix time
        """
        if isinstance(new_timestamp, datetime.datetime):
            new_timestamp = SiemplifyUtils.convert_datetime_to_unix_time(new_timestamp)

        try:
            self.set_context_property(
                context_type,
                identifier,
                self.TIMESTAMP_KEY,
                json.dumps(new_timestamp),
            )
        except Exception as e:
            raise Exception(f"Failed saving timestamps to db, ERROR: {e}")

    def fetch_and_save_timestamp(
        self,
        datetime_format: bool = False,
        timezone: bool | str = False,
        new_timestamp: int | datetime.datetime = SiemplifyUtils.unix_now(),
        context_type: int | None = None,
        identifier: str | None = None,
    ) -> int | datetime.datetime:
        """Fetach and save timestamp
        :param datetime_format: {boolean} if datetime - return timestamp as datetime
        :param timezone: NOT SUPPORTED anymore!
        :param new_timestamp: {long} unix time
        :return: {unix time/ datetime}
        """
        # This function is not in use anymore
        last_run_time = self.fetch_timestamp(
            context_type,
            identifier,
            datetime_format,
            timezone,
        )
        self.save_timestamp(
            context_type,
            identifier,
            datetime_format,
            timezone,
            new_timestamp,
        )
        return last_run_time

    def set_context_property(
        self,
        context_type: int | None,
        identifier: str | None,
        property_key: str,
        property_value: str | float | bool | dict | list | None,
    ) -> bool | None:
        """Set context property
        :param context_type: {int} ContextKeyValueEnum
        :param identifier: {string} identifier
        :param property_key: {string} property key
        :param property_value: {object} property value
        """
        if not SiemplifyUtils.validate_property_value(property_value):
            raise MaximumContextLengthException(
                "Exception was thrown in set_context_property: property value has "
                "reached maximum length",
            )

        if (
            not self.sdk_config.is_remote_publisher_sdk
            or self.is_locally_scheduled_remote_connector
        ):
            # Write to DB
            self.set_context_property_in_server(
                context_type,
                identifier,
                property_key,
                property_value,
            )

        else:  # Write to FS
            try:
                try:
                    with open(self.FILE_SYSTEM_CONTEXT_PATH, "r+") as context_file:
                        json_decoded = json.loads(context_file.read())
                except Exception as e:
                    self.LOGGER.error(
                        f"Exception was thrown in set_context_property: {e}",
                    )
                    json_decoded = {}

                json_decoded[property_key] = property_value

                with open(self.FILE_SYSTEM_CONTEXT_PATH, "w") as json_file:
                    json.dump(json_decoded, json_file)

            except Exception as e:
                self.LOGGER.error(
                    f"Exception was thrown in set_context_property: {e}",
                )
                raise Exception(
                    f"Exception was thrown in set_context_property: {e}",
                )
            return True

    def set_context_property_in_server(
        self,
        context_type: int | None,
        identifier: str | None,
        property_key: str,
        property_value: str | float | bool | dict | list | None,
    ) -> None:
        request_dict = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
            "PropertyValue": property_value,
        }
        address = self.address_provider.provide_set_context_property_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)

    def try_set_context_property(
        self,
        context_type: int | None,
        identifier: str | None,
        property_key: str,
        property_value: str | float | bool | dict | list | None,
    ) -> bool | bytes:
        """Try set context property
        :param context_type: {int} ContextKeyValueEnum
        :param identifier: {string} identifier
        :param property_key: {string} property key
        :param property_value: {object} property value
        """
        if not SiemplifyUtils.validate_property_value(property_value):
            raise MaximumContextLengthException(
                "Exception was thrown in try_set_context_property: property value has "
                "reached maximum length",
            )

        if (
            not self.sdk_config.is_remote_publisher_sdk
            or self.is_locally_scheduled_remote_connector
        ):  # Write to DB
            return self.try_set_context_property_in_server(
                context_type,
                identifier,
                property_key,
                property_value,
            )

        # Write to FS
        try:
            try:
                with open(self.FILE_SYSTEM_CONTEXT_PATH, "r+") as context_file:
                    json_decoded = json.loads(context_file.read())
            except:
                json_decoded = {}

            json_decoded[property_key] = property_value

            with open(self.FILE_SYSTEM_CONTEXT_PATH, "w") as json_file:
                json.dump(json_decoded, json_file)

        except Exception as e:
            self.LOGGER.error(
                f"Exception was thrown in try_set_context_property: {e}",
            )
            raise Exception(
                f"Exception was thrown in try_set_context_property: {e}",
            )
        return True

    def try_set_context_property_in_server(
        self,
        context_type: int | None,
        identifier: str | None,
        property_key: str,
        property_value: str | float | bool | dict | list | None,
    ) -> bytes:
        request_dict = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
            "PropertyValue": property_value,
        }
        address = self.address_provider.provide_try_set_context_property_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        return response.content

    def get_context_property(
        self,
        context_type: int | None,
        identifier: str | None,
        property_key: str,
    ) -> Any:
        if (
            not self.sdk_config.is_remote_publisher_sdk
            or self.is_locally_scheduled_remote_connector
        ):
            return self.get_context_property_from_server(
                context_type,
                identifier,
                property_key,
            )
        # read from FS
        try:
            with open(self.FILE_SYSTEM_CONTEXT_PATH, "r+") as context_file:
                context = json.loads(context_file.read())
        except Exception as e:
            self.LOGGER.error(
                f"Exception was thrown in get_context_property: {e}",
            )
            context = {}
        return context.get(property_key)

    def get_context_property_from_server(
        self,
        context_type: int | None,
        identifier: str | None,
        property_key: str,
    ) -> Any:
        # read from DB
        request_dict = {
            "ContextType": context_type,
            "Identifier": identifier,
            "PropertyKey": property_key,
        }
        address = self.address_provider.provide_get_context_property_address()
        response = self.session.post(address, json=request_dict)
        self.validate_siemplify_error(response)
        if response.status_code == NO_CONTENT_STATUS_CODE:
            self.LOGGER.info(f"No data found for property key: {property_key}")
            return None
        return response.json()

    @staticmethod
    def get_script_context() -> str | bytes:
        """Retrieve the script context from stdin, handling Python version differences.

        Returns:
            The content of `sys.stdin`

        """
        if SiemplifyUtils.is_python_37():
            return sys.stdin.buffer.read()

        return sys.stdin.read()

    def termination_signal_handler(self, sig: int, _: Any) -> None:
        self.LOGGER.warning(f"Termination signal [{sig}] received, exiting...")
        sys.exit(-self.SIGNAL_CODES[sig])

    def cancellation_signal_handler(self, sig: int, _: Any) -> None:
        self.LOGGER.warning(
            f"Cancellation signal [{sig}] received, ignoring to finish execution "
            "gracefully.",
        )


class MaximumContextLengthException(Exception):
    """Custom exception for the set context method"""
