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

import io
import os
from base64 import b64decode, b64encode
from hashlib import sha512
from typing import TYPE_CHECKING

import requests
from requests import HTTPError

from SiemplifyUtils import ENCODING_UTF_8

if TYPE_CHECKING:
    from collections.abc import Buffer, Sized

    from SiemplifyLogger import SiemplifyLogger

DEFAULT_DIRECTORY_NAME: str = "Default"
MAX_FILE_SIZE: int = 20 * 1024 * 1024  # 20MB file size limitation
AGENT_LOCAL_FILES_PATH: str = "/opt/SiemplifyAgent/LocalFiles"


class PersistentFileStorageMixin:
    def __init__(
        self,
        environment: str,
        workflow_instance_id: str,
        logger: SiemplifyLogger,
        is_remote: bool,
        file_storage_session: requests.Session,
        api_root: str,
    ):
        self.environment_name = environment
        self.workflow_instance_id = workflow_instance_id
        self.logger = logger
        self.is_remote_sdk = is_remote
        self.file_storage_session = file_storage_session
        if api_root is not None:
            if is_remote:
                self.api_root = api_root.rstrip("api/")
            else:
                self.api_root = api_root

    @staticmethod
    def _apply_hash(name: str) -> str:
        return sha512(name.encode(ENCODING_UTF_8)).hexdigest()

    @staticmethod
    def _validate_file_size(data: Sized) -> None:
        data_size_bytes = len(data)
        if data_size_bytes > MAX_FILE_SIZE:
            raise Exception(
                f"Data size ({data_size_bytes} bytes) exceeds the maximum allowed size ({MAX_FILE_SIZE} "
                "bytes).",
            )

    @staticmethod
    def _validate_response_error(response: requests.Response) -> None:
        try:
            response.raise_for_status()
        except HTTPError as e:
            raise Exception(f"{e}: {response.content}")

    def _get_destination_blob_name(self, identifier: str) -> str:
        """Constructs the item's destination path.
        The format is: <hashed-environment-name>/<hashed-workflow-instance-id>/<hashed-identifier>.
        If no workflow is provided, a default directory name should be used instead of a hash.
        """
        hashed_environment_name = self._apply_hash(self.environment_name)
        hashed_playbook_instance = (
            self._apply_hash(str(self.workflow_instance_id))
            if self.workflow_instance_id
            else DEFAULT_DIRECTORY_NAME
        )
        hashed_id = self._apply_hash(identifier)
        destination_blob_name = (
            f"{hashed_environment_name}/{hashed_playbook_instance}/{hashed_id}"
        )
        return destination_blob_name

    def _read_from_local_file(self, path: str) -> str:
        self.logger.warning("The data is going to be fetched from a local file.")
        with open(path, "rb") as f:
            data = f.read()
        return data

    def _write_to_local_file(self, path: str, data: str) -> None:
        self.logger.warning("The data is going to be saved locally.")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)

    def _get_blob(self, identifier: str, is_local: bool) -> str:
        self.logger.info(
            f"Persistent File Storage | GET | identifier: {identifier} | environment: {self.environment_name} | workflow instance id: {self.workflow_instance_id}",
        )
        destination_blob_name = self._get_destination_blob_name(identifier)
        if is_local:
            if not self.is_remote_sdk:
                raise Exception(
                    "Downloading files from the local file system is forbidden.",
                )
            data = self._read_from_local_file(
                os.path.join(AGENT_LOCAL_FILES_PATH, destination_blob_name),
            )
        else:
            data = self._get_blob_from_remote(
                self.environment_name,
                destination_blob_name,
            )
        return data

    def _set_blob(self, identifier: str, data: bytes, is_local: bool) -> None:
        self.logger.info(
            f"Persistent File Storage | SET | identifier: {identifier} | environment: {self.environment_name} | workflow instance id: {self.workflow_instance_id}",
        )
        self._validate_file_size(data)
        destination_blob_name = self._get_destination_blob_name(identifier)
        if is_local:
            if not self.is_remote_sdk:
                raise Exception(
                    "Uploading files to the local file system is forbidden.",
                )
            self._write_to_local_file(
                os.path.join(AGENT_LOCAL_FILES_PATH, destination_blob_name),
                data,
            )
        else:
            self._set_blob_from_remote(
                self.environment_name,
                destination_blob_name,
                data,
            )

    def _get_blob_from_remote(
        self,
        environment_name: str,
        destination_blob_name: str,
    ) -> str:
        params = {
            "EnvironmentName": environment_name,
            "DestinationPath": destination_blob_name,
        }
        address = "{0}/{1}".format(self.api_root, "webhooks/blob")
        response = self.file_storage_session.get(address, params=params)
        self._validate_response_error(response)
        return response.content.decode()

    def _set_blob_from_remote(
        self,
        environment_name: str,
        destination_blob_name: str,
        data: Buffer,
    ) -> None:
        payload = {
            "EnvironmentName": environment_name,
            "DestinationPath": destination_blob_name,
        }
        data_file = io.BytesIO(data)
        files = {"Data": ("file", data_file, "application/octet-stream")}
        address = "{0}/{1}".format(self.api_root, "webhooks/blob")
        response = self.file_storage_session.post(address, data=payload, files=files)
        self._validate_response_error(response)

    #################### get saved data ###################

    def get_base64_blob(self, identifier: str, is_local: bool = False) -> str:
        return self._get_blob(identifier, is_local)

    def get_bytes_blob(self, identifier: str, is_local: bool = False) -> bytes:
        base64_data = self._get_blob(identifier, is_local)
        bytes_data = b64decode(base64_data)
        return bytes_data

    def get_string_blob(self, identifier: str, is_local: bool = False) -> str:
        bytes_data = self.get_bytes_blob(identifier, is_local)
        string_data = bytes_data.decode(ENCODING_UTF_8)
        return string_data

    ###################### save data ######################

    def set_base64_blob(
        self,
        identifier: str,
        data: bytes,
        is_local: bool = False,
    ) -> None:
        self._set_blob(identifier, data, is_local)

    def set_bytes_blob(
        self,
        identifier: str,
        data: Buffer,
        is_local: bool = False,
    ) -> None:
        base64_data = b64encode(data)
        self._set_blob(identifier, base64_data, is_local)

    def set_string_blob(
        self,
        identifier: str,
        data: str,
        is_local: bool = False,
    ) -> None:
        bytes_data = data.encode(ENCODING_UTF_8)
        self.set_bytes_blob(identifier, bytes_data, is_local)
