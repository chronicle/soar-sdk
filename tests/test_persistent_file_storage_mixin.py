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

from hashlib import sha512
import json
from typing import Any

import pytest
import requests

from soar_sdk.PersistentFileStorageMixin import PersistentFileStorageMixin
from soar_sdk.SiemplifyLogger import SiemplifyLogger

MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB file size limitation


class TestPersistentFileStorageMixin:
    def test_validate_file_size_invalid_file_size(self) -> None:
        # arrange
        persistent_file_storage_mixin = create_persistent_file_storage_mixin()
        data = b"x" * (MAX_FILE_SIZE + 1)

        # act
        with pytest.raises(Exception) as context:
            persistent_file_storage_mixin._validate_file_size(data)

        # assert
        assert (
            str(context.value)
            == f"Data size ({len(data)} bytes) exceeds the maximum allowed size ({MAX_FILE_SIZE} bytes)."
        )

    def test_validate_file_size_valid_file_size(self) -> None:
        # arrange
        persistent_file_storage_mixin = create_persistent_file_storage_mixin()
        data = b"x" * (MAX_FILE_SIZE - 1)

        # act + assert
        persistent_file_storage_mixin._validate_file_size(data)

    def test_apply_hash(self) -> None:
        # arrange
        persistent_file_storage_mixin = create_persistent_file_storage_mixin()
        test_param = "test test"
        expected_hash = sha512(test_param.encode("utf-8")).hexdigest()

        # act
        result = persistent_file_storage_mixin._apply_hash(test_param)

        # assert
        assert result == expected_hash

    def test_get_blob_from_remote(self, mocker: Any) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.content = b"some_blob_data"
        expected_result = "some_blob_data"
        environment_name = "environment_name"
        destination_blob_name = "destination_blob_name"
        mocker.patch.object(mock_response, "raise_for_status")

        persistent_file_storage_mixin = create_persistent_file_storage_mixin()
        mocker.patch.object(
            persistent_file_storage_mixin.file_storage_session, "get", return_value=mock_response
        )

        # act
        result = persistent_file_storage_mixin._get_blob_from_remote(
            environment_name, destination_blob_name
        )

        # assert
        expected_url = f"{persistent_file_storage_mixin.api_root}/webhooks/blob"
        persistent_file_storage_mixin.file_storage_session.get.assert_called_once_with(
            expected_url,
            params={
                "EnvironmentName": environment_name,
                "DestinationPath": destination_blob_name,
            },
        )
        assert result == expected_result

    def test_set_blob_from_remote(self, mocker: Any) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.content = b"some_blob_data"
        environment_name = "environment_name"
        destination_blob_name = "destination_blob_name"
        file_string_content = "some file text"
        file_bytes_content = file_string_content.encode("utf-8")
        mocker.patch.object(mock_response, "raise_for_status")

        persistent_file_storage_mixin = create_persistent_file_storage_mixin()
        mocker.patch.object(
            persistent_file_storage_mixin.file_storage_session, "post", return_value=mock_response
        )

        # act
        persistent_file_storage_mixin._set_blob_from_remote(
            environment_name, destination_blob_name, file_bytes_content
        )

        # assert
        expected_url = f"{persistent_file_storage_mixin.api_root}/webhooks/blob"
        call_args = persistent_file_storage_mixin.file_storage_session.post.call_args
        actual_url = call_args[0][0]
        actual_data = call_args[1]["data"]
        assert actual_url == expected_url
        assert actual_data == {
            "EnvironmentName": environment_name,
            "DestinationPath": destination_blob_name,
        }

    def test_init_sets_correct_attributes(self) -> None:
        # arrange
        environment_name = "env"
        workflow_instance_id = "wf"
        logger = SiemplifyLogger("/tmp/logger_test")
        is_remote = True
        file_storage_session = requests.Session()
        api_root = "http://api_root"
        one_platform_api_root = "http://1p_api_root/{}"
        files_dataplane_support = True

        # act
        mixin = PersistentFileStorageMixin(
            environment_name,
            workflow_instance_id,
            logger,
            is_remote,
            file_storage_session,
            api_root,
            one_platform_api_root,
            files_dataplane_support,
        )

        # assert
        assert mixin.environment_name == environment_name
        assert mixin.workflow_instance_id == workflow_instance_id
        assert mixin.logger == logger
        assert mixin.is_remote_sdk == is_remote
        assert mixin.file_storage_session == file_storage_session
        assert mixin.api_root == "http://api_root"
        assert mixin.one_platform_api_root == one_platform_api_root
        assert mixin.files_dataplane_support == files_dataplane_support

    def test_get_blob_from_remote_dataplane_support_enabled(self, mocker: Any) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.content = b"some_blob_data"
        expected_result = "some_blob_data"
        environment_name = "environment_name"
        destination_blob_name = "destination_blob_name"
        one_platform_api_root = "https://oneplatform.googleapis.com/{}"
        mocker.patch.object(mock_response, "raise_for_status")

        persistent_file_storage_mixin = create_persistent_file_storage_mixin(
            one_platform_api_root=one_platform_api_root,
            files_dataplane_support=True,
        )
        mocker.patch.object(
            persistent_file_storage_mixin.file_storage_session, "get", return_value=mock_response
        )

        # act
        result = persistent_file_storage_mixin._get_blob_from_remote(
            environment_name, destination_blob_name
        )

        # assert
        expected_url = "https://oneplatform.googleapis.com/download/legacySdk:legacyDownloadBlob"
        persistent_file_storage_mixin.file_storage_session.get.assert_called_once_with(
            expected_url,
            params={
                "alt": "media",
                "environment_name": environment_name,
                "destination_path": destination_blob_name,
            },
        )
        assert result == expected_result

    def test_set_blob_from_remote_dataplane_support_enabled(self, mocker: Any) -> None:
        # arrange
        mock_response = mocker.Mock()
        mock_response.content = b"some_blob_data"
        environment_name = "environment_name"
        destination_blob_name = "destination_blob_name"
        file_string_content = "some file text"
        file_bytes_content = file_string_content.encode("utf-8")
        one_platform_api_root = "https://oneplatform.googleapis.com/{}"
        mocker.patch.object(mock_response, "raise_for_status")

        persistent_file_storage_mixin = create_persistent_file_storage_mixin(
            one_platform_api_root=one_platform_api_root,
            files_dataplane_support=True,
        )
        mocker.patch.object(
            persistent_file_storage_mixin.file_storage_session, "post", return_value=mock_response
        )

        # act
        persistent_file_storage_mixin._set_blob_from_remote(
            environment_name, destination_blob_name, file_bytes_content
        )

        # assert
        expected_url = "https://oneplatform.googleapis.com/upload/legacySdk:legacyUploadBlob"
        call_args = persistent_file_storage_mixin.file_storage_session.post.call_args
        actual_url = call_args[0][0]

        # Check files instead of data
        actual_files = call_args[1]["files"]

        assert actual_url == expected_url

        # Validate metadata in files
        metadata_tuple = actual_files["metadata"]
        assert metadata_tuple[0] is None
        assert json.loads(metadata_tuple[1]) == {
            "environment_name": environment_name,
            "destination_path": destination_blob_name,
        }
        assert metadata_tuple[2] == "application/json"

        # Validate file data in files
        file_tuple = actual_files["file"]
        assert file_tuple[0] == "file"
        assert file_tuple[1].read() == file_bytes_content
        assert file_tuple[2] == "application/octet-stream"


def create_persistent_file_storage_mixin(
    environment_name: str = "Default Environment",
    workflow_instance_id: str = "12334",
    api_root: str = "api_root",
    logger: Any = None,
    is_remote: bool = False,
    file_storage_session: Any = None,
    one_platform_api_root: str | None = None,
    files_dataplane_support: bool = False,
) -> PersistentFileStorageMixin:
    if logger is None:
        logger = SiemplifyLogger("/tmp/logger_test")
    if file_storage_session is None:
        file_storage_session = requests.Session()

    return PersistentFileStorageMixin(
        environment_name,
        workflow_instance_id,
        logger,
        is_remote,
        file_storage_session,
        api_root,
        one_platform_api_root,
        files_dataplane_support,
    )
