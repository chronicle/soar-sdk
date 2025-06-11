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

import os
from typing import TYPE_CHECKING

import google.auth
import google.auth.credentials
import google.auth.transport.requests
from google.auth import impersonated_credentials

if TYPE_CHECKING:
    from SiemplifyBase import SiemplifyBase

DEFAULT_SCOPES: list[str] = ["https://www.googleapis.com/auth/cloud-platform"]
CHRONICLE_SERVICE_ACCOUNT_EMAIL: str = "CHRONICLE_SERVICE_ACCOUNT_EMAIL"


class GcpTokenProvider:
    @staticmethod
    def add_gcp_token(siemplify_base: SiemplifyBase) -> None:
        credentials, project_id = google.auth.default(DEFAULT_SCOPES)
        if credentials is None:
            return
        token = GcpTokenProvider._get_service_account_auth_token(
            siemplify_base,
            credentials,
        )
        if token is not None:
            siemplify_base.session.headers["Authorization"] = f"Bearer {token}"

    @staticmethod
    def _get_service_account_auth_token(
        siemplify_base: SiemplifyBase,
        credentials: google.auth.credentials.Credentials,
    ) -> str | None:
        if not siemplify_base.sdk_config.is_remote_publisher_sdk:
            credentials = GcpTokenProvider._get_credentials_via_impersonation(
                credentials,
            )
        if credentials is None:
            return None

        return GcpTokenProvider._get_remote_auth_token(credentials)

    @staticmethod
    def _get_credentials_via_impersonation(
        credentials: google.auth.credentials.Credentials,
    ) -> impersonated_credentials.Credentials | None:
        sa_email = GcpTokenProvider._get_service_account_email()

        if sa_email is None:
            return None

        return impersonated_credentials.Credentials(
            source_credentials=credentials,
            target_principal=sa_email,
            target_scopes=DEFAULT_SCOPES,
        )

    @staticmethod
    def _get_service_account_email() -> str:
        sa_email = os.environ.get(CHRONICLE_SERVICE_ACCOUNT_EMAIL)
        # TODO (b/403885470) - Throw exception if CHRONICLE_SERVICE_ACCOUNT_EMAIL
        #  environment variable is missing
        return sa_email

    @staticmethod
    def _get_remote_auth_token(
        credentials: impersonated_credentials.Credentials,
    ) -> str:
        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)
        return credentials.token
