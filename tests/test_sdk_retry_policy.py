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

from unittest.mock import ANY, MagicMock

import pytest
import requests

from soar_sdk.SDKRetryPolicy import DEFAULT_LABELS
from soar_sdk.SiemplifyBase import SiemplifyBase


class TestSDKRetryPolicy:
    @pytest.mark.parametrize("status_code", [502, 503, 504])
    def test_retry_policy_end_to_end(self, mocker, status_code: int) -> None:
        # Arrange
        mock_sleep = mocker.patch("time.sleep")
        mock_make_request = mocker.patch("urllib3.connectionpool.HTTPConnectionPool._make_request")

        mock_logger = MagicMock()

        # Use the actual SiemplifyBase method to generate the session
        session = SiemplifyBase.create_session(
            app_key="test_key",
            feat_sdk_retries=True,
            logger=mock_logger,
        )

        # Mock urllib3's _make_request to simulate receiving a response from the server
        mock_httplib_resp = MagicMock()
        mock_httplib_resp.status = status_code
        mock_httplib_resp.msg = MagicMock()
        mock_httplib_resp.read.return_value = b""
        mock_httplib_resp.isclosed.return_value = False
        mock_httplib_resp.headers.get.return_value = None
        mock_httplib_resp.get_redirect_location.return_value = None

        mock_make_request.return_value = mock_httplib_resp

        # Act & Assert
        with pytest.raises(requests.exceptions.RetryError):
            session.get("http://test-site.com/api/test")

        # SiemplifyBase configures total=3 retries.
        # 1 initial attempt + 3 retries = 4 total network calls attempted
        assert mock_make_request.call_count == 4

        # Verify the logger captured the intermediate retry warnings with labels
        assert mock_logger.warn.call_count == 3
        mock_logger.warn.assert_any_call(ANY, labels=DEFAULT_LABELS)

        # Verify the sleep delays: 10, 20 (First retry has no delay)
        assert mock_sleep.call_count == 2
        mock_sleep.assert_has_calls([mocker.call(10), mocker.call(20)])

        # Verify the logger captured the final exhaustion error with labels
        mock_logger.error.assert_called_once_with(ANY, labels=DEFAULT_LABELS)
