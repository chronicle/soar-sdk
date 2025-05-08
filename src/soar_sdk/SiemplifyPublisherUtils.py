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

import json
import os

import requests
from six import string_types

# CONSTS
REST_CALLS_FILE = r"rest_calls.json"


class SiemplifySession(requests.Session):
    @staticmethod
    def write_rest_calls_to_file(address, data):
        """Publisher collects all requests and save it to file.
        :param address: requests address
        :param data:
        """
        # Some of the requests used dict and other explicit json, here we transfer
        # all calls data as dict
        # That's why we try to convert to dict before sending to proxy
        try:
            if isinstance(data, string_types):
                data = json.loads(data)
            else:
                # Verify data is valid python json  (dict or list)
                dummydata = json.dumps(data)
        except Exception:
            raise Exception("PublisherUtils: Payload must be dict list or valid json")

        file_path = REST_CALLS_FILE
        # Check if file exits
        if os.path.exists(file_path):
            with open(file_path) as json_file:
                file_data = json_file.read()
        else:
            file_data = "[]"

        json_data = json.loads(file_data)
        json_data.append({address: data})
        with open(file_path, "w") as json_file:
            json_file.write(json.dumps(json_data))

    # override post
    def post(self, address, data=None, json=None, **kwargs):
        if json:
            request_data = json
        elif data:
            request_data = data
        else:
            request_data = {}

        self.write_rest_calls_to_file(address, request_data)
        # Return response to support validate_error func
        res = requests.Response()
        # override content to support response.json()
        res._content = b'{"dummy": "publisher"}'
        # override status to support comparing status codes
        res.status_code = 200
        return res

    def get(self, address, **kwargs):
        # Override get
        # get requests are not supported in 'publisher' mode
        raise Exception("GET requests are not supported in publisher mode")
