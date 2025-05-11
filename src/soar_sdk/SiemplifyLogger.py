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
import logging.config
import logging.handlers
import sys
import traceback
from abc import ABCMeta, abstractmethod
from os import path
from sys import stderr
from typing import Any, Never

import arrow
import SiemplifyUtils
import six
from SiemplifyDataModel import (
    ActionLogRecord,
    ConnectorLogRecord,
    LogRecordTypeEnum,
    LogRow,
)
from SiemplifyUtils import is_at_least_python_3_11, is_python_37


class LogLevelEnum:
    INFO = 1
    WARN = 2
    ERROR = 3


class SiemplifyLogger:
    DEFAULT_LOGGER_NAME: str = "siemplify_default_logger"
    DEFAULT_FILE_HANDLER_NAME: str = "siempify_file_handler"
    DEFAULT_LOG_FILE_NAME: str = "logdata.log"
    DEFAULT_LOG_LOCATION: str = "SDK"

    def __init__(
        self,
        log_path: str,
        log_location: str = DEFAULT_LOG_LOCATION,
        module: str | None = None,
        logs_collector: FileLogsCollector | None = None,
    ) -> None:
        self.config_file_path = path.join(
            path.dirname(__file__),
            "ScriptingLogging.config",
        )
        self._error_logged = False
        self._log = None
        self._logs_collector = logs_collector
        self._log_rows = []
        try:
            config = self.loadConfigFromFile(log_path, log_location)
            logging.config.dictConfig(config)
            self._log = logging.getLogger(self.DEFAULT_LOGGER_NAME)
            self.module = module
        except:
            SiemplifyLogger.print_to_stderr("LOGGER: Error initializing")
            traceback.print_exc()

    def loadConfigFromFile(self, log_path: str, log_location: Never) -> dict[str, Any]:
        """Load config file
        :param run_folder: {string} running folder path
        :param log_location: {string} elastic search log location
        :return:
        """
        try:
            configfile = open(self.config_file_path)
            config_json_string = configfile.read()
            configfile.close()
            logging_config_from_file = json.loads(config_json_string)

            handlers = logging_config_from_file["handlers"]
            if self.DEFAULT_FILE_HANDLER_NAME in handlers and log_path:
                handlers[self.DEFAULT_FILE_HANDLER_NAME]["filename"] = log_path

            return logging_config_from_file
        except:
            SiemplifyLogger.print_to_stderr("LOGGER: loadConfigFromFile FAILED")

    def exception(self, message: str | Exception, *args: Never, **kwargs: Any) -> None:
        """Configure log - type exception
        :param message: {string} exception message
        """
        self._error_logged = True

        try:
            self.append_message(message, LogLevelEnum.ERROR)
            self.safe_print(message)
            if isinstance(message, Exception):
                version_safe_print_exception(message)

            if self._log:
                if isinstance(message, Exception) and not is_python_37():
                    escaped_msg = str(message.message).replace("%", "%%")
                elif is_python_37():
                    escaped_msg = str(message).replace("%", "%%")
                else:
                    escaped_msg = message.replace("%", "%%")

                if self.module:
                    kwargs.update({"module": self.module})

                if kwargs:
                    self._log.error(escaped_msg, kwargs, exc_info=True)
                else:
                    self._log.error(escaped_msg, exc_info=True)

            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.ERROR)
        except Exception:
            SiemplifyLogger.print_to_stderr("LOGGER.exception FAILED.")

    def error(self, message: str, *args: Never, **kwargs: Any) -> None:
        """Configure log - type error
        :param message: {string} exception message
        """
        self._error_logged = True

        try:
            self.append_message(message, LogLevelEnum.ERROR)
            self.safe_print(message)
            if self._log:
                if self.module:
                    kwargs.update({"module": self.module})
                if kwargs:
                    self._log.error(message.replace("%", "%%"), kwargs)
                else:
                    self._log.error(message)
            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.ERROR)
        except:
            SiemplifyLogger.print_to_stderr("LOGGER.error FAILED")

    def warn(self, message: str, *args: Never, **kwargs: Any) -> None:
        """Configure log - type warn
        :param message: {string} exception message
        """
        try:
            self.append_message(message, LogLevelEnum.WARN)
            self.safe_print(message)
            if self._log:
                if self.module:
                    kwargs.update({"module": self.module})
                if kwargs:
                    self._log.warn(message.replace("%", "%%"), kwargs)
                else:
                    self._log.warn(message)
            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.ERROR)
        except:
            SiemplifyLogger.print_to_stderr("LOGGER.warn FAILED")

    def info(self, message: str, *args: Never, **kwargs: Any) -> None:
        """Configure log - type info
        :param message: {string} exception message
        """
        try:
            self.append_message(message, LogLevelEnum.INFO)
            self.safe_print(message)
            if self._log:
                if self.module:
                    kwargs.update({"module": self.module})
                if kwargs:
                    self._log.info(message.replace("%", "%%"), kwargs)
                else:
                    self._log.info(message)
            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.INFO)
        except Exception:
            SiemplifyLogger.print_to_stderr("LOGGER.info FAILED")

    def append_message(self, message: str, log_level: LogLevelEnum) -> None:
        try:
            log_row = LogRow(
                message=SiemplifyLogger.encode(str(message)),
                log_level=log_level,
                timestamp=SiemplifyUtils.unix_now(),
            )
            self._log_rows.append(log_row)
        except Exception as e:
            print(f"Couldn't append log message, reason: {e}")

    @staticmethod
    def encode(message: str) -> bytes | str:
        try:
            if not is_python_37() and isinstance(message, unicode):
                return message.encode("utf8")
            return message
        except Exception as e:
            print(f"Couldn't encode message, reason: {e}")

    @staticmethod
    def safe_print(message: str) -> None:
        try:
            print(SiemplifyLogger.encode(message))
        except Exception:
            print("Couldn't print exception, check log")

    @property
    def log_rows(self) -> list[str]:
        return self._log_rows

    @staticmethod
    def print_to_stderr(message: Never) -> None:
        stderr.write("LOGGER: loadConfigFromFile FAILED")

    @property
    def error_logged(self) -> bool:
        return self._error_logged


def version_safe_print_exception(e: Exception) -> None:
    if is_at_least_python_3_11():
        traceback.print_exception(e, file=sys.stdout)

    elif is_python_37():
        traceback.print_exception(type(e), value=e, tb=e.__traceback__, file=sys.stdout)


class SiempplifyConnectorsLogger:
    _log_items = []

    def error(self, message: str) -> None:
        msg = "ERROR | " + str(message)
        print(msg)
        self._log_items.append(msg)

    def warn(self, message: str) -> None:
        msg = "WARN | " + str(message)
        print(msg)
        self._log_items.append(msg)

    def info(self, message: str) -> None:
        msg = "INFO | " + str(message)
        print(msg)
        self._log_items.append(msg)


@six.add_metaclass(ABCMeta)
class FileLogsCollector:
    LOG_COLLECTOR_FILENAME = "logs_collector.json"

    def __init__(self, file_dir: str) -> None:
        self.log_collector_file_path = path.join(file_dir, self.LOG_COLLECTOR_FILENAME)

    @abstractmethod
    def create_log_record(
        self,
        message: str,
        log_type: LogLevelEnum,
    ) -> ActionLogRecord | ConnectorLogRecord:
        raise NotImplementedError

    def collect(self, message: str, log_type: LogRecordTypeEnum) -> None:
        log_record = self.create_log_record(message, log_type)
        log_items = []
        try:
            if path.exists(self.log_collector_file_path):
                log_items = json.load(open(self.log_collector_file_path))

            with open(self.log_collector_file_path, "w") as logs_collector:
                log_items.append(log_record)
                logs_collector.write(
                    json.dumps(log_items, default=lambda o: o.__dict__),
                )

        except Exception:
            stderr.write("LOGGER: add log record to collector FAILED")


class ConnectorsFileLogsCollector(FileLogsCollector):
    """Collect connectors logs to a file"""

    def __init__(
        self,
        file_dir: str,
        connector_context: dict[str, Any],
    ) -> None:
        super(ConnectorsFileLogsCollector, self).__init__(file_dir)
        self.connector_context = connector_context

    def create_log_record(
        self,
        message: str,
        log_type: LogLevelEnum,
    ) -> ConnectorLogRecord:
        log_record = ConnectorLogRecord(
            record_type=log_type,
            message=message,
            connector_identifier=self.connector_context.connector_info.identifier,
            result_data_type=self.connector_context.connector_info.result_data_type,
            source_system_name=self.connector_context.connector_info.integration,
            connector_definition_name=self.connector_context.connector_info.connector_definition_name,
            integration=self.connector_context.connector_info.integration,
            timestamp=arrow.utcnow().timestamp,
        )
        return log_record


class ActionsFileLogsCollector(FileLogsCollector):
    """Collect actions logs to a file"""

    def __init__(self, file_dir: str, context_data: dict[str, Any]) -> None:
        super(ActionsFileLogsCollector, self).__init__(file_dir)
        self.context_data = context_data

    def create_log_record(
        self,
        message: str,
        log_type: LogRecordTypeEnum,
    ) -> ActionLogRecord:
        log_record = ActionLogRecord(
            record_type=log_type,
            message=message,
            case_id=self.context_data["case_id"],
            alert_id=self.context_data["alert_id"],
            workflow_id=self.context_data["workflow_id"],
            environment=self.context_data["environment"],
            action_definition_name=self.context_data["action_definition_name"],
            integration=self.context_data["integration_identifier"],
            timestamp=arrow.utcnow().timestamp,
        )

        return log_record
