import logging.handlers
import logging.config
import json
from os import path
import traceback
from abc import ABCMeta, abstractmethod
from sys import stderr
import six
import arrow
import SiemplifyUtils
from SiemplifyDataModel import ConnectorLogRecord, LogRecordTypeEnum, ActionLogRecord, LogRow
from SiemplifyUtils import is_python_37


class LogLevelEnum(object):
    INFO = 1
    WARN = 2
    ERROR = 3


class SiemplifyLogger(object):
    DEFAULT_LOGGER_NAME = "siemplify_default_logger"
    DEFAULT_FILE_HANDLER_NAME = "siempify_file_handler"
    DEFAULT_LOG_FILE_NAME = "logdata.log"
    DEFAULT_LOG_LOCATION = "SDK"

    def __init__(self, log_path, log_location=DEFAULT_LOG_LOCATION, module=None, logs_collector=None):
        self.config_file_path = path.join(path.dirname(__file__), 'ScriptingLogging.config')
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

    def loadConfigFromFile(self, log_path, log_location):
        """
        load config file
        :param run_folder: {string} running folder path
        :param log_location: {string} elastic search log location
        :return:
        """
        try:
            configfile = open(self.config_file_path, "r")
            config_json_string = configfile.read()
            configfile.close()
            logging_config_from_file = json.loads(config_json_string)

            handlers = logging_config_from_file["handlers"]
            if self.DEFAULT_FILE_HANDLER_NAME in handlers and log_path:
                handlers[self.DEFAULT_FILE_HANDLER_NAME]["filename"] = log_path

            return logging_config_from_file
        except:
            SiemplifyLogger.print_to_stderr("LOGGER: loadConfigFromFile FAILED")

    def exception(self, message, *args, **kwargs):
        """
        configure log - type exception
        :param message: {string} exception message
        """
        self._error_logged = True

        try:
            self.append_message(message, LogLevelEnum.ERROR)
            self.safe_print(message)
            if self._log:
                if isinstance(message, Exception) and not is_python_37():
                    escaped_msg = str(message.message).replace("%", "%%")
                elif is_python_37():
                    escaped_msg = str(message).replace("%", "%%")
                else:
                    escaped_msg = message.replace("%", "%%")

                if self.module:
                    kwargs.update({'module': self.module})

                if kwargs:
                    self._log.error(escaped_msg, kwargs, exc_info=True)
                else:
                    self._log.error(escaped_msg, exc_info=True)

            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.ERROR)
        except Exception as e:
            SiemplifyLogger.print_to_stderr("LOGGER.exception FAILED.")

    def error(self, message, *args, **kwargs):
        """
        configure log - type error
        :param message: {string} exception message
        """
        self._error_logged = True

        try:
            self.append_message(message, LogLevelEnum.ERROR)
            self.safe_print(message)
            if self._log:
                if self.module:
                    kwargs.update({'module': self.module})
                if kwargs:
                    self._log.error(message.replace("%", "%%"), kwargs)
                else:
                    self._log.error(message)
            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.ERROR)
        except:
            SiemplifyLogger.print_to_stderr("LOGGER.error FAILED")

    def warn(self, message, *args, **kwargs):
        """
        configure log - type warn
        :param message: {string} exception message
        """
        try:
            self.append_message(message, LogLevelEnum.WARN)
            self.safe_print(message)
            if self._log:
                if self.module:
                    kwargs.update({'module': self.module})
                if kwargs:
                    self._log.warn(message.replace("%", "%%"), kwargs)
                else:
                    self._log.warn(message)
            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.ERROR)
        except:
            SiemplifyLogger.print_to_stderr("LOGGER.warn FAILED")

    def info(self, message, *args, **kwargs):
        """
        configure log - type info
        :param message: {string} exception message
        """
        try:
            self.append_message(message, LogLevelEnum.INFO)
            self.safe_print(message)
            if self._log:
                if self.module:
                    kwargs.update({'module': self.module})
                if kwargs:
                    self._log.info(message.replace("%", "%%"), kwargs)
                else:
                    self._log.info(message)
            if self._logs_collector:
                self._logs_collector.collect(message, LogRecordTypeEnum.INFO)
        except Exception as e:
            SiemplifyLogger.print_to_stderr(u"LOGGER.info FAILED")

    def append_message(self, message, log_level):
        try:
            log_row = LogRow(message=SiemplifyLogger.encode(str(message)),
                             log_level=log_level,
                             timestamp=SiemplifyUtils.unix_now())
            self._log_rows.append(log_row)
        except Exception as e:
            print("Couldn't append log message, reason: {exception}".format(e))

    @staticmethod
    def encode(message):
        try:
            if not is_python_37() and isinstance(message, unicode):
                return message.encode("utf8")
            else:
                return message
        except Exception as e:
            print("Couldn't encode message, reason: {exception}".format(e))

    @staticmethod
    def safe_print(message):
        try:
            print(SiemplifyLogger.encode(message))
        except Exception as e:
            print("Couldn't print exception, check log")

           

    @property
    def log_rows(self):
        return self._log_rows

    @staticmethod
    def print_to_stderr(message):
        stderr.write("LOGGER: loadConfigFromFile FAILED")

    @property
    def error_logged(self):
        return self._error_logged

class SiempplifyConnectorsLogger(object):
    _log_items = []

    def error(self, message):
        msg = "ERROR | " + str(message)
        print(msg)
        self._log_items.append(msg)

    def warn(self, message):
        msg = "WARN | " + str(message)
        print(msg)
        self._log_items.append(msg)

    def info(self, message):
        msg = "INFO | " + str(message)
        print(msg)
        self._log_items.append(msg)

@six.add_metaclass(ABCMeta)
class FileLogsCollector(object):
    LOG_COLLECTOR_FILENAME = "logs_collector.json"

    def __init__(self, file_dir):
        self.log_collector_file_path = path.join(file_dir, self.LOG_COLLECTOR_FILENAME)

    @abstractmethod
    def create_log_record(self, message, log_type):
        raise NotImplementedError

    def collect(self, message, log_type):
        log_record = self.create_log_record(message, log_type)
        log_items = []
        try:
            if path.exists(self.log_collector_file_path):
                log_items = json.load(open(self.log_collector_file_path, "r"))

            with open(self.log_collector_file_path, 'w') as logs_collector:
                log_items.append(log_record)
                logs_collector.write(json.dumps(log_items, default=lambda o: o.__dict__))

        except Exception:
            stderr.write("LOGGER: add log record to collector FAILED")

class ConnectorsFileLogsCollector(FileLogsCollector):
    """Collect connectors logs to a file"""
    def __init__(self, file_dir, connector_context):
        super(ConnectorsFileLogsCollector, self).__init__(file_dir)
        self.connector_context = connector_context

    def create_log_record(self, message, log_type):
        log_record = ConnectorLogRecord(
            record_type=log_type,
            message=message,
            connector_identifier=self.connector_context.connector_info.identifier,
            result_data_type=self.connector_context.connector_info.result_data_type,
            source_system_name=self.connector_context.connector_info.integration,
            connector_definition_name=self.connector_context.connector_info.connector_definition_name,
            integration=self.connector_context.connector_info.integration,
            timestamp=arrow.utcnow().timestamp
        )
        return log_record


class ActionsFileLogsCollector(FileLogsCollector):
    """Collect actions logs to a file"""
    def __init__(self, file_dir, context_data):
        super(ActionsFileLogsCollector, self).__init__(file_dir)
        self.context_data = context_data

    def create_log_record(self, message, log_type):
        log_record = ActionLogRecord(
            record_type=log_type,
            message=message,
            case_id=self.context_data['case_id'],
            alert_id=self.context_data['alert_id'],
            workflow_id=self.context_data['workflow_id'],
            environment=self.context_data["environment"],
            action_definition_name=self.context_data["action_definition_name"],
            integration=self.context_data["integration_identifier"],
            timestamp=arrow.utcnow().timestamp
        )

        return log_record