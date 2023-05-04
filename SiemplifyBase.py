import SiemplifyLogger
import SiemplifyUtils
from SiemplifySdkConfig import SiemplifySdkConfig
from SiemplifyPublisherUtils import SiemplifySession
import datetime
import os
import sys
import getopt
import requests
import json

HEADERS = {'Content-Type': 'application/json', 'Accept': 'application/json'}
REQUEST_CA_BUNDLE = "REQUESTS_CA_BUNDLE"
NO_CONTENT_STATUS_CODE = 204

class SiemplifyBase(object):
    TIMESTAMP_KEY = "timestamp"
    
    def __init__(self, is_connector = False):
        self.api_key = None
        self.sdk_config = SiemplifySdkConfig()
        self.RUN_FOLDER = self.sdk_config.run_folder_path
        self.script_name = ""
        self._logger = None
        self._logs_collector = None
        self._log_path = None
        self.API_ROOT = self.sdk_config.api_root_uri
        self.FILE_SYSTEM_CONTEXT_PATH = os.path.join(self.RUN_FOLDER, "context_file.json")
        options, _ = getopt.gnu_getopt(sys.argv[1:], "", ["useElastic", "logPath=","correlationId="])

        for name, value in options:
            if name == "--logPath":
                self._log_path=value.strip('"')
            elif name =="--correlationId":
                HEADERS.update({"correlation-id": value.strip('"')})
        
        if not self.sdk_config.is_remote_publisher_sdk:
            # Checking Environment Variables
            # For action runs we get api key as first param, for connectors we get api key as second param and isTest as first param
            if is_connector:
                self.api_key = sys.argv[2]
            else:
                self.api_key = sys.argv[1]
            if REQUEST_CA_BUNDLE in os.environ:
                if self.sdk_config.ignore_ca_bundle:
                    del os.environ[REQUEST_CA_BUNDLE]
                else:
                    print("Warning: Environment Variables cannot contain key {0}, please remove it.".format(REQUEST_CA_BUNDLE))
            
            # Create regular Session
            self.session = requests.Session()
            self.session.verify = False
            HEADERS.update({"AppKey": self.api_key})
            self.session.headers.update(HEADERS)
        
        else:
            # Create custom Session
            # Publisher mode not send the requests
            self.session = SiemplifySession()

    @property
    def run_folder(self):
        """
        build run_folder base on script name
        :return: {string} full path (e.g. C:\Siemplify_Server\Scripting\SiemplifyAction\<script name>)
        """
        path = os.path.join(self.RUN_FOLDER, self.__class__.__name__)

        if not self.script_name:
            raise Exception(
                "Cannot build run_folder when script_name has not been defined first. Try addind: siemplify.script_name='name'")

        path = os.path.join(path, self.script_name)

        if not os.path.exists(path):
            os.makedirs(path)

        return path

    @property
    def log_location(self):
        return "smp_python"

    @property
    def LOGGER(self):
        if not self._logger:
            self._logger = SiemplifyLogger.SiemplifyLogger(self._log_path, log_location=self.log_location,
                                                           logs_collector=self._logs_collector)

        return self._logger
    
    @staticmethod
    def validate_siemplify_error(response):
        """
        validate error
        :param response: {response}
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise Exception("{0}: {1}".format(e, response.content))

    def set_logs_collector(self, logs_collector):
        self._logs_collector = logs_collector

    def fetch_timestamp(self, datetime_format=False, timezone=False, context_type=None, identifier=None):
        """
        get timestamp
        :param datetime_format: {boolean} if datetime - return timestamp as datetime
        :param timezone: NOT SUPPORTED anymore!
        :return: {unix time/ datetime}
        """
        last_run_time = 0
        try:
            last_run_time = self.get_context_property(context_type, identifier, self.TIMESTAMP_KEY)
        except Exception as e:
            raise Exception("Failed reading timestamps from db, ERROR: {0}".format(e))
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

    def save_timestamp(self,datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now(), context_type=None, identifier=None):
        """
        save timestamp
        :param datetime_format: {boolean} if datetime - return timestamp as datetime
        :param timezone:  NOT SUPPORTED anymore!
        :param new_timestamp: {long} unix time
        """
        if isinstance(new_timestamp, datetime.datetime):
            new_timestamp = SiemplifyUtils.convert_datetime_to_unix_time(new_timestamp)

        try:
            self.set_context_property(context_type, identifier, self.TIMESTAMP_KEY, json.dumps(new_timestamp))
        except Exception as e:
            raise Exception("Failed saving timestamps to db, ERROR: {0}".format(e))

    def fetch_and_save_timestamp(self, datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now(), context_type=None, identifier=None):
        """
        fetach and save timestamp
        :param datetime_format: {boolean} if datetime - return timestamp as datetime
        :param timezone: NOT SUPPORTED anymore!
        :param new_timestamp: {long} unix time
        :return: {unix time/ datetime}
        """
        #This function is not in use anymore
        last_run_time = self.fetch_timestamp(context_type, identifier, datetime_format, timezone)
        self.save_timestamp(context_type, identifier, datetime_format, timezone, new_timestamp)
        return last_run_time
        
    def set_context_property(self, context_type, identifier, property_key, property_value):
        """
        set context property
        :param context_type: {int} ContextKeyValueEnum
        :param identifier: {string} identifier
        :param property_key: {string} property key 
        :param property_value: {object} property value
        """
        if not SiemplifyUtils.validate_property_value(property_value):
            raise MaximumContextLengthException("Exception was thrown in set_context_property: property value has reached maximum length")
            
        if not self.sdk_config.is_remote_publisher_sdk: # Write to DB 
            request_dict = {"ContextType":context_type, 
                            "Identifier": identifier,
                            "PropertyKey": property_key,
                            "PropertyValue": property_value}
            address = "{0}/{1}".format(self.API_ROOT, "external/v1/sdk/SetContextProperty")
            response = self.session.post(address, json=request_dict)
            self.validate_siemplify_error(response)
            
        else: # Write to FS                         
            try:
                try:
                    with open(self.FILE_SYSTEM_CONTEXT_PATH, 'r+') as context_file:
                        json_decoded = json.loads(context_file.read())                                     
                except Exception as e:
                    self.LOGGER.error("Exception was thrown in set_context_property: {}".format(e))
                    json_decoded = {}
                    
                json_decoded[property_key] = property_value
                
                with open(self.FILE_SYSTEM_CONTEXT_PATH, 'w') as json_file:
                    json.dump(json_decoded, json_file)

            except e:
                self.LOGGER.error("Exception was thrown in set_context_property: {}".format(e))
                raise Exception("Exception was thrown in set_context_property: {}".format(e))
            return True

    def try_set_context_property(self, context_type, identifier, property_key, property_value):
        """
        try set context property
        :param context_type: {int} ContextKeyValueEnum
        :param identifier: {string} identifier
        :param property_key: {string} property key 
        :param property_value: {object} property value
        """
        if not SiemplifyUtils.validate_property_value(property_value):
            raise MaximumContextLengthException("Exception was thrown in try_set_context_property: property value has reached maximum length")
            
        if not self.sdk_config.is_remote_publisher_sdk: # Write to DB 
            request_dict = {"ContextType":context_type, 
                            "Identifier": identifier,
                            "PropertyKey": property_key,
                            "PropertyValue": property_value}
            address = "{0}/{1}".format(self.API_ROOT, "external/v1/sdk/TrySetContextProperty")
            response = self.session.post(address, json=request_dict)
            self.validate_siemplify_error(response)
            return response.content
            
        else: # Write to FS                         
            try:
                try:
                    with open(self.FILE_SYSTEM_CONTEXT_PATH, 'r+') as context_file:
                        json_decoded = json.loads(context_file.read())                                             
                except:
                    json_decoded = {}
                    
                json_decoded[property_key] = property_value
                
                with open(self.FILE_SYSTEM_CONTEXT_PATH, 'w') as json_file:
                    json.dump(json_decoded, json_file)

            except Exception as e:
                self.LOGGER.error("Exception was thrown in try_set_context_property: {}".format(e))
                raise Exception("Exception was thrown in try_set_context_property: {}".format(e))
            return True
            
    
    def get_context_property(self, context_type, identifier, property_key):
        if not self.sdk_config.is_remote_publisher_sdk:
            #read from DB
            request_dict = {"ContextType":context_type, "Identifier": identifier,
                            "PropertyKey": property_key}
            address = "{0}/{1}".format(self.API_ROOT, "external/v1/sdk/GetContextProperty")
            response = self.session.post(address, json=request_dict)
            self.validate_siemplify_error(response)
            if response.status_code == NO_CONTENT_STATUS_CODE:
                return None
            return response.json()
        else:
            #read from FS
            try:
                with open(self.FILE_SYSTEM_CONTEXT_PATH, 'r+') as context_file:
                    context = json.loads(context_file.read())
            except Exception as e:
                self.LOGGER.error("Exception was thrown in get_context_property: {}".format(e))
                context = {}
            return context.get(property_key)


class MaximumContextLengthException(Exception):
    """
    Custom exception for the set context method
    """
    pass