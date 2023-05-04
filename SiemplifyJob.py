import sys
import json
from Siemplify import Siemplify
from SiemplifyUtils import extract_script_param, is_python_37, is_str_instance
import SiemplifyUtils
import SiemplifyVaultUtils


class SiemplifyJob(Siemplify):

    def __init__(self):
        super(SiemplifyJob, self).__init__()

        if is_python_37():
            raw_context_data = sys.stdin.buffer.read()
        else:
            raw_context_data = sys.stdin.read()

        context_data = json.loads(raw_context_data.decode("utf-8-sig"))
        self.parameters = self._fix_parameters(context_data['parameters'])
        self.unique_identifier = context_data.get('unique_identifier')
        self.use_proxy_settings = context_data.get('use_proxy_settings', False)
        self.vault_settings = context_data.get('vault_settings', None)
        
        if self.use_proxy_settings: 
            self.init_proxy_settings()

    def get_configuration(self, provider, environment=None, integration_instance=None):
        """
        Get integration configuration
        :param provider: {string} integration name (e.g. "VirusTotal")
        :param environment: {string} configuration for specific environment or 'all'
        :param integration_instance: {string} the identifier of the integration instance.
        :return: {dict} configuration details
        """
        return super(SiemplifyJob, self).get_configuration(provider, environment, integration_instance)

    def get_system_info(self,start_time_unixtime_ms):
        return super(SiemplifyJob, self).get_system_info(start_time_unixtime_ms)

    def get_job_context_property(self, identifier, property_key):
        return super(SiemplifyJob, self).get_context_property(3, identifier, property_key)

    def set_job_context_property(self, identifier, property_key, property_value):
        return super(SiemplifyJob, self).set_context_property(3, identifier, property_key,property_value)
        
    def get_scoped_job_context_property(self, property_key):
        """
        Get scoped job context property, uses the unique identifier of a job
        :param property_key: {string} key of the context property of the job
        :return: value of a specific key
        """    
        return self.get_job_context_property(self.unique_identifier, property_key)

    def set_scoped_job_context_property(self, property_key, property_value):
        """
        Set scoped job context property, uses the unique identifier of a job
        :param property_key: {string} key of the context property of the job
        :param property_value: {string} value of the context property of the job
        :return:
        """
        return self.set_job_context_property(self.unique_identifier, property_key, property_value)

    def save_publisher_logs(self, records):
        """
        Save publisher log records
        :param records: {list} records to be saved
        :return:
        """
        address = "{0}/{1}".format(self.API_ROOT, "external/v1/sdk/AddAgentLogs?format=snake")
        response = self.session.post(address, json=records)
        self.validate_siemplify_error(response)
        
    @property
    def log_location(self):
        return "SDK_Jobs"

    def get_failed_actions(self, number_of_hours):
        """
        Get all the etl jobs that had failed in the last hours
        :return: {dict} failed jobs
        """
        address = "{0}/{1}/{2}{3}".format(self.API_ROOT, "external/v1/sdk/GetFailedActions", number_of_hours, "?format=snake")
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_failed_etljobs(self, number_of_hours):
        """
        Get all the etl jobs that had failed in the last hours
        :return: {dict} failed jobs
        """
        address = "{0}/{1}/{2}{3}".format(self.API_ROOT, "external/v1/sdk/GetFailedETLOperations", number_of_hours, "?format=snake")
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_faulted_jobs(self, number_of_hours):
        """
        Get all the jobs that had failed in the last hours
        :return: {dict} failed jobs
        """
        address = "{0}/{1}/{2}{3}".format(self.API_ROOT, "external/v1/sdk/GetFailedJobs", number_of_hours, "?format=snake")
        response = self.session.get(address)
        self.validate_siemplify_error(response)
        return response.json()

    def get_faulted_connectors(self, start_unix_time, end_unix_time):
        """
        Get all the connectors that had failed in the last hours
        :return: {dict} failed connectors
        """
        request = {
            "start_unix_time": start_unix_time,
            "end_unix_time": end_unix_time,
        }
        address = "{0}/{1}/{2}".format(self.API_ROOT, "external/v1/sdk/GetFailedConnectors", "?format=snake")
        response = self.session.post(address, json=request)
        self.validate_siemplify_error(response)
        return response.json()

    def send_mail(self, subject, message, recipients, attachment_file_name, attachment_content):
        request = {
            "subject": subject,
            "message": message,
            "recipients": recipients,
            "attachment_file_name": attachment_file_name,
            "attachment_content": attachment_content,
        }
        address = "{0}/{1}/{2}".format(self.API_ROOT, "external/v1/sdk/SendEmailWithAttachment", "?format=snake")
        response = self.session.post(address, json=request)
        self.validate_siemplify_error(response)
        

    def extract_job_param(self, param_name, default_value=None, input_type=str, is_mandatory=False, print_value=False):
        script_param = extract_script_param(siemplify=self,
                                    input_dictionary=self.parameters,
                                    param_name=param_name,
                                    default_value=default_value,
                                    input_type=input_type,
                                    is_mandatory=is_mandatory,
                                    print_value=print_value)
        if not self.vault_settings:
            return script_param
        return SiemplifyVaultUtils.extract_vault_param(script_param, self.vault_settings)
    
    def save_timestamp(self, datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now()):
            return super(SiemplifyJob, self).save_timestamp(datetime_format, timezone, new_timestamp, 3, self.script_name)
            
    def fetch_timestamp(self, datetime_format=False, timezone=False):
        return super(SiemplifyJob, self).fetch_timestamp(datetime_format, timezone,3, self.script_name)
    
    def fetch_and_save_timestamp(self,datetime_format=False, timezone=False, new_timestamp=SiemplifyUtils.unix_now()):
        last_run_time = self.fetch_timestamp(datetime_format, timezone)
        self.save_timestamp(datetime_format, timezone, new_timestamp)
        return last_run_time
