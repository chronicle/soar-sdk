import json

class ConnectorContext:
    def __init__(self, connector_info, vault_settings=None):
        self.connector_info = ConnectorInfo(**connector_info)
        self.vault_settings = vault_settings


class ConnectorInfo:
    def __init__(self, **kwargs):
        self.environment = kwargs.get("environment")
        self.integration = kwargs.get("integration")
        self.connector_definition_name = kwargs.get("connector_definition_name")
        self.identifier = kwargs.get("identifier")
        self.display_name = kwargs.get("display_name")
        self.description = kwargs.get("description")
        self.result_data_type = kwargs.get("result_data_type")
        self.params = kwargs.get("params")
        white_list = kwargs.get("allow_list", kwargs.get("white_list"))
        if white_list is not None:
            self.white_list = white_list
        else:
            white_list = kwargs.get("allow_list_json_object", kwargs.get("white_list_json_object"))
            self.white_list = json.loads(white_list) if white_list != None else None


class CaseInfo(object):
    def __init__(self):
        self.environment = None
        self.ticket_id = None
        self.description = None
        self.display_id = None
        self.reason = None
        self.name = None
        self.source_system_url = None
        self.source_rule_identifier = None
        self.device_vendor = None
        self.device_product = None
        self.start_time = None
        self.end_time = None
        self.is_test_case = False
        self.priority = -1
        self.rule_generator = None
        self.source_grouping_identifier = None
        self.extensions = {}
        self.events = []
        self.attachments = []
        self.siem_alert_id = None

class AlertInfo(CaseInfo):
    def __init__(self):
        super(AlertInfo, self).__init__()
