from SiemplifyConnectors import SiemplifyConnectorExecution
from OverflowManager import OverflowAlertDetails
from SiemplifyConnectorsDataModel import CaseInfo
import SiemplifyUtils

import uuid
import sys
import random

#==============================================================================
# This is a Connector Template + mock generator. This file objective is to demonstrate how to build a connector, and exmplain the objective of each field.
# All the data generated here, is MOCK data. Enjoy.
#==============================================================================

GENERATE_ENVIRONMENTS = True



class RandomDataGenerator(object):

    RULE_GENERATOR_FAILED_LOGIN = "Failed login"
    RULE_GENERATOR_OUT_OF_HOURS = "Out of hours activities"
    RULE_GENERATOR_UNAUTHORIZED = "Unauthorized access attempt"
    RULE_GENERATOR_PORT_SCAN = "Port scan"
    RULE_GENERATOR_PHISHING = "Phishing Attempt"

    PRODUCT_AD="Active Directory"
    PRODUCT_IPS = "IPS"
    PRODUCT_PHISHING = "Phishing Email Detector"
    PRODUCT_AV = "AntiVirus"

    SOURCE_GROUPING_IDENTIFIER_A = "A"
    SOURCE_GROUPING_IDENTIFIER_B = "B"
    SOURCE_GROUPING_IDENTIFIER_C = "C"
    SOURCE_GROUPING_IDENTIFIER_D = "D"
    SOURCE_GROUPING_IDENTIFIER_E = "E"

    def __init__(self, is_static):
        self.is_static = is_static

    _vendor = None
    @property
    def VENDOR(self):
        if (not self._vendor or self.is_static == False):
            vendors = ["Macrohard", "Anira", "Mcnally"]
            random_vendor = vendors[random.randint(0, len(vendors) - 1)]
            self._vendor = random_vendor

        return self._vendor


    _source_group_identifier = None
    @property
    def SOURCE_GROUPING_IDENTIFIER(self):
        if (not self._source_group_identifier or self.is_static == False):
            rules = [self.SOURCE_GROUPING_IDENTIFIER_A,
                     self.SOURCE_GROUPING_IDENTIFIER_B,
                     self.SOURCE_GROUPING_IDENTIFIER_C,
                     self.SOURCE_GROUPING_IDENTIFIER_D,
                     self.SOURCE_GROUPING_IDENTIFIER_E]
            random_rule = rules[random.randint(0, len(rules) - 1)]
            self._source_group_identifier = random_rule

        return self._source_group_identifier

    _rule_generator = None
    @property
    def RULE_GENERATOR(self):
        if (not self._rule_generator or self.is_static == False):
            rules = [self.RULE_GENERATOR_FAILED_LOGIN,
                     self.RULE_GENERATOR_OUT_OF_HOURS,
                     self.RULE_GENERATOR_UNAUTHORIZED,
                     self.RULE_GENERATOR_PORT_SCAN,
                     self.RULE_GENERATOR_PHISHING]
            random_rule = rules[random.randint(0, len(rules) - 1)]
            self._rule_generator = random_rule

        return self._rule_generator

    def create_product(self, rule_generator):
        rule_tree = {self.RULE_GENERATOR_FAILED_LOGIN: [self.PRODUCT_AD,self.PRODUCT_IPS],
                     self.RULE_GENERATOR_OUT_OF_HOURS: [self.PRODUCT_AD,self.PRODUCT_IPS],
                     self.RULE_GENERATOR_UNAUTHORIZED: [self.PRODUCT_AD, self.PRODUCT_IPS],
                     self.RULE_GENERATOR_PORT_SCAN: [self.PRODUCT_AV,self.PRODUCT_IPS],
                     self.RULE_GENERATOR_PHISHING : [self.PRODUCT_PHISHING]}
        possible_products = rule_tree[rule_generator]
        random_product = possible_products[random.randint(0, len(possible_products) - 1)]
        return random_product


    def create_alert_name(self,rule_generator, product):

        tree = {self.RULE_GENERATOR_OUT_OF_HOURS: {self.PRODUCT_AD:["Active Directory Audit Policy Warning"],
                                         self.PRODUCT_IPS:["Activity timeline sensor triggered"]},
                self.RULE_GENERATOR_FAILED_LOGIN: {self.PRODUCT_AD:["Active Directory Audit Policy Warning"],
                                         self.PRODUCT_IPS:["User Authentication sensor triggered","unauthorized access detected"]},
                self.RULE_GENERATOR_PORT_SCAN: {self.PRODUCT_AV:["New Port Used","System Service port blocked by unknown process"],
                                                self.PRODUCT_IPS:["Out out policy port used","Unusual Port activity"]},
                self.RULE_GENERATOR_PHISHING: {self.PRODUCT_PHISHING:["Suspisous attachment hash detected in mail","Mail contains a known phishing address"]},
                self.RULE_GENERATOR_UNAUTHORIZED: {self.PRODUCT_AD:["User attempted to access computer out of Group", "'Morgan' vulnrability detected"],
                                                   self.PRODUCT_IPS:["WAF Flag Triggered A54","WAF Flag Triggered B34"]}
                }

        possible_event_names = tree[rule_generator][product]


        #                      "Port scan": ["ClearNet's detected a port scan", "Antivirus detected unusual port traffic"]}

        random_event_name = possible_event_names[random.randint(0, len(possible_event_names) - 1)]

        return random_event_name


    _source_host = None

    @property
    def SOURCE_HOST(self):
        if (random.randint(0, 3) == 0): return None
        if (not self._source_host or self.is_static == False):
            self._source_host = "Src_Host_" + str(random.randint(0, 10))
        return self._source_host

    _dest_host = None

    @property
    def DEST_HOST(self):
        if (random.randint(0, 3) == 0): return None
        if (not self._dest_host or self.is_static == False):
            self._dest_host = "Dst_Host_" + str(random.randint(0, 10))
        return self._dest_host

    _source_ip = None
    @property
    def SOURCE_IP(self):
        if (random.randint(0, 3) == 0): return None
        if (not self._source_ip or self.is_static == False):
            self._source_ip = "10.0.0." + str(random.randint(0, 50))
        return self._source_ip

    _dest_ip = None
    @property
    def DESTINATION_IP(self):
        if (random.randint(0, 3) == 0): return None
        if (not self._dest_ip or self.is_static == False):
            self._dest_ip = "200.0.0." + str(random.randint(0, 50))
        return self._dest_ip

    _source_username = None
    @property
    def SOURCE_USERNAME(self):
        if (random.randint(0, 3) == 0): return None
        if (not self._source_username or self.is_static == False):
            self._source_username = "src_user_" + str(random.randint(0, 50))
        return self._source_username

    _destination_username = None
    @property
    def DESTINATION_USERNAME(self):
        if (random.randint(0, 5) == 0): return None
        if (not self._destination_username or self.is_static == False):
            self._destination_username = "dst_user_" + str(random.randint(0, 50))
        return self._destination_username

    _usb = None
    @property
    def USB(self):
        if (random.randint(0, 1) == 0): return None
        if (not self._usb or self.is_static == False):
            self._usb = "usb_" + str(random.randint(0, 300))
        return self._usb

    _filename = None
    @property
    def FILENAME(self):
        if (random.randint(0, 1) == 0): return None
        if (not self._destination_username or self.is_static == False):
            self._filename = "filename" + str(random.randint(0, 50))+".txt"
        return self._filename

    _filehash = None
    @property
    def FILEHASH(self):
        if (random.randint(0, 4) == 0): return None
        if (not self._destination_username or self.is_static == False):
            hashes = ["bb9d72654ab021561cef4c38ae0f8999",
                     "ba22d18e50b1dd3816234194f1ec80d0",
                     "3283e1a9cc738526842c195a862a8b14",
                     "4da2687190b4fb0986c30e7b048c34c1",
                     "08c75a8fb8010d5b68dde217f92fe84e",
                     "c2e39d563dd537288f441643e334f6b9",
                     "d4b4e9b2cdff02ac0f5c6bf7cb878c49",
                     "f881b4cfbf549405f830a2f1cd2ba2d7",
                     "29dad148591bf98df950f6071ff014b9"]
            self._filehash = hashes[random.randint(0, len(hashes) - 1)]
        return self._filehash

    _destinationPort = None
    @property
    def PORT(self):
        if (random.randint(0, 2) == 0): return None
        if (not self._destination_username or self.is_static == False):
            self._destinationPort = str(random.randint(1, 9000))
        return self._destinationPort

    _categoryOutcome = None
    @property
    def CATEGORY_OUTCOME(self):
        if (not self._destination_username or self.is_static == False):
            outcomes = ["Blocked",
                      "Approved",
                      "Rejected",
                      "Passed",
                      "Proxied",
                      "Unified",
                      "Eliminited",
                      "Exterminiated",
                      "Quarantined"]
            self._categoryOutcome = outcomes[random.randint(0, len(outcomes) - 1)]
        return self._categoryOutcome

class DummyGenerator(object):
    SOURCE = "DummyGenerator"

    def __init__(self,logger):
        self.LOGGER = logger
        self.GENERATOR = RandomDataGenerator(is_static=True)

    def BuildDummySecurityEvent(self,environment, rule_generator, product):
        event = {}

        # Fill event fields by BL logic here:
        # Here is an exmaple of fields usually found in siems:

        # Time Fields (Arcsight Example):
        event["managerReceiptTime"] = SiemplifyUtils.unix_now() # Times should be saved in UnixTime. You may use SiemplifyUtils DateTime conversions, or the example convert_datetime_to_unix_time method below
        event["StartTime"] = SiemplifyUtils.unix_now()
        event["EndTime"] = SiemplifyUtils.unix_now()
        event["Environment"] = environment

        # Some fields, siemplify expects as mandatory. Their names may vary in source, but later on they will be mapped:
        alert_type = self.GENERATOR.create_alert_name(rule_generator,product)
        event["event_type"] = alert_type
        event["name"] = alert_type + " " + str(SiemplifyUtils.unix_now())
        event["device_product"] =  product# ie: "device_product" is the field name in arcsight that describes the product the event originated from.

         # usually, the most intresting fields are (again, their precise name, may vary between siems.
        # You are not expected to fill them yourself, just pass them along from the siem. Since this is a dummy generator, We create them manaualy with made up name (PascalCase\CcmelCase doesn't matter)
        event["SourceHostName"] = self.GENERATOR.SOURCE_HOST
        event["DestinationHostName"] = self.GENERATOR.DEST_HOST
        event["SourceAddress"] = self.GENERATOR.SOURCE_IP
        event["DestinationAddress"] = self.GENERATOR.DESTINATION_IP
        event["SourceUserName"] = self.GENERATOR.SOURCE_USERNAME
        event["DestinationUserName"] = self.GENERATOR.DESTINATION_USERNAME
        event["FileName"] = self.GENERATOR.FILENAME
        event["Usb"] = self.GENERATOR.USB
        event["FileHash"] = self.GENERATOR.FILEHASH
        event["Port"] = self.GENERATOR.PORT
        event["CategoryOutcome"] = self.GENERATOR.CATEGORY_OUTCOME

        non_empty_event = {}
        for key in event:
            if (event[key]):
                non_empty_event[key]=event[key]

        # It is also usual, for extra data, to be available, or fetched from the siem. What it is you want. ie:
        # event["IsMalicousByVirusTotal"] =
        # event["PaloAlto_AutoFocus_Tags"] =

        return non_empty_event

    def GenerateDummyCase(self, siemplify, environment):

        # We start by creating a caseInfo object. This represent a siemplify "Alert".
        # An alert, is the siems build in aggregation of basic event ie (Arcsight correlation or QRadar Offense)
        case_info = CaseInfo()
        case_info.events = []
        case_info.source_grouping_identifier = self.GENERATOR.SOURCE_GROUPING_IDENTIFIER
        # each case_info object, must have a uniqe key. The objective of this, is to later validate the same data isn't digested multiple times, creating duplicates in the system.
        # The key is later on built by "Name' + 'TicketId' fields Combination. Make sure its a unique combination! (ie: Arcsight will use: CorrelationName+EventId. QRadar will use: OffenseName+OffenseId)
        # The uniqueness must be persistant, even after Server Restart\ Refetching of the same that from siem, multiple runs of the same API queries, etc.
        case_info.ticket_id = str(uuid.uuid4())  # The ID of the siem alert. Should be the extact ID as saved and identified in the siem. (ie: Arcsight Correlation's EventId, or QRadar OffenseId).

        case_info.rule_generator = self.GENERATOR.RULE_GENERATOR  # Describes the name of the siem's rule, that caused the aggregation of the alert.
        case_info.name =  case_info.rule_generator + " " + str(SiemplifyUtils.unix_now())
        case_info.device_product = self.GENERATOR.create_product(case_info.rule_generator) # This field, may be fetched from the Original Alert. If you build this alert manualy, Describe the source product of the data. (ie: ActiveDirectory, AntiVirus)
        # ----------------------------- Base Events Populating START -----------------------------
        # Build case events here, heres a mock example:
        # First, we wil populate the alert with events:



        for i in range(0,2):
            random_event = self.BuildDummySecurityEvent(environment, case_info.rule_generator, case_info.device_product)
            case_info.events.append(random_event)
        # ----------------------------- Base Events Populating END -----------------------------


        # ----------------------------- Alert Field initilization START -----------------------------


        case_info.environment = environment

        # The alert times may be fetched as the original data of the alert, or recalculated as the minimum+maxsimum times of BaseEvents.
        case_info.start_time =  SiemplifyUtils.unix_now() # Times should be saved in UnixTime. You may use SiemplifyUtils DateTime conversions
        case_info.end_time =  SiemplifyUtils.unix_now()

        # Cases Priority are Calculated by the siemplify Server Algorithem. But, sometimes, the feature may be turned off (To preserve original siem priority).
        # In case this may happen, it is advised to set a default priority value before hand.
        case_info.priority =  60 # Informative = -1,Low = 40,Medium = 60,High = 80,Critical = 100.

        case_info.device_vendor = self.GENERATOR.VENDOR # This field, may be fetched from the Original Alert. If you build this alert manualy, Describe the source vendor of the data. (ie: Microsoft, Mcafee)

        # ----------------------------- Alert Field initilization END -----------------------------

        return case_info

def main():
    # Connectors are run in iterations. The interval is configurable from the ConnectorsScreen UI.
    start_timestamp = SiemplifyUtils.unix_now()
    output_variables = {}

    cases = [] # The main output of each connector run
    siemplify = SiemplifyConnectorExecution() # Siemplify main SDK wrapper

    # ------------ Logging ----------------------
    # It is best to use this logger. It's output will be visible at:
    # "C:\Siemplify_Server\Scripting\SiemplifyConnectorExecution\<Connector's instance name>\logdata.log"
    # "http://localhost:5601 -- default kibana service
    # It is possible to pass the logger class other classes.
    siemplify.LOGGER.info("----Mock Template - Main - STARTED-------")
    # Last logging call must be performed before calling "return_package"

    # log_items is a depricated logging system. each item is a string record. It is passed along via the sdtout, after calling the "return_package" method, So size should be considered.
    # This logs will be passed along the the siemplify server DB, if feature is turned on, via the connector framework.
    log_items = []  #
    # ------------ Logging ----------------------

    # the params passed along from the Framework (as set in the IDE \ Connector screen UI. Can be used to create a more configurable logic, are simply, pass dynamic arguments (ie: Server IP + Credentials)
    params = siemplify.parameters
    siemplify.LOGGER.info("PARAMS:" + str(params))

    # For MSSP, each alert and its baseEvents, will be part of a diffrenet customer environment. In Arcsight, it is distinguished by the "customer_uri" field. Here we create a random:
    environments = ["AAA", "BBB", "CCC"]
    random_environment = environments[random.randint(0, len(environments) - 1)]

    if (GENERATE_ENVIRONMENTS==False):
        random_environment = None

    dummyCon = DummyGenerator(siemplify.LOGGER)
    dummyCase = dummyCon.GenerateDummyCase(siemplify,random_environment)

    # overflow, is a configurable mechanism to limit alert digested by the system, based on a 3 way key (environment, product, ruleGenreator (alertName)
    is_overflow = siemplify.is_overflowed_alert(environment=random_environment,
                                                alert_identifier=str(dummyCase.ticket_id),
                                                #ingestion_time=str(SiemplifyUtils.unix_now()),
                                                #original_file_path=None,
                                                #original_file_content=None,
                                                alert_name=str(dummyCase.rule_generator),
                                                product=str(dummyCase.device_product)
                                                #source_ip=None,
                                                #source_host=None,
                                                #destination_ip=None,
                                                #destination_host=None
                                                )

    if (is_overflow):
        siemplify.LOGGER.warn("Alert {} has overflowed".format(dummyCase.ticket_id), module="DummyConnector", alert_id=dummyCase.ticket_id)
    else:
        cases.append(dummyCase)
        siemplify.LOGGER.info("Alert {} processed by DummyConnector".format(dummyCase.ticket_id), module="DummyConnector", alert_id=dummyCase.ticket_id)

    end_timestamp = SiemplifyUtils.unix_now()
    runtime_ms = end_timestamp-start_timestamp
    siemplify.LOGGER.info("----Mock Template - Main - FINISHED-------",module="OverflowMockConnector",alert_id=dummyCase.ticket_id,miliseconds=runtime_ms)
    # At the and, call the Return_package, to return the result of the connector run, from the python scrpit, back to the Framework.
    siemplify.return_package(cases, output_variables, log_items)

def Test():
    # This method, is called when clicking the Test button in the IDE \ Connector screen UI's
    # This method objective is to validate the connector is ready to run. Here is the place to perform connectivty, credentials, and params test.

    # ------------------ Test Logic - Start -----------------------
    siemplify = SiemplifyConnectorExecution()
    siemplify.LOGGER.info("----Mock Template - Test - STARTED-------")

    # result_params is a free-form dictionary, that will be presented in the UI after clicking the Test button.
    # You may place here whatever you want. Here is an mock example
    result_params = {}
    result_params["Params Validation"] = "Valid" # ie: Valid, Missing Mandatory, Invalid Values,
    result_params["Connectivity Validation"] = "No Ping" # ie: Success, No Ping, No endpoint listening, Timeout, HTTP ErrorCodes
    result_params["Credentials Validation"] = "Valid" # ie: Wrong Username\Password
    result_params["Data Fetching"] = "Valid" # ie: Success, Autherization Problem, No Data, Invalid Query Syntax

    success = True # simple Yes no Anser for Connector Test Success status:

    # overflow, is a configurable mechanism to limit alert digested by the system, based on a 3 way key (environment, product, ruleGenreator (alertName)
    is_overflow = siemplify.is_overflowed_alert(environment="TEST ENV",
                                                alert_identifier="TICKET_ID",
                                                alert_name="RULE_GEN",
                                                product="PRODUCT")

    siemplify.LOGGER.info("----Mock Template - Test - FINISHED-------")
    # ------------------ Test Logic - End -----------------------

    siemplify.return_test_result(success, result_params)

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == 'True':
        print "Main execution started"
        main()
    else:
        print "Test execution started"
        Test()