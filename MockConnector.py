from SiemplifyConnectors import SiemplifyConnectorExecution
from SiemplifyConnectorsDataModel import CaseInfo
import SiemplifyUtils
from SimulatedCasesCreator import SimulatedCasesCreator
from SiemplifyMock import SiemplifyConnectorMock

import uuid
import sys
import random

def get_source_files():
    files = ["PhishinEmail1.py"]
    return files

def main():
    output_variables = {}

    cases = [] # The main output of each connector run
    siemplify = SiemplifyConnectorMock() # Siemplify main SDK wrapper

    siemplify.LOGGER.info("----Mock Template - Main - STARTED-------")

    log_items = []  #
    params = siemplify.parameters

    simulation_source_files = get_source_files()

    simulated_cases_creator = SimulatedCasesCreator()

    for file in simulation_source_files:
        simulated_cases = simulated_cases_creator.create_cases_from_json(file)
        cases.append(simulated_cases)

    siemplify.LOGGER.info("----Mock Template - Main - FINISHED-------", module="Simulation cases Creator")

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
        print("Main execution started")
        main()
    else:
        print("Test execution started")
        Test()