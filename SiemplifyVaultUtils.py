import re
from SiemplifyUtils import is_str_instance
from SiemplifyVaultCyberArkPam import SiemplifyVaultCyberArkPam
from VaultProviderFactory import VaultProviderFactory


# CONSTS
REGEX_CONFIGURATION = r"(?<=\[)[^[\]\:]*:::[^[\]]*(?=])"
EXTERNAL_PROVIDER_SEPARATOR = ":::"
SEPARATOR_AMOUNT = 3
ACCOUNT_ID_POSITION = 3

def extract_vault_param(configuration_item, vault_settings):
        """
        extract vault param
        :param configuration_item: {string} connector parameter (or vault placeholder)
        :param vault_settings: {VaultSettings json}
        :return: if regular param, return the value. if vault param, get the vault from vault {string}
        """

        if is_str_instance(configuration_item):        
            # Support new usage of get_configuration using vault for exp [AAA:::CyberArkVault:::CyberArkVault_1:::property_id]
            if (configuration_item.count(EXTERNAL_PROVIDER_SEPARATOR) == SEPARATOR_AMOUNT):
                for placeholder in re.findall(REGEX_CONFIGURATION, configuration_item):
                    account_id = placeholder.split(EXTERNAL_PROVIDER_SEPARATOR, SEPARATOR_AMOUNT)[ACCOUNT_ID_POSITION]              
                    configuration_item = configuration_item.replace("[{}]".format(placeholder),
                    get_vault_secret(account_id, vault_settings))

        return configuration_item
        
def get_vault_secret(account_id, vault_settings):
    """
    Get vault secret (password) using the id of the secret (account_id) and the vault_settings
    :param account_id: {string}
    :param vault_settings: {VaultSettings json}
    """
    try:
        vault_manager = VaultProviderFactory.create_vault_class_by_provider_type(vault_settings)
        return vault_manager.get_password(account_id)
    except Exception as e:
        raise Exception("Couldn't get vault password from account id " + account_id + ": " + str(e))