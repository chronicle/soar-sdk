import sys
import json
import requests
import SiemplifyUtils

"""
Base vault class. All vault provider managers should inherit from it.
"""
class SiemplifyVault(object):
    def __init__(self, vault_settings):
        # Extract and validate vault parameters
        if vault_settings is not None:
            self.session = requests.Session()
            self.api_root = vault_settings.get('vault_api_root', None)
            self.verify_ssl = vault_settings.get('vault_verify_ssl', False)
            self.username = vault_settings.get('vault_username', None)
            self.password = vault_settings.get('vault_password', None)
            self.client_ca_certificate = vault_settings.get('vault_client_ca_certificate', None)
            self.client_certificate = vault_settings.get('vault_client_certificate', None)
            self.client_certificate_passphrase = vault_settings.get('vault_client_certificate_passphrase', None)
            self.validate_vault_params()
        
    def validate_vault_params(self):        
        if not self.username or not self.password or not self.api_root:
            raise Exception("Cannot initialize vault. Missing parameters")     