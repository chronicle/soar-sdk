from SiemplifyVaultCyberArkPam import SiemplifyVaultCyberArkPam

# vault providers enums
CYBERARK_VAULT_PROVIDER = 0

# the vault factory class creates the vault correct vault provider according to the vault type
class VaultProviderFactory:
    @staticmethod
    def create_vault_class_by_provider_type(vault_settings):
        if vault_settings is None:
            raise Exception("Vault settings were not supplied")
        provider_type = vault_settings.get('vault_type', CYBERARK_VAULT_PROVIDER)
        
        # For now we only support CyberArkVault provider 
        if provider_type == CYBERARK_VAULT_PROVIDER:
            return SiemplifyVaultCyberArkPam(vault_settings)
        else:
            raise Exception("The vault provider {0} is not supported".format(provider_type))
