import sys
import json
import requests
import base64
try:
    from urllib.parse import urljoin
except ImportError:
     from urlparse import urljoin
from SiemplifyVault import SiemplifyVault
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from typing import Optional
from requests_toolbelt.adapters.x509 import X509Adapter

# CONSTS
CA_CERT_PATH = "cacert.pem"
URLS = {
    "get_access_token": "/PasswordVault/API/Auth/CyberArk/Logon",
    "get_password": "PasswordVault/API/Accounts/{account_id}/Password/Retrieve/"
}
MAX_RETRIES = 1
GET_TOKEN_TIMEOUT = 60

# vault manager class, includes the logic that contact the remote vault provider
# supports python2.7 and python 3.7
class CyberArkPamManagerError(Exception):
    """
    General Exception for CyberArk PAM manager
    """
    pass


class CyberArkPamNotFoundError(CyberArkPamManagerError):
    """
    Not Found Exception for CyberArk PAM manager
    """
    pass


class SiemplifyVaultCyberArkPam(SiemplifyVault):
    """
    CyberArk PAM Manager
    """
    def __init__(self, vault_settings):
        super(SiemplifyVaultCyberArkPam, self).__init__(vault_settings)
        self.__set_certificates(
            self.client_certificate_passphrase,
            self.client_certificate
        )
        self.__set_verify(self.verify_ssl, self.client_ca_certificate)
        self.session.headers.update({
            "Content-Type": "application/json",
            "Authorization": self.__get_access_token(
                self.username, self.password
            )
        })

    def __set_certificates(self, client_certificate_passphrase = None,
                           client_certificate = None):
        if not client_certificate:
            return

        backend = default_backend()
        encoded_cert = base64.b64decode(client_certificate)
        encoded_passphrase = (
            client_certificate_passphrase.encode("utf-8")
            if client_certificate_passphrase is not None
            else client_certificate_passphrase
        )

        decoded_cert = load_key_and_certificates(
            data=encoded_cert,
            password=encoded_passphrase,
            backend=backend
        )

        cert_bytes = decoded_cert[1].public_bytes(Encoding.DER)
        pk_bytes = decoded_cert[0].private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        adapter = X509Adapter(
            max_retries=MAX_RETRIES,
            cert_bytes=cert_bytes,
            pk_bytes=pk_bytes,
            encoding=Encoding.DER
        )
        self.session.mount('https://', adapter)

    def __set_verify(self, verify_ssl, ca_certificate=None):
        """
        Set verify ssl
        :param verify_ssl: {bool} True if verify ssl
        :param ca_certificate: {str} CA certificate
        """
        if verify_ssl and ca_certificate:
            ca_cert = base64.b64decode(ca_certificate)
            with open(CA_CERT_PATH, "w+") as f:
                f.write(ca_cert.decode())

            self.session.verify = CA_CERT_PATH
        elif verify_ssl:
            self.session.verify = True
        else:
            self.session.verify = False

    def __build_full_uri(self, url_key, **kwargs):
        """
        Build full uri from url key
        :param url_key: {str} The key
        :param kwargs: {dict} Variables passed for string formatting
        :return: {str} The full uri
        """
        return urljoin(self.api_root, URLS[url_key].format(**kwargs))

    def __get_access_token(self, username, password):
        """
        Get token from CyberArk PAM
        :param username
        :param password
        :return: {str} Token
        """
        payload = {
            'username': username,
            'password': password
        }

        response = self.session.post(
            url=self.__build_full_uri('get_access_token'),
            json=payload,
            timeout=GET_TOKEN_TIMEOUT
        )
        self.validate_response(response)
        return response.text[1:-1]

    @staticmethod
    def validate_response(response):
        """
        Check for error
        """
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                raise CyberArkPamNotFoundError(e)
            raise CyberArkPamManagerError(e)

    def get_password(self, account):
        payload = {
            "reason": "Chronicle SOAR vault integration"
        }
        prepared_payload = {
            key: value for key, value in payload.items()
            if value is not None
        }

        response = self.session.post(
            url=self.__build_full_uri('get_password', account_id=account),
            json=prepared_payload
        )
        self.validate_response(response)
        # we get the secret with "", we remove it and return the clean secret
        return response.text[1:-1]