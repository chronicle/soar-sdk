import configparser
from os import getenv, path


class SiemplifySdkConfig:
    config_file_path = path.join(path.dirname(__file__), 'sdk_config.ini')

    def __init__(self):
        self._config = configparser.ConfigParser()
        self._config.read(self.config_file_path)
        self.api_root_uri = self._build_api_server_uri()
        self.run_folder_path = self._config.get('ExecutionConfig', 'runFolderPath')
        self.is_remote_publisher_sdk = self._config.getboolean('ExecutionConfig', 'IsRemotePublisherSdk', fallback=False)
        self.ignore_ca_bundle = self._config.getboolean('ExecutionConfig', 'IgnoreCaBundle', fallback=False)

    def _build_api_server_uri(self):
        use_ssl_env = self._safe_cast(getenv('APP_USE_SSL'), bool)
        use_ssl = use_ssl_env if use_ssl_env is not None else self._config.getboolean('ServerService', 'UseSsl', fallback=True)
        _scheme = 'https' if use_ssl else 'http'
        _host = getenv('APP_IP', self._config.get('ServerService', 'Host', fallback='localhost'))
        _port = self._safe_cast(getenv('APP_PORT'), int) or self._config.getint('ServerService', 'Port', fallback=8443)
        return "{}://{}:{}/api".format(_scheme, _host, _port)

    @staticmethod
    def _safe_cast(val, to_type, default=None):
        try:
            _val = eval(val)
            return _val if type(_val) == to_type else default
        except (ValueError, TypeError, NameError):
            return default
