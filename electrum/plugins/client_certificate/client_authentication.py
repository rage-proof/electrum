import asyncio
import os
import ssl
from typing import NamedTuple, Optional, Sequence, List, Dict, Tuple, TYPE_CHECKING, Iterable

from electrum.interface import ServerAddr, ca_path, Interface as BaseInterface


class AuthInterface(BaseInterface):

    def __init__(self, *, network: 'Network', server: ServerAddr, proxy: Optional[dict]):
        self.ssl_clientkey = network.config.get('ssl_clientkey', None)
        self.ssl_clientcert = network.config.get('ssl_clientcert', None)
        self.config_server = network.config.get('server', None)
        self.logger.info(f'Test Test Test Test Test Test Test TestTest Test Test Test')
        super().__init__(network, server, proxy)


    async def _get_ssl_context(self):
        sslc = await super()._get_ssl_context()
        if self.is_config_server() and self.is_client_cert_available():
            sslc.load_cert_chain(certfile=self.ssl_clientcert, keyfile=self.ssl_clientkey)
            self.logger.info(f'client certificate {self.ssl_clientcert} used for client authentification.')
            self.logger.info(f'active.')
        return sslc


    def is_config_server(self) -> bool:
        print('config_server ',self.config_server)#
        print('server ',self.server)#
        return self.config_server == self.server


    def is_client_cert_available(self) -> bool:
        print('certs? ',self.ssl_clientkey and self.ssl_clientcert)#
        return self.ssl_clientkey and self.ssl_clientcert
