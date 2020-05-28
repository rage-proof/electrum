from functools import partial
import os
import sys
import asyncio

from PyQt5.QtWidgets import (QHBoxLayout, QLabel, QVBoxLayout, QGridLayout)

from electrum.plugin import BasePlugin, hook
from electrum.interface import ServerAddr
from electrum import x509, pem
from electrum.gui.qt.util import (ThreadedButton, Buttons, EnterButton, WindowModalDialog, OkButton, CloseButton)
from electrum.i18n import _


class Plugin(BasePlugin):
    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)

        self.default_server = self.config.get('server', None)
        if self.default_server:
            try:
                self.default_server = ServerAddr.from_str(self.default_server)
            except:
                self.default_server = None
        self.logger.info(f'Set default Server: {self.default_server}')


        #self.parent # existiert bereits #class=Plugins
        self.ssl_clientcert = self.config.get('ssl_clientcert', None)
        self.ssl_clientkey = self.config.get('ssl_clientkey', None)
        self.use_client_certificate = self.config.get('use_client_certificate', None)
        if self.ssl_clientcert and self.ssl_clientkey and self.use_client_certificate:
            self.logger.info(f'Using client certificate')

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'), partial(self.settings_dialog, window))


    def settings_dialog(self, window):
        d = WindowModalDialog(window, _("SSL Settings"))
        d.setMinimumSize(500, 200)
        vbox = QVBoxLayout(d)
        grid = QGridLayout()
        vbox.addLayout(grid)
        grid.addWidget(QLabel('SSL Certificate'), 0, 0)
        grid.addWidget(QLabel('SSL Key'), 1, 0)


        vbox.addStretch()
        vbox.addLayout(Buttons(CloseButton(d), OkButton(d)))
        d.show()
        return bool(d.exec_())




    @hook
    def init_qt(self, gui):
        network = gui.daemon.network
        if not network or not self.default_server:
                return
        if not self.ssl_clientcert or not self.ssl_clientkey or not self.use_client_certificate:
                return
        if not self._is_client_ssl_valid():
                return
        interfaces = gui.daemon.network.get_interfaces()#
        self.logger.info(f'Ausgabe Interfaces: {interfaces}')#
        self.logger.info(f'2. Ausgabe Interfaces {gui.daemon.network.interfaces}')#



    def _is_client_ssl_valid(self):
        #copied from interface
        if not os.path.exists(self.ssl_clientcert):
            return False
        with open(self.ssl_clientcert, 'r') as f:
            contents = f.read()
        try:
            b = pem.dePem(contents, 'CERTIFICATE')
            x = x509.X509(b)
        except (SyntaxError, Exception) as e:
            self.logger.info(f"error parsing cert: {e}")
            return False
        try:
            x.check_date()
            return True
        except x509.CertificateError as e:
            self.logger.info(f"certificate has expired: {e}")
            return False
