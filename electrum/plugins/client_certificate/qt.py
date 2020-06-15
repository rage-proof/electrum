from functools import partial
import os
import sys
import asyncio
import ssl

from PyQt5.QtWidgets import (QHBoxLayout, QVBoxLayout, QLabel, QGridLayout,
                             QPushButton, QFileDialog, QLineEdit, QFormLayout,
                             QMessageBox)

from electrum.plugin import BasePlugin, hook
from electrum.interface import ServerAddr
from electrum import x509, pem
from electrum.gui.qt.util import (ThreadedButton, Buttons, EnterButton, WindowModalDialog,
                                  OkButton, CloseButton, CancelButton)
from electrum.i18n import _


class OkButtonCheck(OkButton):
    def __init__(self, dialog):
        super().__init__(self, dialog)
        self.clicked.connect(self.accept)

    def accept(self):
        dialog.accept

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
        fbox = QFormLayout()
        vbox.addLayout(fbox)
        
        hbox = QHBoxLayout()
        cert_name_e = QLineEdit()
        button_cert = QPushButton(_('Choose...'))
        hbox.addWidget(cert_name_e)
        hbox.addWidget(button_cert)
        fbox.addRow(QLabel(_('SSL Certificate') + ':'),hbox)
        
        hbox2 = QHBoxLayout()
        key_name_e = QLineEdit()
        button_key = QPushButton(_('Choose...'))
        hbox2.addWidget(key_name_e)
        hbox2.addWidget(button_key)
        fbox.addRow(QLabel(_('SSL Key') + ':'),hbox2)
       
        def on_choose_cert():
            path, __ = QFileDialog.getOpenFileName(window, "Select your certificate file", self.config.path)
            if path:
                cert_name_e.setText(path)
        def on_choose_key():
            path, __ = QFileDialog.getOpenFileName(window, "Select your priate key file", self.config.path)
            if path:
                key_name_e.setText(path)

        def on_ok():
            button_ok.setDefault(True)
            cert = cert_name_e.text()
            key = key_name_e.text()
            try:
                self._is_client_ssl_valid(cert, key)
                self.config.set_key('ssl_clientcert', cert, True)
                self.config.set_key('ssl_clientkey', key, True)
                d.accept()
            except Exception as e:
                self.show_alert(f'{e}')
                 
        vbox.addStretch()
        button_ok = QPushButton(_('OK'))
        vbox.addLayout(Buttons(CancelButton(d), button_ok))

        self._get_ssl_files()
        if self.ssl_clientcert:
            cert_name_e.setText(self.ssl_clientcert)
        if self.ssl_clientkey:
            key_name_e.setText(self.ssl_clientkey)
        button_cert.clicked.connect(on_choose_cert)
        button_key.clicked.connect(on_choose_key)
        button_ok.clicked.connect(on_ok)
        d.show()
        return bool(d.exec_())
    
    def _get_ssl_files(self):
        self.ssl_clientcert = self.config.get('ssl_clientcert', None)
        self.ssl_clientkey = self.config.get('ssl_clientkey', None)

    @hook
    def init_qt(self, gui):
        network = gui.daemon.network
        if not network or not self.default_server:
                return
        if not self.ssl_clientcert or not self.ssl_clientkey or not self.use_client_certificate:
                return
        #if not self._is_client_ssl_valid():
        interfaces = gui.daemon.network.get_interfaces()#
        self.logger.info(f'Ausgabe Interfaces: {interfaces}')#
        self.logger.info(f'2. Ausgabe Interfaces {gui.daemon.network.interfaces}')#



    def _is_client_ssl_valid(self, client_cert, client_key):
        #copied from interface.py and adjusted
        if not os.path.exists(client_cert):
            raise FileNotFoundError('cert file does not exist')
        if not os.path.exists(client_key):
            raise FileNotFoundError('key file does not exist')
        
        with open(client_cert, 'r') as f:
            content_cert = f.read()        
        with open(client_key, 'r') as f:
            content_key = f.read()
        
        try:
            b = pem.dePem(content_cert, 'CERTIFICATE')
        except SyntaxError as e:
            self.logger.info(f"error parsing client cert: {e}")
            raise
        try:
            x = x509.X509(b)
        except Exception as e:
            self.logger.info(f"error parsing client cert: {e}")
            raise

        try:
            b = pem.parse_private_key(content_key)
            x.check_date()
            context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        except SyntaxError as e:
            self.logger.info(f"error parsing client priv key: {e}")
            raise
        except x509.CertificateError as e:
            self.logger.info(f"certificate has expired: {e}")
            raise
        except ssl.SSLError as e:
            self.logger.info(f"cert and priv key are invalid: {e}")
            raise

    def show_alert(self, alert_msg):
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Information)
            msg.setWindowTitle("Client SSL Error")
            msg.setText("Client Authentication invalid")
            msg.setInformativeText(alert_msg)           
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
            
