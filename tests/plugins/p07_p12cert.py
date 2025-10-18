"""stunnel server tests

This test uses a PKCS#12 file with a certificate chain and empty passphrase,
encrypted with PBMAC1 (RFC 9579) and AES-256-CBC — a FIPS-compliant setup
supported by OpenSSL 3.4.0 and later.

On systems with FIPS mode enabled (e.g. Red Hat), OpenSSL versions prior to 3.4.0
fail to handle empty passphrases correctly and prompt for input despite the key
being unencrypted.

To prevent the test from hanging due to such interactive prompts, the subprocess
running stunnel is detached from the controlling terminal by creating a new session
(preexec_fn=os.setsid). This blocks the child process from accessing /dev/tty
and disables interactive password prompts.

Consequently, if FIPS mode is active and the OpenSSL version is less than 3.4.0,
the test is skipped.
"""

import logging
import pathlib
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import (
    Config,
    StunnelAcceptConnect
)


class StunnelTest(StunnelAcceptConnect):
    """Base class for stunnel server tests."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_client = True
        self.params.services = ['server']


class Certp12Test(StunnelTest):
    """Checking if the file containing certificates used by stunnel to authenticate
       itself against the remote client may be in the P12 format.
       The success is expected because the server presents the valid certificate in the P12 format.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '071. Test PKCS#12 certificate'
        self.params.context = 'load_verify_locations"'
        self.events.skip = [
            "passphrase callback error"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            ERR_CONN_RESET,
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel server."""
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.p12
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class StunnelServerTest(Plugin):
    """Stunnel server tests:
       HTTPS client --> stunnel server --> HTTP server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Existing PKCS#12 certificate'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = Certp12Test(cfg, logger)
        await stunnel.test_stunnel(cfg)
