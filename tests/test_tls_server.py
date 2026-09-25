"""A stalled TLS client must not block every other panel connection."""

import http.client
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest


class TLSServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cert = Path(cls.tempdir.name, "cert.pem")
        key = Path(cls.tempdir.name, "key.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=localhost",
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        os.environ["PANEL_DOMAIN"] = "localhost"
        os.environ["PANEL_SECRET"] = "test-secret"
        os.environ["PANEL_DB"] = str(Path(cls.tempdir.name, "panel.db"))
        os.environ["PANEL_CERT"] = str(cert)
        os.environ["PANEL_KEY"] = str(key)
        os.environ["PANEL_PORT"] = "0"
        path = Path(__file__).resolve().parents[1] / "app.py"
        spec = importlib.util.spec_from_file_location("hysteria_control_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.server = module.PanelServer()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.tempdir.cleanup()

    def test_stalled_handshake_does_not_block_login(self):
        port = self.server.server_address[1]
        stalled = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", port,
                context=ssl._create_unverified_context(), timeout=2,
            )
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertIn(b"Hysteria Control", response.read())
            finally:
                connection.close()
        finally:
            stalled.close()


if __name__ == "__main__":
    unittest.main()
