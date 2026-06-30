import base64
import os
import stat
import tempfile
import unittest
from pathlib import Path

from sslproxy_ops.commands.up_ready.peers import (
    generate_peer_preshared_key,
    peer_tunnel_address,
    write_secret_text,
)
from sslproxy_ops.commands.up_ready.secrets import (
    registry_host_value,
    registry_plain_http_enabled,
)


class UpReadyHelpersTest(unittest.TestCase):
    def test_peer_tunnel_address(self):
        self.assertEqual(peer_tunnel_address("peer1"), "10.13.13.2/32")
        self.assertEqual(peer_tunnel_address("peer7"), "10.13.13.8/32")
        self.assertTrue(peer_tunnel_address("laptop").startswith("10.13.13."))

    def test_preshared_key_is_32_random_bytes_base64(self):
        value = generate_peer_preshared_key()
        self.assertEqual(len(base64.b64decode(value)), 32)

    def test_write_secret_text_sets_mode(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "secret"
            write_secret_text(path, "value", 0o600)
            self.assertEqual(path.read_text(), "value\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_registry_helpers(self):
        self.assertEqual(registry_host_value("http://192.168.1.2:5000/foo"), "192.168.1.2:5000")
        self.assertTrue(registry_plain_http_enabled("192.168.1.2:5000", "auto"))
        self.assertFalse(registry_plain_http_enabled("registry.example.com", "auto"))


if __name__ == "__main__":
    unittest.main()

