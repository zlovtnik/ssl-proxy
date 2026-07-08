import base64
import os
import stat
import tempfile
import unittest
from pathlib import Path

from sslproxy_ops.commands.up_ready.peers import (
    ensure_unique_peer_tunnel_addresses,
    generate_peer_preshared_key,
    peer_material_complete,
    peer_tunnel_address,
    write_secret_text,
)
from sslproxy_ops.commands.up_ready.checks import runtime_obfuscation_value
from sslproxy_ops.commands.up_ready.model import UpReadyError
from sslproxy_ops.commands.up_ready.secrets import (
    registry_host_value,
    registry_plain_http_enabled,
)


class UpReadyHelpersTest(unittest.TestCase):
    def test_peer_tunnel_address(self):
        self.assertEqual(peer_tunnel_address("peer1"), "10.13.13.2/32")
        self.assertEqual(peer_tunnel_address("peer7"), "10.13.13.8/32")
        self.assertTrue(peer_tunnel_address("laptop").startswith("10.13.13."))

    def test_duplicate_peer_tunnel_addresses_raise(self):
        with self.assertRaises(UpReadyError):
            ensure_unique_peer_tunnel_addresses(["peer1", "bia"])

    def test_peer_material_rejects_placeholder_config_keys(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            peer_dir = root / "config" / "peer1"
            peer_dir.mkdir(parents=True)
            for name in ["privatekey-peer1", "publickey-peer1", "presharedkey-peer1"]:
                (peer_dir / name).write_text("value\n")
            direct = peer_dir / "peer1.conf"
            obfuscated = peer_dir / "peer1-obfuscated.conf"
            direct.write_text("[Interface]\nPrivateKey = <peer1-private-key>\n[Peer]\nPresharedKey = value\n")
            obfuscated.write_text("[Interface]\nPrivateKey = value\n[Peer]\nPresharedKey = value\n")

            with unittest.mock.patch("sslproxy_ops.commands.up_ready.peers.repo_root", return_value=root):
                self.assertFalse(peer_material_complete("peer1"))

                direct.write_text("[Interface]\nPrivateKey = value\n[Peer]\nPresharedKey = value\n")
                self.assertTrue(peer_material_complete("peer1"))

    def test_runtime_obfuscation_accepts_service_name(self):
        completed = unittest.mock.Mock(stdout="old wg_obfuscation_enabled=false\nwg_obfuscation_enabled=true\n")

        with unittest.mock.patch("sslproxy_ops.commands.up_ready.checks.shell.compose", return_value=completed) as mocked:
            self.assertEqual(runtime_obfuscation_value("ssl-proxy"), "true")

        self.assertEqual(mocked.call_args.args[:4], ("logs", "--tail", "200", "ssl-proxy"))

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
