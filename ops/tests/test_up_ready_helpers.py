import base64
import os
import stat
import tempfile
import unittest
from pathlib import Path

from sslproxy_ops.commands.up_ready import apply_profile_runtime_env, preflight
from sslproxy_ops.commands.up_ready.checks import (
    discover_peer_configs,
    runtime_obfuscation_value,
    write_credential_handoff,
)
from sslproxy_ops.commands.up_ready.model import (
    UpReadyContext,
    UpReadyError,
    desired_obfuscation_value,
)
from sslproxy_ops.commands.up_ready.peers import (
    ensure_local_peer_material,
    ensure_one_peer_material,
    ensure_private_config_mode,
    ensure_unique_peer_tunnel_addresses,
    generate_peer_preshared_key,
    peer_material_complete,
    peer_tunnel_address,
    render_direct_peer_config,
    write_secret_text,
)
from sslproxy_ops.commands.up_ready.secrets import (
    registry_host_value,
    registry_plain_http_enabled,
)
from sslproxy_ops.config import Settings


class UpReadyHelpersTest(unittest.TestCase):
    def test_kubernetes_preflight_requires_public_hostname_before_mutation(self):
        settings = Settings()
        settings.deployment_target = "kubernetes"
        settings.schema_migrator_public_hostname = None
        settings.acme_email = None
        ctx = UpReadyContext(settings=settings)

        with (
            unittest.mock.patch(
                "sslproxy_ops.commands.up_ready.ensure_secret_bootstrap"
            ) as secret_bootstrap,
            self.assertRaisesRegex(UpReadyError, "SCHEMA_MIGRATOR_PUBLIC_HOSTNAME"),
        ):
            preflight(ctx)

        secret_bootstrap.assert_not_called()

    def test_kubernetes_preflight_requires_acme_email_before_mutation(self):
        settings = Settings()
        settings.deployment_target = "kubernetes"
        settings.schema_migrator_public_hostname = "schema.example.com"
        settings.acme_email = None
        ctx = UpReadyContext(settings=settings)

        with (
            unittest.mock.patch(
                "sslproxy_ops.commands.up_ready.ensure_secret_bootstrap"
            ) as secret_bootstrap,
            self.assertRaisesRegex(UpReadyError, "ACME_EMAIL"),
        ):
            preflight(ctx)

        secret_bootstrap.assert_not_called()

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
            direct.write_text(
                "[Interface]\nPrivateKey = <peer1-private-key>\n"
                "[Peer]\nPublicKey = server-public\nPresharedKey = value\n"
            )
            obfuscated.write_text(
                "[Interface]\nPrivateKey = value\n"
                "[Peer]\nPublicKey = server-public\nPresharedKey = value\n"
            )

            with unittest.mock.patch("sslproxy_ops.commands.up_ready.peers.repo_root", return_value=root):
                self.assertFalse(peer_material_complete("peer1"))

                direct.write_text(
                    "[Interface]\nPrivateKey = value\n"
                    "[Peer]\nPublicKey = <server-public-key>\nPresharedKey = value\n"
                )
                self.assertFalse(peer_material_complete("peer1"))

                direct.write_text(
                    "[Interface]\nPrivateKey = value\n"
                    "[Peer]\nPublicKey = server-public\nPresharedKey = value\n"
                )
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

    def test_owner_managed_private_config_accepts_chmod_permission_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "peer.conf"
            path.write_text("secret\n")
            path.chmod(0o600)

            with unittest.mock.patch(
                "sslproxy_ops.commands.up_ready.peers.os.chmod",
                side_effect=PermissionError("owner-managed"),
            ):
                ensure_private_config_mode(path)

    def test_owner_managed_permissive_config_rejects_chmod_permission_error(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "peer.conf"
            path.write_text("secret\n")
            path.chmod(0o644)

            with (
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.peers.os.chmod",
                    side_effect=PermissionError("owner-managed"),
                ),
                self.assertRaisesRegex(UpReadyError, "chmod 600"),
            ):
                ensure_private_config_mode(path)

    def test_complete_mac_material_does_not_rewrite_direct_profile(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            peer_dir = root / "config" / "peer1"
            server_dir = root / "config" / "server"
            peer_dir.mkdir(parents=True)
            server_dir.mkdir(parents=True)
            (server_dir / "privatekey-server").write_text("server-private\n")
            (server_dir / "publickey-server").write_text("server-public\n")
            (peer_dir / "privatekey-peer1").write_text("private\n")
            (peer_dir / "publickey-peer1").write_text("public\n")
            (peer_dir / "presharedkey-peer1").write_text("preshared\n")
            resolved = (
                "[Interface]\nPrivateKey = private\n"
                "[Peer]\nPublicKey = server-public\nPresharedKey = preshared\n"
            )
            (peer_dir / "peer1.conf").write_text(resolved)
            (peer_dir / "peer1-obfuscated.conf").write_text(resolved)
            settings = Settings()
            settings.profile_mode = "mac"
            ctx = UpReadyContext(settings=settings)

            with (
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.peers.repo_root", return_value=root
                ),
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.peers.render_direct_peer_config"
                ) as render_direct,
                unittest.mock.patch.dict(os.environ, {"WG_PEERS": "peer1"}, clear=False),
            ):
                ensure_local_peer_material(ctx)

            render_direct.assert_not_called()

    def test_mac_material_repair_preserves_resolved_direct_profile(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            peer_dir = root / "config" / "peer1"
            peer_dir.mkdir(parents=True)
            (peer_dir / "privatekey-peer1").write_text("private\n")
            (peer_dir / "publickey-peer1").write_text("public\n")
            (peer_dir / "presharedkey-peer1").write_text("preshared\n")
            (peer_dir / "peer1.conf").write_text(
                "[Interface]\nPrivateKey = private\n"
                "[Peer]\nPublicKey = server-public\nPresharedKey = preshared\n"
            )
            settings = Settings()
            settings.profile_mode = "mac"
            ctx = UpReadyContext(settings=settings)

            with (
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.peers.repo_root", return_value=root
                ),
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.peers.render_direct_peer_config"
                ) as render_direct,
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.peers.render_obfuscated_peer_config"
                ) as render_obfuscated,
            ):
                ensure_one_peer_material(ctx, "peer1", "server-public")

            render_direct.assert_not_called()
            render_obfuscated.assert_called_once_with(
                "peer1", "private", "preshared", "server-public"
            )

    def test_registry_helpers(self):
        self.assertEqual(registry_host_value("http://192.168.1.2:5000/foo"), "192.168.1.2:5000")
        self.assertTrue(registry_plain_http_enabled("192.168.1.2:5000", "auto"))
        self.assertFalse(registry_plain_http_enabled("registry.example.com", "auto"))

    def test_iphone_mode_keeps_server_obfuscation_enabled(self):
        self.assertEqual(desired_obfuscation_value("iphone"), "true")

        settings = Settings()
        settings.profile_mode = "iphone"
        ctx = UpReadyContext(settings=settings)
        with (
            unittest.mock.patch(
                "sslproxy_ops.commands.up_ready.ensure_admin_api_key_file"
            ),
            unittest.mock.patch(
                "sslproxy_ops.commands.up_ready.activate_obfuscation_key_env_fallback"
            ) as activate_key,
            unittest.mock.patch.dict(os.environ, {}, clear=False),
        ):
            apply_profile_runtime_env(ctx)
            self.assertEqual(os.environ["WG_OBFUSCATION_ENABLED"], "true")
            self.assertEqual(os.environ["WG_PORT"], "443")
            self.assertEqual(os.environ["WG_INTERNAL_PORT"], "51820")
            self.assertTrue(settings.wg_obfuscation_enabled)
            self.assertEqual(settings.wg_port, 443)
            self.assertEqual(settings.wg_internal_port, 51820)
            activate_key.assert_called_once_with()

    def test_direct_profile_uses_plain_internal_port_without_listen_port(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            with (
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.peers.repo_root", return_value=root
                ),
                unittest.mock.patch.dict(
                    os.environ,
                    {
                        "WG_OBFUSCATION_ENABLED": "true",
                        "WG_PORT": "443",
                        "WG_INTERNAL_PORT": "51820",
                    },
                    clear=False,
                ),
            ):
                render_direct_peer_config(
                    "peer1", "private", "preshared", "192.0.2.10", "server-public"
                )

            profile = (root / "config" / "peer1" / "peer1.conf").read_text()
            self.assertIn("Endpoint = 192.0.2.10:51820", profile)
            self.assertIn("PublicKey = server-public", profile)
            self.assertNotIn("<server-public-key>", profile)
            self.assertNotIn("Endpoint = 127.0.0.1", profile)
            self.assertNotIn("ListenPort =", profile)

    def test_iphone_config_discovery_refuses_obfuscated_fallback(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            peer_dir = root / "config" / "peer1"
            peer_dir.mkdir(parents=True)
            (peer_dir / "publickey-peer1").write_text("public\n")
            (peer_dir / "peer1-obfuscated.conf").write_text("[Interface]\n")
            settings = Settings()
            settings.profile_mode = "iphone"
            settings.server_ip = "192.0.2.10"
            settings.client_ip = "192.0.2.20"
            ctx = UpReadyContext(settings=settings)

            with unittest.mock.patch(
                "sslproxy_ops.commands.up_ready.checks.repo_root", return_value=root
            ):
                with self.assertRaises(UpReadyError):
                    discover_peer_configs(ctx)

    def test_iphone_handoff_contains_direct_profile_only(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            peer_dir = root / "config" / "peer1"
            secret_dir = root / "secrets"
            peer_dir.mkdir(parents=True)
            secret_dir.mkdir()
            schema_secret_dir = secret_dir / "schema-migrator"
            schema_secret_dir.mkdir()
            for name in [
                "postgres.key",
                "grafana_admin_password.key",
                "admin_api_key",
                "wg_obfuscation_key",
            ]:
                (secret_dir / name).write_text(f"{name}-value\n")
            (schema_secret_dir / "application_admin_password.key").write_text(
                "temporary-schema-password\n"
            )
            (peer_dir / "peer1.conf").write_text(
                "[Interface]\nPrivateKey = private\n"
                "[Peer]\nEndpoint = 192.0.2.10:51820\n"
            )
            (peer_dir / "peer1-obfuscated.conf").write_text(
                "[Peer]\nEndpoint = 127.0.0.1:51821\n"
            )
            output = secret_dir / "handoff.txt"
            settings = Settings()
            settings.profile_mode = "iphone"
            settings.server_ip = "192.0.2.10"
            settings.client_ip = "192.0.2.20"
            settings.schema_migrator_public_hostname = "schema.example.com"
            settings.credential_handoff_file = output
            ctx = UpReadyContext(settings=settings)

            with (
                unittest.mock.patch(
                    "sslproxy_ops.commands.up_ready.checks.repo_root", return_value=root
                ),
                unittest.mock.patch.dict(os.environ, {"WG_PEERS": "peer1"}, clear=False),
            ):
                write_credential_handoff(ctx)

            handoff = output.read_text()
            self.assertIn("Endpoint = 192.0.2.10:51820", handoff)
            self.assertNotIn("## WireGuard shim", handoff)
            self.assertNotIn("WG_OBFS_", handoff)
            self.assertNotIn("obfuscated config", handoff)
            self.assertNotIn("127.0.0.1:51821", handoff)
            self.assertIn("url=https://schema.example.com", handoff)
            self.assertIn("username=schema-admin", handoff)
            self.assertIn("temporary_password=temporary-schema-password", handoff)
            self.assertIn("password_change_required=true", handoff)


if __name__ == "__main__":
    unittest.main()
