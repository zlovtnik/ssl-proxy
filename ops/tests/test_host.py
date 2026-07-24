import unittest

from sslproxy_ops.commands.host import (
    containerd_config_version,
    containerd_registry_hosts_toml,
    k3s_registries_yaml,
    normalize_registry_authority,
)


class HostCommandTest(unittest.TestCase):
    def test_normalizes_registry_authority(self):
        self.assertEqual(
            normalize_registry_authority("http://192.168.1.221:5000/"),
            "192.168.1.221:5000",
        )

    def test_rejects_registry_paths(self):
        with self.assertRaises(ValueError):
            normalize_registry_authority("192.168.1.221:5000/team")

    def test_rejects_dot_only_registry_authorities(self):
        for authority in (".", "..", "http://./", "https://../"):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                normalize_registry_authority(authority)

    def test_plain_http_hosts_toml_is_pull_only(self):
        rendered = containerd_registry_hosts_toml(
            "192.168.1.221:5000", plain_http=True
        )

        self.assertIn('server = "http://192.168.1.221:5000"', rendered)
        self.assertIn('capabilities = ["pull", "resolve"]', rendered)
        self.assertNotIn('"push"', rendered)

    def test_k3s_registries_yaml_plain_http(self):
        rendered = k3s_registries_yaml(
            "192.168.1.221:5000", plain_http=True
        )
        self.assertIn('mirrors:', rendered)
        self.assertIn('"192.168.1.221:5000":', rendered)
        self.assertIn('- "http://192.168.1.221:5000"', rendered)
        self.assertNotIn('https', rendered)

    def test_k3s_registries_yaml_tls(self):
        rendered = k3s_registries_yaml(
            "192.168.1.221:5000", plain_http=False
        )
        self.assertIn('- "https://192.168.1.221:5000"', rendered)

    def test_parses_top_level_containerd_config_version(self):
        self.assertEqual(
            containerd_config_version(
                'version = 3\nimports = ["/etc/containerd/conf.d/*.toml"]\n'
            ),
            3,
        )

    def test_missing_containerd_config_version_is_reported(self):
        self.assertIsNone(
            containerd_config_version(
                'imports = ["/etc/containerd/conf.d/*.toml"]\n'
            )
        )

    def test_invalid_containerd_config_version_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "top-level version"):
            containerd_config_version('version = "3"\n')


if __name__ == "__main__":
    unittest.main()
