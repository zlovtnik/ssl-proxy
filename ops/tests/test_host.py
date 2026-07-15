import unittest

from sslproxy_ops.commands.host import (
    containerd_registry_hosts_toml,
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

    def test_plain_http_hosts_toml_is_pull_only(self):
        rendered = containerd_registry_hosts_toml(
            "192.168.1.221:5000", plain_http=True
        )

        self.assertIn('server = "http://192.168.1.221:5000"', rendered)
        self.assertIn('capabilities = ["pull", "resolve"]', rendered)
        self.assertNotIn('"push"', rendered)


if __name__ == "__main__":
    unittest.main()
