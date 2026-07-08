import unittest

from sslproxy_ops.health.signatures import classify_text, load_signatures


class SignaturesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signatures = load_signatures()

    def test_loads_twenty_signatures(self):
        self.assertEqual(len(self.signatures), 20)

    def test_classifies_up_ready_only_peer_permission_signature(self):
        result = classify_text(
            "awk: cannot open /config/peer1.conf (Permission denied)",
            signatures=self.signatures,
        )

        self.assertTrue(result.matched)
        self.assertEqual(result.name, "peer_config_permission_denied")

    def test_classifies_registry_timeout(self):
        result = classify_text(
            "lookup registry-1.docker.io on 1.1.1.1:53: i/o timeout",
            signatures=self.signatures,
        )

        self.assertEqual(result.name, "docker_registry_dns_timeout")
        self.assertEqual(result.retry, "auto")

    def test_unknown_default(self):
        result = classify_text("nothing interesting", signatures=self.signatures)

        self.assertFalse(result.matched)
        self.assertEqual(result.name, "unknown")

    def test_empty_signatures_does_not_load_defaults(self):
        result = classify_text(
            "lookup registry-1.docker.io on 1.1.1.1:53: i/o timeout",
            signatures=[],
        )

        self.assertFalse(result.matched)
        self.assertEqual(result.name, "unknown")


if __name__ == "__main__":
    unittest.main()
