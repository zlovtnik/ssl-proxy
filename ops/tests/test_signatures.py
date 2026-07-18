import unittest

from sslproxy_ops.health.signatures import classify_text, load_signatures


class SignaturesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signatures = load_signatures()

    def test_loads_twenty_four_signatures(self):
        self.assertEqual(len(self.signatures), 24)

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

    def test_classifies_pending_helm_operation(self):
        result = classify_text(
            "Helm release 'ssl-proxy' remains pending-rollback",
            signatures=self.signatures,
        )

        self.assertEqual(result.name, "helm_pending_operation")
        self.assertEqual(result.retry, "manual")

    def test_classifies_flannel_before_downstream_dns_errors(self):
        result = classify_text(
            "FailedCreatePodSandBox: flannel failed to load /run/flannel/subnet.env\n"
            "Failed to resolve ssl-proxy-redpanda:9092",
            signatures=self.signatures,
        )

        self.assertEqual(result.name, "kubernetes_cni_unavailable")

    def test_classifies_node_not_ready(self):
        result = classify_text("Node is not ready", signatures=self.signatures)

        self.assertEqual(result.name, "kubernetes_node_not_ready")

    def test_classifies_helm_context_canceled(self):
        result = classify_text(
            'Upgrade "ssl-proxy" failed: context canceled',
            signatures=self.signatures,
        )

        self.assertEqual(result.name, "helm_context_canceled")

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
