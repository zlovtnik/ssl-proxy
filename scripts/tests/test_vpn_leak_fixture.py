"""Exercise fixture recovery without host network changes or Linux privileges."""

import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "vpn_leak_results", Path(__file__).with_name("test-vpn-leak-results.py")
)
VPN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VPN)


class PhysicalRecoveryTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.fixture = VPN.LinuxFixture.__new__(VPN.LinuxFixture)
        self.fixture.temporary = self.fixture.output = Path(directory.name)
        self.fixture.captures = []
        self.fixture.shim = None
        self.addresses = {VPN.CLIENT4 + "/24", VPN.CLIENT6 + "/64"}
        self.routes = {("4", "default"), ("6", "default"),
                       ("4", VPN.RELAY4 + "/32"), ("6", VPN.RELAY6 + "/128")}
        self.expected_addresses = self.addresses.copy()
        self.expected_routes = self.routes.copy()
        self.link_up = True
        self.fail_link_up = False
        self.fixture.ip = self.ip
        self.fixture.run = Mock(return_value=SimpleNamespace(stdout="peer 1"))
        self.fixture.policy = Mock()
        self.fixture.tunnel_routes = Mock()
        self.fixture.capture_start = Mock()
        self.fixture.capture_stop = Mock()
        self.fixture.probes = lambda _nonce: dict.fromkeys(VPN.TRAFFIC, self.ready())

    def ready(self):
        return (self.link_up and self.addresses == self.expected_addresses
                and self.routes == self.expected_routes)

    def ip(self, namespace, *args):
        self.assertEqual(namespace, "client")
        if args[:3] == ("link", "set", "eth0"):
            if args[3] == "down":
                self.link_up = False
                self.addresses.clear()
                self.routes.clear()
            else:
                if self.fail_link_up:
                    self.fail_link_up = False
                    raise ValueError("simulated link-up failure")
                self.link_up = True
        elif "addr" in args and "replace" in args:
            self.addresses.add(args[args.index("replace") + 1])
        elif "route" in args and "replace" in args:
            destination = args[args.index("replace") + 1]
            self.routes.add(("6" if "-6" in args else "4", destination))
        return SimpleNamespace(stdout=json.dumps([{"dev": "eth0"}]))

    def row(self, scenario):
        # Packet parsing has its own pcap-based self-tests. Here only network
        # state and row lifecycle run for real; no subprocess can touch the host.
        with patch.object(VPN, "packets", return_value=[]), \
                patch.object(VPN, "counts", return_value=(0, 0, 1, 1)), \
                patch.object(VPN.time, "sleep"):
            return self.fixture.row("direct-wg", scenario)

    def test_network_change_recovers_traffic_and_later_row(self):
        result = self.row("network-change")
        self.assertEqual(result["status"], "pass", result.get("reason"))
        self.assertEqual(result["failure_window_expected"], dict.fromkeys(VPN.TRAFFIC, True))
        self.assertEqual(result["failure_window_success"], result["failure_window_expected"])
        self.assertTrue(self.ready())
        self.assertEqual(self.row("steady-state")["status"], "pass")

    def test_failed_link_up_still_restores_state_for_later_row(self):
        self.fail_link_up = True
        result = self.row("network-change")
        self.assertEqual(result["status"], "fail")
        self.assertIn("simulated link-up failure", result["reason"])
        self.assertTrue(self.ready())
        self.assertEqual(self.row("steady-state")["status"], "pass")

    def test_restore_is_idempotent(self):
        self.ip("client", "link", "set", "eth0", "down")
        self.fixture.restore_physical()
        self.fixture.restore_physical()
        self.assertTrue(self.ready())


if __name__ == "__main__":
    unittest.main()
