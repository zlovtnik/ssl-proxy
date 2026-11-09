"""Exercise the reverse bridge with isolated loopback peers, without a VPN."""

import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOKEN = b"a" * 64


@unittest.skipUnless(shutil.which("rustc"), "rustc is needed to compile the standalone bridge")
class LocalReverseBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="reverse-bridge-", dir="/private/tmp" if Path("/private/tmp").is_dir() else None)
        cls.binary = str(Path(cls.directory.name) / "bridge")
        subprocess.run(["rustc", "--edition=2021", "-D", "warnings",
                        str(ROOT / "docker/local/mac-egress-bridge.rs"), "-o", cls.binary], check=True)
        cls.token_path = Path(cls.directory.name) / "token"
        cls.token_path.write_bytes(TOKEN + b"\n")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        environment = dict(os.environ, MAC_BRIDGE_TOKEN_FILE=str(self.token_path))
        for service in ("PROXY", "DNS", "WORKER"):
            environment[f"MAC_BRIDGE_{service}_ADDR"] = "127.0.0.1:0"
        self.process = subprocess.Popen([self.binary], env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_bridge)
        self.assertTrue(select.select([self.process.stdout], [], [], 5)[0], "bridge failed to start")
        ready = self.process.stdout.readline()
        self.assertIn("ready", ready)
        self.addresses = {}
        for setting in ready.split()[2:]:
            service, address = setting.split("=")
            host, port = address.split(":")
            self.addresses[service] = (host, int(port))

    def stop_bridge(self):
        self.process.terminate()
        self.process.communicate(timeout=3)

    def connect(self, service):
        connection = socket.create_connection(self.addresses[service], timeout=8)
        self.addCleanup(connection.close)
        return connection

    def worker(self):
        worker = self.connect("worker")
        worker.sendall(TOKEN + b"\n")
        return worker

    def test_wrong_and_unbounded_authentication_is_rejected(self):
        for token in (b"b" * 64 + b"\n", TOKEN + b"extra\n", b"a" * 128):
            worker = self.connect("worker")
            worker.sendall(token)
            self.assertEqual(worker.recv(1), b"")

    def test_both_listener_types_preserve_bytes_and_half_close(self):
        for service, expected in (("proxy", b"P"), ("dns", b"D")):
            with self.subTest(service=service):
                worker = self.worker()
                client = self.connect(service)
                client.sendall(b"request\0payload")
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(worker.recv(1), expected)
                worker.sendall(b"A")
                received = bytearray()
                while data := worker.recv(4096):
                    received.extend(data)
                self.assertEqual(received, b"request\0payload")
                worker.sendall(b"response after EOF")
                worker.shutdown(socket.SHUT_WR)
                response = bytearray()
                while data := client.recv(4096):
                    response.extend(data)
                self.assertEqual(response, b"response after EOF")

    def test_bad_ack_worker_retried_without_consuming_client_bytes(self):
        stale = self.worker()
        client = self.connect("proxy")
        client.sendall(b"preserve me")
        self.assertEqual(stale.recv(1), b"P")
        stale.sendall(b"X")
        healthy = self.worker()
        self.assertEqual(healthy.recv(1), b"P")
        healthy.sendall(b"A")
        self.assertEqual(healthy.recv(11), b"preserve me")
        healthy.sendall(b"reply")
        self.assertEqual(client.recv(5), b"reply")

    def test_silent_worker_retried_after_ack_deadline(self):
        stale = self.worker()
        client = self.connect("dns")
        self.assertEqual(stale.recv(1), b"D")
        healthy = self.worker()
        start = time.monotonic()
        self.assertEqual(healthy.recv(1), b"D")
        self.assertLess(time.monotonic() - start, 4)
        healthy.sendall(b"A")
        client.sendall(b"dns")
        self.assertEqual(healthy.recv(3), b"dns")

    def test_absent_worker_closes_client_within_bounded_wait(self):
        client = self.connect("proxy")
        start = time.monotonic()
        self.assertEqual(client.recv(1), b"")
        elapsed = time.monotonic() - start
        self.assertGreater(elapsed, 4)
        self.assertLess(elapsed, 7)


if __name__ == "__main__":
    unittest.main()
