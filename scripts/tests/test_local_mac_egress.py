"""Verify local macOS egress routing and proxy stream boundaries."""

import importlib.util
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("local_mac_egress", ROOT / "scripts/local-mac-egress.py")
egress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(egress)


class LocalMacEgressTests(unittest.TestCase):
    def test_reverse_workers_reconnect_without_backoff_after_serving(self):
        stopped = Mock()
        stopped.is_set.side_effect = [False, False, False, False, True]
        connection = MagicMock()
        connection.__enter__.return_value = connection
        workers = egress.ReverseWorkers(18081, b"a" * 64, 15, stopped, 0)
        with patch.object(egress.socket, "socket", return_value=connection), \
                patch.object(egress, "receive_exact", return_value=b"P"), \
                patch.object(egress, "EgressHandler") as handle:
            workers.run()
        self.assertEqual(handle.call_count, 2)
        self.assertEqual(connection.connect.call_count, 2)
        stopped.wait.assert_not_called()
        self.assertFalse(workers.connections)

    def test_reverse_workers_back_off_after_failed_connection_or_assignment(self):
        for failure in ("connect", "assignment"):
            with self.subTest(failure=failure):
                stopped = Mock()
                stopped.is_set.side_effect = [False, False, True]
                connection = MagicMock()
                connection.__enter__.return_value = connection
                if failure == "connect":
                    connection.connect.side_effect = OSError("unavailable")
                workers = egress.ReverseWorkers(18081, b"a" * 64, 15, stopped, 0)

                def wait_after_cleanup(seconds):
                    self.assertFalse(workers.connections)
                    connection.__exit__.assert_called_once()

                stopped.wait.side_effect = wait_after_cleanup
                with patch.object(egress.socket, "socket", return_value=connection), \
                        patch.object(egress, "receive_exact", return_value=b"X"), \
                        patch.object(egress, "EgressHandler") as handle:
                    workers.run()
                stopped.wait.assert_called_once_with(1)
                handle.assert_not_called()

    def test_reverse_token_requires_complete_hex_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_bytes(b"a1" * 32 + b"\n")
            self.assertEqual(egress.read_reverse_token(path), b"a1" * 32)
            for value in (b"", b"partial", b"g" * 64, b"a" * 65):
                path.write_bytes(value)
                with self.assertRaises(ValueError):
                    egress.read_reverse_token(path)

    def test_reverse_workers_authenticate_ack_and_dispatch_both_protocols(self):
        for mode in (b"P", b"D"):
            with self.subTest(mode=mode), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(3)
                stopped = threading.Event()
                workers = egress.ReverseWorkers(listener.getsockname()[1], b"a" * 64, 15, stopped, 1)
                calls = []

                def handle(connection, address, server):
                    calls.append((server.interface_index, server.dns,
                                  egress.receive_exact(connection, 7)))
                    stopped.set()

                with patch.object(egress, "EgressHandler", side_effect=handle):
                    workers.start()
                    try:
                        with listener.accept()[0] as bridge:
                            bridge.settimeout(3)
                            self.assertEqual(egress.receive_exact(bridge, 65), b"a" * 64 + b"\n")
                            # Assignment and tunnel bytes may arrive together;
                            # reading the assignment must not consume the payload.
                            bridge.sendall(mode + b"payload")
                            self.assertEqual(egress.receive_exact(bridge, 1), b"A")
                            self.assertTrue(stopped.wait(3))
                    finally:
                        workers.stop()
                self.assertEqual(calls, [(15, mode == b"D", b"payload")])
                self.assertFalse(any(thread.is_alive() for thread in workers.threads))

    def test_reverse_worker_reconnects_after_disconnect_and_stops_while_idle(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(3)
            stopped = threading.Event()
            workers = egress.ReverseWorkers(listener.getsockname()[1], b"b" * 64, 15, stopped, 1)
            with patch.object(egress, "EgressHandler") as handle:
                workers.start()
                try:
                    with listener.accept()[0] as bridge:
                        bridge.settimeout(3)
                        self.assertEqual(egress.receive_exact(bridge, 65), b"b" * 64 + b"\n")
                        bridge.sendall(b"X")
                        self.assertEqual(bridge.recv(1), b"")
                    with listener.accept()[0] as bridge:
                        bridge.settimeout(3)
                        self.assertEqual(egress.receive_exact(bridge, 65), b"b" * 64 + b"\n")
                        workers.stop()
                        self.assertEqual(bridge.recv(1), b"")
                finally:
                    workers.stop()
                handle.assert_not_called()
            self.assertFalse(any(thread.is_alive() for thread in workers.threads))

    def test_physical_listener_rejects_other_hotspot_clients(self):
        server = Mock(server_address=("172.20.10.2", 18080))
        for address in ("127.0.0.1", "172.20.10.2"):
            self.assertTrue(egress.EgressServer.verify_request(server, None, (address, 12345)))
        for address in ("172.20.10.1", "172.20.10.3", "192.168.65.3"):
            self.assertFalse(egress.EgressServer.verify_request(server, None, (address, 12345)))

    def read_request(self, request):
        sender, receiver = socket.socketpair()
        receiver.settimeout(2)

        def write():
            try:
                sender.sendall(request)
                sender.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            finally:
                sender.close()

        writer = threading.Thread(target=write)
        writer.start()
        try:
            return egress.read_connect(receiver)
        finally:
            receiver.close()
            writer.join(2)

    def test_connect_binds_interface_before_dialing(self):
        connection = Mock()
        with patch.object(egress.sys, "platform", "darwin"), patch.object(egress.socket, "socket", return_value=connection):
            self.assertIs(egress.connect_bound(("1.1.1.1", 853), 15), connection)
        self.assertEqual(connection.method_calls, [
            unittest.mock.call.setsockopt(socket.IPPROTO_IP, egress.IP_BOUND_IF, 15),
            unittest.mock.call.settimeout(10),
            unittest.mock.call.connect(("1.1.1.1", 853)),
        ])

    def test_bind_failure_closes_socket_and_does_not_connect(self):
        connection = Mock()
        connection.setsockopt.side_effect = OSError("interface unavailable")
        with patch.object(egress.sys, "platform", "darwin"), patch.object(egress.socket, "socket", return_value=connection):
            with self.assertRaisesRegex(OSError, "interface unavailable"):
                egress.connect_bound(("1.1.1.1", 853), 15)
        connection.connect.assert_not_called()
        connection.close.assert_called_once()

    def test_non_mac_cannot_fall_back_to_unbound_connection(self):
        with patch.object(egress.sys, "platform", "linux"), patch.object(egress.socket, "socket") as create:
            with self.assertRaisesRegex(OSError, "requires macOS"):
                egress.connect_bound(("1.1.1.1", 853), 15)
        create.assert_not_called()

    def test_connect_request_accepts_numeric_and_hostname_targets(self):
        for hostname in ("1.1.1.1", "example.com"):
            with self.subTest(hostname=hostname):
                self.assertEqual(self.read_request(f"CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}:443\r\n\r\n".encode()), (hostname, 443))

    def test_request_reader_preserves_first_tunneled_bytes(self):
        sender, receiver = socket.socketpair()
        try:
            sender.sendall(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\npayload")
            self.assertEqual(egress.read_connect(receiver), ("1.1.1.1", 443))
            self.assertEqual(receiver.recv(7), b"payload")
        finally:
            sender.close()
            receiver.close()

    def test_malformed_or_oversized_requests_are_rejected(self):
        for request in (
            b"GET / HTTP/1.1\r\n\r\n",
            b"CONNECT example.com HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:0 HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:65536 HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:443 HTTP/2\r\n\r\n",
            b"CONNECT user@example.com:443 HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\ninvalid\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\n",
            b"X" * (egress.HEADER_LIMIT + 1),
        ):
            with self.subTest(request=request[:60]):
                with self.assertRaises(ValueError):
                    self.read_request(request)

    def test_numeric_target_does_not_use_dns(self):
        with patch.object(egress, "connect_bound") as connect:
            self.assertEqual(egress.resolve_ipv4("1.1.1.1", 15), ["1.1.1.1"])
        connect.assert_not_called()

    def test_hostname_resolution_verifies_tls_with_macos_system_ca(self):
        context = MagicMock()
        raw = MagicMock()
        with patch.object(egress.ssl, "create_default_context", return_value=context) as create_context, \
                patch.object(egress, "connect_bound", return_value=raw) as connect, \
                patch.object(egress, "receive_exact", side_effect=[b"\0\x0c", b"response"]), \
                patch.object(egress, "dns_addresses", return_value=["1.2.3.4"]):
            self.assertEqual(egress.resolve_ipv4("example.com", 15), ["1.2.3.4"])
        create_context.assert_called_once_with(cafile="/etc/ssl/cert.pem")
        connect.assert_called_once_with(("1.1.1.1", 853), 15)
        context.wrap_socket.assert_called_once_with(raw.__enter__.return_value, server_hostname="cloudflare-dns.com")

    def test_dns_response_parses_compressed_a_answer_and_checks_bounds(self):
        query = egress.dns_query("example.com", 123)
        response = struct.pack("!6H", 123, 0x8180, 1, 1, 0, 0) + query[12:]
        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.215.14")
        self.assertEqual(egress.dns_addresses(response, 123), ["93.184.215.14"])
        with self.assertRaises(OSError):
            egress.dns_addresses(response, 124)
        with self.assertRaises(OSError):
            egress.dns_addresses(response[:-1], 123)
        with self.assertRaises(ValueError):
            egress.dns_query("a" * 64 + ".com", 123)

    def test_relay_preserves_half_close_and_response(self):
        client, left = socket.socketpair()
        right, server = socket.socketpair()
        sockets = (client, left, right, server)
        for connection in sockets:
            connection.settimeout(2)
        errors = []

        def run():
            try:
                egress.relay(left, right, idle_timeout=1)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=run)
        thread.start()
        try:
            client.sendall(b"request")
            client.shutdown(socket.SHUT_WR)
            self.assertEqual(server.recv(7), b"request")
            self.assertEqual(server.recv(1), b"")
            server.sendall(b"response after request EOF")
            server.shutdown(socket.SHUT_WR)
            response = bytearray()
            while data := client.recv(1024):
                response.extend(data)
            self.assertEqual(response, b"response after request EOF")
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
        finally:
            for connection in sockets:
                connection.close()
            thread.join(2)

    def test_relay_delivers_response_while_upload_is_blocked(self):
        client, left = socket.socketpair()
        right, server = socket.socketpair()
        right.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        client.setblocking(False)
        server.settimeout(2)
        thread = threading.Thread(target=egress.relay, args=(left, right, 1))
        thread.start()
        try:
            while True:
                try:
                    client.send(b'x' * 65536)
                except BlockingIOError:
                    break
            server.sendall(b'early response')
            client.settimeout(2)
            self.assertEqual(client.recv(1024), b'early response')
        finally:
            for connection in (client, left, right, server):
                connection.close()
            thread.join(2)

    def test_proxy_returns_502_without_direct_fallback(self):
        with egress.EgressServer(("127.0.0.1", 0), 15) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with patch.object(egress, "connect_target", side_effect=OSError("dial failed")) as connect:
                    with socket.create_connection(server.server_address, timeout=2) as client:
                        client.sendall(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\n\r\n")
                        self.assertTrue(client.recv(1024).startswith(b"HTTP/1.1 502 "))
                    connect.assert_called_once_with(("1.1.1.1", 443), 15)
            finally:
                server.shutdown()
                thread.join(2)


if __name__ == "__main__":
    unittest.main()
