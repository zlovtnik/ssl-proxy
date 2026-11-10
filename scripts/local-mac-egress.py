#!/usr/bin/env python3
"""Keep local Docker VPN egress on a physical macOS interface.

Run on the Mac, not in a container. Only TCP is forwarded; the DNS listener
carries CoreDNS's end-to-end DNS-over-TLS connection without terminating TLS.
"""

import argparse
import ipaddress
import os
from pathlib import Path
import selectors
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace


IP_BOUND_IF = getattr(socket, "IP_BOUND_IF", 25)  # Darwin netinet/in.h
HEADER_LIMIT = 8192
CONNECT_TIMEOUT = 10
DNS_UPSTREAM = ("1.1.1.1", 853)


def connect_bound(address, interface_index):
    """Connect through the selected physical interface, without a fallback."""
    if sys.platform != "darwin":
        raise OSError("physical-interface egress requires macOS")
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, interface_index)
        connection.settimeout(CONNECT_TIMEOUT)
        connection.connect(address)
        return connection
    except BaseException:
        connection.close()
        raise


def receive_exact(connection, length):
    result = bytearray()
    while len(result) < length:
        data = connection.recv(length - len(result))
        if not data:
            raise OSError("unexpected end of upstream response")
        result.extend(data)
    return bytes(result)


def dns_query(hostname, query_id):
    labels = hostname.rstrip(".").encode("idna").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid DNS hostname")
    name = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    if len(name) > 255:
        raise ValueError("DNS hostname is too long")
    return struct.pack("!6H", query_id, 0x0100, 1, 0, 0, 0) + name + b"\0\1\0\1"


def dns_addresses(response, query_id):
    """Read bounded A records, skipping compressed owner names and CNAMEs."""
    if len(response) < 12:
        raise OSError("short DNS response")
    actual_id, flags, questions, answers, _, _ = struct.unpack("!6H", response[:12])
    if actual_id != query_id or not flags & 0x8000 or flags & 0x020F or questions != 1:
        raise OSError("invalid DNS response")

    def skip_name(offset):
        while offset < len(response):
            size = response[offset]
            offset += 1
            if size & 0xC0 == 0xC0:
                if offset >= len(response):
                    break
                pointer = ((size & 0x3F) << 8) | response[offset]
                if pointer >= len(response):
                    break
                return offset + 1
            if size & 0xC0 or offset + size > len(response):
                break
            if size == 0:
                return offset
            offset += size
        raise OSError("invalid DNS name")

    offset = skip_name(12) + 4
    addresses = []
    for _ in range(answers):
        offset = skip_name(offset)
        if offset + 10 > len(response):
            raise OSError("short DNS answer")
        record_type, record_class, _, size = struct.unpack("!HHIH", response[offset:offset + 10])
        offset += 10
        if offset + size > len(response):
            raise OSError("short DNS record")
        if record_type == 1 and record_class == 1 and size == 4:
            addresses.append(socket.inet_ntoa(response[offset:offset + size]))
        offset += size
    if not addresses:
        raise OSError("DNS returned no IPv4 addresses")
    return addresses


def resolve_ipv4(hostname, interface_index):
    try:
        return [str(ipaddress.IPv4Address(hostname))]
    except ipaddress.AddressValueError:
        pass
    query_id = int.from_bytes(os.urandom(2), "big")
    query = dns_query(hostname, query_id)
    # Python.org macOS builds do not necessarily load Apple's system CA bundle.
    context = ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    with connect_bound(DNS_UPSTREAM, interface_index) as raw:
        with context.wrap_socket(raw, server_hostname="cloudflare-dns.com") as secured:
            secured.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", receive_exact(secured, 2))[0]
            return dns_addresses(receive_exact(secured, length), query_id)


def connect_target(target, interface_index):
    hostname, port = target
    last_error = OSError("no upstream address")
    for address in resolve_ipv4(hostname, interface_index):
        try:
            return connect_bound((address, port), interface_index)
        except OSError as error:
            last_error = error
    raise last_error


def read_connect(connection):
    # Read exactly the HTTP header, preserving any tunneled bytes in the socket.
    header = bytearray()
    while len(header) < HEADER_LIMIT:
        data = connection.recv(1)
        if not data:
            raise ValueError("incomplete proxy request")
        header.extend(data)
        if header.endswith(b"\r\n\r\n"):
            break
    else:
        raise ValueError("proxy request is too large")
    lines = header.decode("ascii").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
        raise ValueError("only HTTP CONNECT is supported")
    if any(":" not in line for line in lines[1:-2]):
        raise ValueError("invalid proxy header")
    authority = parts[1]
    if authority.count(":") != 1:
        raise ValueError("an IPv4 address or hostname and port are required")
    hostname, port = authority.split(":")
    if not hostname or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for char in hostname):
        raise ValueError("invalid proxy hostname")
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise ValueError("invalid proxy port")
    return hostname, int(port)


def relay(left, right, idle_timeout=300):
    """Preserve TCP half-close so a peer can finish responding after request EOF."""
    peers = {left: right, right: left}
    buffers = {left: bytearray(), right: bytearray()}
    reading = {left: True, right: True}
    for connection in peers:
        connection.setblocking(False)
    with selectors.DefaultSelector() as pending:
        while True:
            for connection, peer in peers.items():
                events = (selectors.EVENT_READ if reading[connection] and len(buffers[peer]) < 65536 else 0)
                if buffers[connection]:
                    events |= selectors.EVENT_WRITE
                try:
                    pending.get_key(connection)
                except KeyError:
                    if events:
                        pending.register(connection, events)
                else:
                    if events:
                        pending.modify(connection, events)
                    else:
                        pending.unregister(connection)
            if not pending.get_map():
                return
            ready = pending.select(idle_timeout)
            if not ready:
                return
            for entry, events in ready:
                connection = entry.fileobj
                peer = peers[connection]
                if events & selectors.EVENT_WRITE:
                    sent = connection.send(buffers[connection])
                    del buffers[connection][:sent]
                    if not buffers[connection] and not reading[peer]:
                        connection.shutdown(socket.SHUT_WR)
                if events & selectors.EVENT_READ:
                    data = connection.recv(65536 - len(buffers[peer]))
                    if data:
                        buffers[peer].extend(data)
                    else:
                        reading[connection] = False
                        if not buffers[peer]:
                            peer.shutdown(socket.SHUT_WR)


class EgressServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, interface_index, dns=False):
        self.interface_index = interface_index
        self.dns = dns
        super().__init__(address, EgressHandler)

    def verify_request(self, request, client_address):
        # Docker Desktop originates connections on the Mac. When listening on
        # its physical address, do not offer a proxy to other hotspot clients.
        peer = ipaddress.IPv4Address(client_address[0])
        return peer.is_loopback or str(peer) == self.server_address[0]


class EgressHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(CONNECT_TIMEOUT)
        established = False
        try:
            if self.server.dns:
                upstream = connect_bound(DNS_UPSTREAM, self.server.interface_index)
            else:
                target = read_connect(self.request)
                upstream = connect_target(target, self.server.interface_index)
            with upstream:
                if not self.server.dns:
                    self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                established = True
                relay(self.request, upstream)
        except ssl.SSLCertVerificationError:
            if not established and not self.server.dns:
                self.respond(502)
        except (ValueError, UnicodeError):
            self.respond(400)
        except OSError:
            if not established and not self.server.dns:
                self.respond(502)

    def respond(self, status):
        try:
            self.request.sendall(f"HTTP/1.1 {status} Egress Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii"))
        except OSError:
            pass


def read_reverse_token(path):
    token = Path(path).read_bytes().strip()
    if len(token) != 64 or any(byte not in b"0123456789abcdefABCDEF" for byte in token):
        raise ValueError("reverse token file must contain a 64-character hexadecimal key")
    return token


class ReverseWorkers:
    """Carry Docker requests over authenticated, Mac-initiated connections."""

    def __init__(self, port, token, interface_index, stopped, workers):
        self.address = ("127.0.0.1", port)
        self.token = token
        self.interface_index = interface_index
        self.stopped = stopped
        self.connections = set()
        self.lock = threading.Lock()
        self.threads = [threading.Thread(target=self.run, daemon=True) for _ in range(workers)]

    def start(self):
        for thread in self.threads:
            thread.start()

    def run(self):
        while not self.stopped.is_set():
            retry = False
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                with self.lock:
                    if self.stopped.is_set():
                        return
                    self.connections.add(connection)
                try:
                    connection.settimeout(CONNECT_TIMEOUT)
                    connection.connect(self.address)
                    connection.sendall(self.token + b"\n")
                    # Keep unused workers parked instead of filling the
                    # bridge queue with expired connections. EOF or stop()
                    # wakes this read when the bridge exits or we shut down.
                    connection.settimeout(None)
                    mode = receive_exact(connection, 1)
                    if mode not in (b"P", b"D"):
                        raise ValueError("invalid reverse relay assignment")
                    # ACK only the assignment byte. The existing handler reads
                    # the original CONNECT header or raw DNS TLS stream next.
                    connection.sendall(b"A")
                    EgressHandler(connection, self.address, SimpleNamespace(
                        interface_index=self.interface_index, dns=mode == b"D"))
                except (OSError, ValueError):
                    retry = True
                finally:
                    with self.lock:
                        self.connections.discard(connection)
            if retry:
                self.stopped.wait(1)

    def stop(self):
        self.stopped.set()
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        deadline = time.monotonic() + CONNECT_TIMEOUT + 1
        for thread in self.threads:
            # An outbound connect may still be observing its ten-second
            # timeout. Daemon workers must not hold process shutdown forever.
            thread.join(max(0, deadline - time.monotonic()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", default="en0", help="physical hotspot/Wi-Fi interface (default: en0)")
    parser.add_argument("--bind", default="127.0.0.1", help="IPv4 loopback or the selected interface's IPv4 address")
    parser.add_argument("--proxy-port", type=int, default=18080, help="HTTP CONNECT listener port (default: 18080)")
    parser.add_argument("--dns-port", type=int, default=1853, help="raw DNS-over-TLS relay port (default: 1853)")
    parser.add_argument("--reverse-port", type=int, help="connect workers to Docker's published loopback bridge port (usually 18081)")
    parser.add_argument("--token-file", type=Path, help="local admin_api_key export for reverse bridge authentication")
    parser.add_argument("--workers", type=int, default=32, help="reverse worker count, 1-128 (default: 32)")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("run this helper on the macOS Docker host")
    try:
        if not 1 <= args.workers <= 128:
            raise ValueError("workers must be between 1 and 128")
        if args.reverse_port is not None and not 1 <= args.reverse_port <= 65535:
            raise ValueError("reverse port must be between 1 and 65535")
        if args.reverse_port is not None and args.token_file is None:
            raise ValueError("--token-file is required with --reverse-port")
        interface_index = socket.if_nametoindex(args.interface)
        stopped = threading.Event()
        for event in (signal.SIGINT, signal.SIGTERM):
            signal.signal(event, lambda *_: stopped.set())
        if args.reverse_port is not None:
            workers = ReverseWorkers(args.reverse_port, read_reverse_token(args.token_file),
                                     interface_index, stopped, args.workers)
            workers.start()
            print(f"macOS reverse egress: {args.workers} workers connecting to 127.0.0.1:{args.reverse_port}, interface {args.interface}", flush=True)
            try:
                stopped.wait()
            finally:
                workers.stop()
            return
        bind_ip = ipaddress.IPv4Address(args.bind)
        if not bind_ip.is_loopback:
            interface_ip = subprocess.check_output(
                ["/usr/sbin/ipconfig", "getifaddr", args.interface], text=True
            ).strip()
            if str(bind_ip) != interface_ip:
                raise ValueError("listener address must belong to the selected physical interface")
        if any(not 1 <= port <= 65535 for port in (args.proxy_port, args.dns_port)):
            raise ValueError("listener ports must be between 1 and 65535")
        with EgressServer((args.bind, args.proxy_port), interface_index) as proxy:
            with EgressServer((args.bind, args.dns_port), interface_index, dns=True) as dns:
                threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (proxy, dns)]
                for thread in threads:
                    thread.start()
                print(f"macOS egress ready on {args.bind}:{args.proxy_port}, DNS TLS relay :{args.dns_port}, interface {args.interface}", flush=True)
                stopped.wait()
                proxy.shutdown()
                dns.shutdown()
                for thread in threads:
                    thread.join()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"local-mac-egress: {error}\n")


if __name__ == "__main__":
    main()
