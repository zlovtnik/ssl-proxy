#!/usr/bin/env python3
"""Plan 005 result contract, negative tests and isolated Linux fixture.

Only synthetic test traffic is captured. A validator pass is deliberately stricter
than successful fixture setup: missing OS/endpoint scenarios remain BLOCKED.
"""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time


PROFILES = ("direct-wg", "shim-aead")
SCENARIOS = (
    "startup-before-wg", "steady-state", "reconnect", "shim-crash",
    "shim-restart", "wg-interface-removal", "dns-dot-outage",
    "certificate-failure", "dns-timeout", "sleep-resume", "network-change",
    "ipv4-only", "ipv6-only", "dual-stack", "outer-udp-blocked", "lan-denied",
)
TRAFFIC = ("tcp4", "udp4", "dns4", "tcp6", "udp6", "dns6")
CLIENT4, CLIENT6 = "192.0.2.2", "fd00:5::2"
RELAY4, RELAY6 = "198.51.100.2", "fd00:6::2"
APP4, APP6 = "203.0.113.80", "fd00:113::80"
DNS4 = "203.0.113.53"
INNER4, INNER6 = "10.13.13.1", "fd13:13::1"
TOKEN = b"vpn005-"


def require(value, message):
    if not value:
        raise ValueError(message)


def integer(value):
    return type(value) is int and value >= 0


def artifact(directory, name):
    require(isinstance(name, str) and name, "missing artifact path")
    path = (directory / name).resolve()
    require(path.is_relative_to(directory.resolve()), "artifact escapes results directory")
    require(path.is_file(), f"missing artifact: {name}")
    return path


def packets(path):
    """Read complete classic pcaps emitted by tcpdump, including raw WG links."""
    raw = path.read_bytes()
    require(len(raw) >= 24, f"empty/truncated pcap: {path.name}")
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(raw[:4])
    require(endian is not None, "unsupported pcap magic")
    link = struct.unpack_from(endian + "I", raw, 20)[0]
    require(link in (1, 12, 101, 113, 276), f"unsupported capture link type {link}")
    result, offset = [], 24
    while offset < len(raw):
        require(offset + 16 <= len(raw), "truncated pcap record")
        _, _, size, original = struct.unpack_from(endian + "IIII", raw, offset)
        offset += 16
        require(size == original and offset + size <= len(raw), "truncated packet capture")
        packet = raw[offset:offset + size]
        offset += size
        skip = {1: 14, 12: 0, 101: 0, 113: 16, 276: 20}[link]
        require(len(packet) >= skip, "short link header")
        if link == 1 and packet[12:14] == b"\x81\x00":
            skip += 4
        packet = packet[skip:]
        if not packet or packet[0] >> 4 not in (4, 6):
            # ARP is link control, never application/DNS traffic.
            continue
        version = packet[0] >> 4
        if version == 4:
            require(len(packet) >= 20, "short IPv4 header")
            length = (packet[0] & 15) * 4
            require(length >= 20 and len(packet) >= length, "invalid IPv4 header")
            require(not struct.unpack_from("!H", packet, 6)[0] & 0x3FFF,
                    "fragmented test traffic cannot be classified safely")
            protocol = packet[9]
            source = socket.inet_ntop(socket.AF_INET, packet[12:16])
            destination = socket.inet_ntop(socket.AF_INET, packet[16:20])
        else:
            require(len(packet) >= 40, "short IPv6 header")
            length, protocol = 40, packet[6]
            source = socket.inet_ntop(socket.AF_INET6, packet[8:24])
            destination = socket.inet_ntop(socket.AF_INET6, packet[24:40])
            require(protocol not in (0, 43, 44, 60),
                    "IPv6 extension headers require an explicit detector adapter")
        source_port, port, payload = 0, 0, b""
        if protocol in (6, 17):
            require(len(packet) >= length + 8, "short transport header")
            source_port, port = struct.unpack_from("!HH", packet, length)
            if protocol == 17:
                payload = packet[length + 8:]
            else:
                require(len(packet) >= length + 20, "short TCP header")
                payload = packet[length + ((packet[length + 12] >> 4) * 4):]
        result.append((source, destination, protocol, source_port, port, payload))
    require(result, f"capture contains no IP packets: {path.name}")
    return result


def counts(physical, tunnel, profile):
    app = dns = outer = 0
    for source, destination, protocol, _, port, payload in physical:
        if source not in (CLIENT4, CLIENT6):
            continue
        if protocol == 58:
            continue  # namespace fixture generates only NDP control ICMPv6
        if (protocol == 17 and destination in ((RELAY4,) if profile == "shim-aead" else (RELAY4, RELAY6))
                and port == (443 if profile == "shim-aead" else 51820)
                and not payload.startswith(TOKEN)):
            outer += 1
        elif protocol in (6, 17) and port in (53, 853):
            dns += 1
        else:
            app += 1
    return app, dns, outer, len(tunnel)


def captured_traffic(tunnel, nonce):
    """Require matching request/response payloads, not user-supplied success flags."""
    observed = dict.fromkeys(TRAFFIC, False)
    for version, application, resolver in (("4", APP4, INNER4), ("6", APP6, INNER6)):
        for kind, protocol, destination, port in (("tcp", 6, application, 8080),
                                                   ("udp", 17, application, 40443),
                                                   ("dns", 17, resolver, 53)):
            requests = responses = False
            for source, target, transport, source_port, target_port, payload in tunnel:
                if transport != protocol:
                    continue
                marker = nonce.encode() in payload
                requests |= target == destination and target_port == port and marker
                if kind == "tcp":
                    responses |= source == destination and source_port == port and b"vpn005-ok" in payload
                else:
                    responses |= source == destination and source_port == port and marker
            observed[kind + version] = requests and responses
    return observed


def validate_row(row, directory, control=False):
    require(isinstance(row, dict), "result row must be an object")
    require(row.get("os") == "linux", "unexpected OS in Linux result contract")
    require(row.get("profile") in PROFILES, "unknown transport profile")
    require(isinstance(row.get("nonce"), str) and row["nonce"].startswith("vpn005-"), "missing unique fixture query nonce")
    require(row.get("status") == "pass", f"{row.get('scenario')}: {row.get('status')} {row.get('reason', '')}")
    for field in ("capture_valid", "outer_route_uses_physical_interface", "protected_dns_verified"):
        require(row.get(field) is True, f"{row.get('scenario')}: {field} is not verified")
    require(integer(row.get("handshake_epoch")) and row["handshake_epoch"] > 0,
            "missing actual kernel WireGuard handshake")
    require(all(integer(row.get(field)) for field in
                ("unexpected_application_packets", "unexpected_dns_packets")), "invalid packet count")
    require(isinstance(row.get("traffic"), dict)
            and all(row["traffic"].get(kind) is True for kind in TRAFFIC),
            "missing known application/DNS traffic through selected WG path")
    require(isinstance(row.get("attempts"), dict)
            and all(integer(row["attempts"].get(kind)) and row["attempts"][kind] > 0 for kind in TRAFFIC),
            "missing failure-window traffic generation")
    captures = row.get("captures", {})
    for kind in ("physical", "tunnel", "relay"):
        capture = captures.get(kind)
        require(isinstance(capture, str) and capture.endswith(".pcap"), "missing capture path")
        log = artifact(directory, str(Path(capture).with_suffix(".log"))).read_text()
        dropped = re.findall(r"(?m)^(\d+) packets dropped by kernel$", log)
        require("listening on " in log and dropped == ["0"], "capture missing final statistics or dropped packets")
    physical = packets(artifact(directory, captures.get("physical")))
    tunnel = packets(artifact(directory, captures.get("tunnel")))
    app, dns, outer, _ = counts(physical, tunnel, row["profile"])
    require(outer > 0, "missing expected outer WireGuard/shim packets")
    require(app == row["unexpected_application_packets"] and dns == row["unexpected_dns_packets"],
            "reported leak counts disagree with capture")
    require(app > 0 and dns > 0 if control else app == 0 and dns == 0,
            "positive control did not expose both leaks" if control else f"application/DNS leak detected: {app}/{dns}")
    require(all(captured_traffic(tunnel, row.get("nonce", "!")).values()),
            "known six-way application/DNS request and response traffic absent from WG capture")
    relay = packets(artifact(directory, captures.get("relay")))
    require(any(destination == DNS4 and protocol == 6 and port == 853
                for _, destination, protocol, _, port, _ in relay), "no relay external DoT packets")
    require(not any((source == DNS4 or destination == DNS4) and protocol in (6, 17)
                    and (source_port == 53 or port == 53)
                    for source, destination, protocol, source_port, port, _ in relay),
            "relay external plaintext DNS observed")
    routes = json.loads(artifact(directory, row.get("routes")).read_text())
    require(set(routes) == {"ipv4", "ipv6"}, "missing dual-stack outer route lookups")
    for family in routes.values():
        require(isinstance(family, list) and family and family[0].get("dev") == "eth0",
                "outer route recurses into WG or misses physical interface")
    dns_log = artifact(directory, row.get("dns_evidence")).read_text().splitlines()
    events = [json.loads(line) for line in dns_log]
    require(any(event.get("verified") is True and event.get("hostname") == "dns.vpn005.invalid"
                and event.get("query", "").startswith(row.get("nonce", "!"))
                for event in events), "missing authenticated DoT query evidence")
    if not control:
        expected = dict.fromkeys(TRAFFIC, True)
        scenario = row.get("scenario")
        if scenario in ("startup-before-wg", "reconnect", "wg-interface-removal", "outer-udp-blocked", "lan-denied"):
            expected = dict.fromkeys(TRAFFIC, False)
        elif scenario == "shim-crash" and row["profile"] == "shim-aead":
            expected = dict.fromkeys(TRAFFIC, False)
        elif scenario in ("dns-dot-outage", "certificate-failure", "dns-timeout"):
            expected["dns4"] = expected["dns6"] = False
            require(any(event.get("verified") is False and event.get("query", "").startswith(row["nonce"] + "-failure")
                        for event in events), "missing failed DoT query evidence during upstream failure")
        require(row.get("failure_window_success") == expected and row.get("failure_window_expected") == expected,
                "missing or incorrect scenario-specific failure-window outcomes")


def validate(directory):
    directory = Path(directory)
    data = json.loads(artifact(directory, "results.json").read_text())
    require(isinstance(data, dict) and data.get("schema_version") == 1, "unsupported results schema")
    rows = data.get("results")
    require(isinstance(rows, list), "missing results matrix")
    expected = {(profile, scenario) for profile in PROFILES for scenario in SCENARIOS}
    found = [(row.get("profile"), row.get("scenario")) for row in rows if isinstance(row, dict)]
    require(len(found) == len(rows) and len(found) == len(set(found)) and set(found) == expected,
            "missing, duplicate or unexpected profile/scenario")
    controls = data.get("controls")
    require(isinstance(controls, list) and all(isinstance(row, dict) for row in controls)
            and {row.get("profile") for row in controls} == set(PROFILES)
            and len(controls) == len(PROFILES), "missing deliberately uncontained positive controls")
    errors = []
    for row, control in [(row, True) for row in controls] + [(row, False) for row in rows]:
        try:
            validate_row(row, directory, control)
        except (ValueError, KeyError, TypeError, OSError, struct.error) as error:
            errors.append(f"{row.get('profile')}/{row.get('scenario')}: {error}")
    require(not errors, "\n".join(errors))
    return data


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def self_test():
    """No privileges/binaries needed; test rejection using actual small pcaps."""
    def ip_packet(destination, port, source=CLIENT4, payload=b"test", protocol=17, source_port=40000):
        if protocol == 17:
            transport = struct.pack("!HHHH", source_port, port, 8 + len(payload), 0) + payload
        else:
            transport = struct.pack("!HHIIBBHHH", source_port, port, 0, 0, 0x50, 0x18, 4096, 0, 0) + payload
        if ":" in destination:
            return (struct.pack("!IHBB", 6 << 28, len(transport), protocol, 64)
                    + socket.inet_pton(socket.AF_INET6, source) + socket.inet_pton(socket.AF_INET6, destination) + transport)
        return (b"\x45\x00" + struct.pack("!H", 20 + len(transport)) + b"\x00" * 4
                + bytes([64, protocol, 0, 0]) + socket.inet_aton(source)
                + socket.inet_aton(destination) + transport)

    def pcap(path, items):
        raw = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)
        for packet in items:
            raw += struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet
        path.write_bytes(raw)
        path.with_suffix(".log").write_text("listening on synthetic self-test capture\n0 packets dropped by kernel\n")

    rejected = 0
    with tempfile.TemporaryDirectory(prefix="vpn005-validator-") as temporary:
        directory = Path(temporary)
        write_json(directory / "routes.json", {"ipv4": [{"dev": "eth0"}], "ipv6": [{"dev": "eth0"}]})
        (directory / "dns.jsonl").write_text(json.dumps({"verified": True, "hostname": "dns.vpn005.invalid", "query": "vpn005-self.invalid"}) + "\n")
        traffic = []
        for client, application, resolver in (("10.13.13.2", APP4, INNER4), ("fd13:13::2", APP6, INNER6)):
            for destination, port, protocol in ((application, 8080, 6), (application, 40443, 17), (resolver, 53, 17)):
                traffic.append(ip_packet(destination, port, client, b"vpn005-self", protocol))
                traffic.append(ip_packet(client, 40000, destination,
                                         b"vpn005-ok" if protocol == 6 else b"vpn005-self", protocol, port))
        pcap(directory / "tunnel.pcap", traffic)
        pcap(directory / "relay.pcap", [ip_packet(DNS4, 853, RELAY4, protocol=6)])
        pcap(directory / "clean.pcap", [ip_packet(RELAY4, 443, payload=b"encrypted")])
        pcap(directory / "leak.pcap", [ip_packet(RELAY4, 443, payload=b"encrypted"), ip_packet(APP4, 8080), ip_packet(DNS4, 53)])
        pcap(directory / "empty.pcap", [])
        row = {"os": "linux", "profile": "shim-aead", "scenario": "steady-state", "status": "pass",
               "capture_valid": True, "outer_route_uses_physical_interface": True,
               "protected_dns_verified": True, "handshake_epoch": 1,
               "unexpected_application_packets": 0, "unexpected_dns_packets": 0,
               "traffic": dict.fromkeys(TRAFFIC, True), "attempts": dict.fromkeys(TRAFFIC, 1),
               "captures": {"physical": "clean.pcap", "tunnel": "tunnel.pcap", "relay": "relay.pcap"},
               "routes": "routes.json", "dns_evidence": "dns.jsonl", "nonce": "vpn005-self",
               "failure_window_success": dict.fromkeys(TRAFFIC, True), "failure_window_expected": dict.fromkeys(TRAFFIC, True)}
        validate_row(row, directory)
        control = copy.deepcopy(row)
        control["captures"]["physical"] = "leak.pcap"
        control["unexpected_application_packets"] = control["unexpected_dns_packets"] = 1
        validate_row(control, directory, True)
        variants = []
        for field, value in (("status", "blocked"), ("capture_valid", False),
                             ("handshake_epoch", 0), ("protected_dns_verified", False),
                             ("outer_route_uses_physical_interface", False),
                             ("unexpected_dns_packets", -1), ("unexpected_application_packets", True)):
            bad = copy.deepcopy(row)
            bad[field] = value
            variants.append(bad)
        for physical in ("empty.pcap", "missing.pcap", "../escape.pcap", "leak.pcap"):
            bad = copy.deepcopy(row)
            bad["captures"]["physical"] = physical
            variants.append(bad)
        for kind in ("tunnel", "relay"):
            bad = copy.deepcopy(row)
            bad["captures"][kind] = "clean.pcap"
            variants.append(bad)
        pcap(directory / "plaintext-relay.pcap", [ip_packet(DNS4, 853, RELAY4, protocol=6), ip_packet(DNS4, 53, RELAY4)])
        bad = copy.deepcopy(row)
        bad["captures"]["relay"] = "plaintext-relay.pcap"
        variants.append(bad)
        (directory / "truncated.pcap").write_bytes((directory / "clean.pcap").read_bytes()[:-1])
        bad = copy.deepcopy(row)
        bad["captures"]["physical"] = "truncated.pcap"
        (directory / "truncated.log").write_text("listening on synthetic self-test capture\n0 packets dropped by kernel\n")
        variants.append(bad)
        pcap(directory / "dropped.pcap", [ip_packet(RELAY4, 443)])
        (directory / "dropped.log").write_text("listening on synthetic self-test capture\n1 packets dropped by kernel\n")
        bad = copy.deepcopy(row)
        bad["captures"]["physical"] = "dropped.pcap"
        variants.append(bad)
        for field in ("traffic", "attempts", "dns_evidence", "routes"):
            bad = copy.deepcopy(row)
            del bad[field]
            variants.append(bad)
        variants.append(control)
        bad = copy.deepcopy(row)
        bad["scenario"] = "certificate-failure"
        variants.append(bad)
        bad = copy.deepcopy(row)
        bad["scenario"] = "network-change"
        bad["failure_window_expected"] = bad["failure_window_success"] = dict.fromkeys(TRAFFIC, False)
        variants.append(bad)
        for bad in variants:
            try:
                validate_row(bad, directory)
            except (ValueError, TypeError, OSError):
                rejected += 1
            else:
                raise AssertionError(f"accepted invalid result: {bad}")
        for data in ({}, {"schema_version": 1, "results": [], "controls": []}, []):
            write_json(directory / "results.json", data)
            try:
                validate(directory)
            except (ValueError, TypeError):
                rejected += 1
            else:
                raise AssertionError("accepted missing results matrix")
        (directory / "results.json").write_text("{")
        try:
            validate(directory)
        except ValueError:
            rejected += 1
        else:
            raise AssertionError("accepted malformed JSON")
        # Exercise the complete matrix path as well as individual row checks.
        complete = {"schema_version": 1, "results": [], "controls": []}
        for profile in PROFILES:
            port = 443 if profile == "shim-aead" else 51820
            pcap(directory / (profile + ".pcap"), [ip_packet(RELAY4, port, payload=b"encrypted")])
            pcap(directory / (profile + "-leak.pcap"), [ip_packet(RELAY4, port, payload=b"encrypted"), ip_packet(APP4, 8080), ip_packet(DNS4, 53)])
            for scenario in SCENARIOS:
                item = copy.deepcopy(row)
                item.update(profile=profile, scenario=scenario)
                item["captures"]["physical"] = profile + ".pcap"
                failure = scenario in ("startup-before-wg", "reconnect", "wg-interface-removal", "outer-udp-blocked", "lan-denied") or (scenario == "shim-crash" and profile == "shim-aead")
                expected = dict.fromkeys(TRAFFIC, not failure)
                if scenario in ("dns-dot-outage", "certificate-failure", "dns-timeout"):
                    expected["dns4"] = expected["dns6"] = False
                item.update(failure_window_expected=expected, failure_window_success=expected.copy())
                complete["results"].append(item)
            item = copy.deepcopy(control)
            item.update(profile=profile, scenario="uncontained-control")
            item["captures"]["physical"] = profile + "-leak.pcap"
            complete["controls"].append(item)
        with (directory / "dns.jsonl").open("a") as evidence:
            evidence.write(json.dumps({"verified": False, "query": "vpn005-self-failure.vpn005.invalid"}) + "\n")
        write_json(directory / "results.json", complete)
        validate(directory)
        for edit in ("missing", "duplicate", "extra", "no-control"):
            bad = copy.deepcopy(complete)
            if edit == "missing":
                bad["results"].pop()
            elif edit == "duplicate":
                bad["results"].append(bad["results"][0])
            elif edit == "extra":
                bad["results"][0]["scenario"] = "unknown"
            else:
                bad["controls"].pop()
            write_json(directory / "results.json", bad)
            try:
                validate(directory)
            except ValueError:
                rejected += 1
            else:
                raise AssertionError(f"accepted incomplete matrix: {edit}")
    print(f"PASS: valid header captures accepted; positive controls observed; {rejected} invalid/missing/leaking results rejected")


def dns_response(query):
    require(len(query) >= 12, "short DNS query")
    end = 12
    labels = []
    while end < len(query) and query[end]:
        size = query[end]
        require(size <= 63 and end + size < len(query), "invalid DNS name")
        labels.append(query[end + 1:end + size + 1].decode("ascii"))
        end += size + 1
    require(end + 5 <= len(query), "short DNS question")
    qtype = struct.unpack_from("!H", query, end + 1)[0]
    value = socket.inet_pton(socket.AF_INET6 if qtype == 28 else socket.AF_INET, APP6 if qtype == 28 else APP4)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 0, len(value)) + value
    return (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:end + 5] + answer,
            ".".join(labels))


def receive_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise OSError("short DNS-over-TLS stream")
        data += chunk
    return data


def serve(role, temporary, output):
    """Owned synthetic HTTP/UDP/DNS fixtures, reachable only inside namespaces."""
    temporary, output = Path(temporary), Path(output)

    def listener(address, port, udp=False):
        sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET,
                             socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if ":" in address:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, port))
        if not udp:
            sock.listen(32)
        return sock

    def tls_server():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(temporary / "dns.crt", temporary / "dns.key")
        sock = listener(DNS4, 853)
        while True:
            connection, _ = sock.accept()
            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    tls.settimeout(2)
                    length = struct.unpack("!H", receive_exact(tls, 2))[0]
                    answer, _ = dns_response(receive_exact(tls, length))
                    if (temporary / "dns-mode").read_text().strip() == "timeout":
                        time.sleep(1.5)
                        continue
                    tls.sendall(struct.pack("!H", len(answer)) + answer)
            except (OSError, ValueError):
                connection.close()

    def dns_server(address):
        sock = listener(address, 53, True)
        while True:
            query, peer = sock.recvfrom(2048)
            try:
                _, name = dns_response(query)
                mode = (temporary / "dns-mode").read_text().strip()
                context = ssl.create_default_context(cafile=str(temporary / "dns.crt"))
                hostname = "wrong.vpn005.invalid" if mode == "certificate-failure" else "dns.vpn005.invalid"
                with socket.create_connection((DNS4, 853 if mode != "outage" else 8853), timeout=1) as connection:
                    with context.wrap_socket(connection, server_hostname=hostname) as tls:
                        tls.sendall(struct.pack("!H", len(query)) + query)
                        length = struct.unpack("!H", receive_exact(tls, 2))[0]
                        answer = receive_exact(tls, length)
                        event = {"query": name, "verified": True, "hostname": hostname,
                                 "certificate_sha256": hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()}
                        with (output / "dns.jsonl").open("a") as evidence:
                            evidence.write(json.dumps(event) + "\n")
                        sock.sendto(answer, peer)
            except (OSError, ValueError) as error:
                with (output / "dns.jsonl").open("a") as evidence:
                    evidence.write(json.dumps({"query": locals().get("name", ""), "verified": False,
                                               "failure": type(error).__name__}) + "\n")

    def echo_udp(address):
        sock = listener(address, 40443, True)
        while True:
            data, peer = sock.recvfrom(2048)
            if data.startswith(TOKEN):
                sock.sendto(data, peer)

    def http(address):
        sock = listener(address, 8080)
        while True:
            connection, _ = sock.accept()
            with connection:
                connection.settimeout(1)
                try:
                    data = connection.recv(2048)
                    if TOKEN in data:
                        connection.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nvpn005-ok")
                except OSError:
                    pass

    functions = [(tls_server, ())] if role == "router" else [
        (function, (address,)) for address in (APP4, APP6) for function in (echo_udp, http)
    ] + [(dns_server, (address,)) for address in (INNER4, INNER6)]
    for function, args in functions:
        threading.Thread(target=function, args=args, daemon=True).start()
    (temporary / (role + ".ready")).touch()
    while True:
        time.sleep(1)


def probe(nonce, kinds=None):
    kinds = TRAFFIC if kinds is None else kinds
    results = {}
    for kind in kinds:
        family = socket.AF_INET6 if kind.endswith("6") else socket.AF_INET
        destination = APP6 if family == socket.AF_INET6 else APP4
        port = 8080 if kind.startswith("tcp") else 40443
        if kind.startswith("dns"):
            destination, port = (INNER6 if family == socket.AF_INET6 else INNER4), 53
        sock = socket.socket(family, socket.SOCK_STREAM if kind.startswith("tcp") else socket.SOCK_DGRAM)
        sock.settimeout(0.7)
        try:
            sock.connect((destination, port))
            if kind.startswith("dns"):
                name = nonce + ".vpn005.invalid"
                query = struct.pack("!HHHHHH", 47, 0x100, 1, 0, 0, 0)
                query += b"".join(bytes([len(label)]) + label.encode() for label in name.split("."))
                query += b"\x00" + struct.pack("!HH", 28 if family == socket.AF_INET6 else 1, 1)
                sock.send(query)
                answer = sock.recv(2048)
                results[kind] = len(answer) > len(query) and answer[:2] == query[:2]
            else:
                data = TOKEN + nonce.encode()
                sock.sendall(b"GET /" + data + b" HTTP/1.0\r\n\r\n" if kind.startswith("tcp") else data)
                answer = sock.recv(2048)
                results[kind] = b"vpn005-ok" in answer if kind.startswith("tcp") else answer == data
        except OSError:
            results[kind] = False
        finally:
            sock.close()
    # Same relay tuple from the application UID must not acquire the shim's escape.
    for family, address in ((socket.AF_INET, RELAY4), (socket.AF_INET6, RELAY6)):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(TOKEN + nonce.encode(), (address, 443))
            except OSError:
                pass
    print(json.dumps(results))


class LinuxFixture:
    """All mutations are netns-scoped; no namespace has a link to the host."""

    def __init__(self, output):
        require(sys.platform == "linux" and os.geteuid() == 0, "Linux administrator namespace privileges required")
        self.output = Path(output).absolute()
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root = Path(__file__).resolve().parents[2]
        self.script = Path(__file__).resolve()
        # TMPDIR and the checkout may have parents inaccessible to fixture UIDs.
        staging_parent = Path("/tmp").resolve()
        require(all(path.stat().st_mode & 0o001 for path in (staging_parent, *staging_parent.parents)),
                "fixture staging parents must permit unprivileged traversal")
        self.temporary = Path(tempfile.mkdtemp(prefix="vpn005-private-", dir=staging_parent))
        os.chmod(self.temporary, 0o755)
        self.prefix = "v005-" + secrets.token_hex(4)
        self.namespaces = {}
        self.processes = []
        self.data = {"schema_version": 1, "os_version": self.command("uname", "-srv").stdout.strip(),
                     "wg_version": self.command("wg", "--version").stdout.strip(),
                     "scope": "disposable-network-namespaces; synthetic traffic only",
                     "controls": [], "results": []}
        self.shim = None
        self.captures = []

    @staticmethod
    def command(*args, check=True, **kwargs):
        return subprocess.run(args, text=True, check=check, capture_output=True, **kwargs)

    def run(self, namespace, *args, **kwargs):
        require(namespace in self.namespaces, "refusing unowned namespace mutation")
        return self.command("ip", "netns", "exec", self.namespaces[namespace], *map(str, args), **kwargs)

    def ip(self, namespace, *args):
        return self.run(namespace, "ip", *args)

    def background(self, namespace, args, name, uid=None, env=None):
        require(namespace in self.namespaces, "refusing unowned namespace process")
        command = ["ip", "netns", "exec", self.namespaces[namespace]]
        if uid is not None:
            command += ["setpriv", f"--reuid={uid}", f"--regid={uid}", "--clear-groups",
                        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs"]
        logfile = (self.output / name).open("w")
        process = subprocess.Popen(command + list(map(str, args)), stdout=logfile, stderr=subprocess.STDOUT,
                                   env=env, start_new_session=True)
        logfile.close()
        self.processes.append(process)
        return process

    def link(self, left, right, left_name, right_name, addresses):
        # Both endpoints are created directly INSIDE owned namespaces.
        self.ip(left, "link", "add", left_name, "type", "veth", "peer", "name", right_name,
                "netns", self.namespaces[right])
        for namespace, interface, addr4, addr6 in addresses:
            self.ip(namespace, "addr", "add", addr4, "dev", interface)
            self.ip(namespace, "-6", "addr", "add", addr6, "dev", interface, "nodad")
            self.ip(namespace, "link", "set", interface, "up")

    def stage_executables(self):
        self.shim_binary = self.temporary / "wg-obfs-shim"
        shutil.copyfile(self.root / "target/debug/wg-obfs-shim", self.shim_binary)
        os.chmod(self.shim_binary, 0o755)
        staged_script = self.temporary / "probe.py"
        shutil.copyfile(self.script, staged_script)
        os.chmod(staged_script, 0o644)
        self.script = staged_script

    def setup(self):
        self.stage_executables()
        for role in ("client", "router", "relay"):
            name = self.prefix + "-" + role
            self.command("ip", "netns", "add", name)
            self.namespaces[role] = name
            self.ip(role, "link", "set", "lo", "up")
            namespace_inode = self.run(role, "readlink", "/proc/self/ns/net").stdout.strip()
            require(namespace_inode != os.readlink("/proc/self/ns/net"), "namespace isolation check failed")
            interfaces = json.loads(self.ip(role, "-j", "link", "show").stdout)
            require([interface["ifname"] for interface in interfaces] == ["lo"], "namespace inherited management interface")
        self.link("client", "router", "eth0", "client0", [
            ("client", "eth0", CLIENT4 + "/24", CLIENT6 + "/64"),
            ("router", "client0", "192.0.2.1/24", "fd00:5::1/64")])
        self.link("router", "relay", "relay0", "eth0", [
            ("router", "relay0", "198.51.100.1/24", "fd00:6::1/64"),
            ("relay", "eth0", RELAY4 + "/24", RELAY6 + "/64")])
        for role, interface in (("client", "eth0"), ("router", "client0"), ("router", "relay0"), ("relay", "eth0")):
            self.run(role, "sysctl", "-qw", f"net.ipv4.conf.{interface}.rp_filter=0")
        self.run("router", "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
        for address in (APP4 + "/32", APP6 + "/128"):
            self.ip("relay", "addr", "add", address, "dev", "lo")
        self.ip("router", "addr", "add", DNS4 + "/32", "dev", "lo")
        for address in (APP4 + "/32", INNER4 + "/32"):
            self.ip("router", "route", "add", address, "via", RELAY4)
        for address in (APP6 + "/128", INNER6 + "/128"):
            self.ip("router", "-6", "route", "add", address, "via", RELAY6)
        self.ip("relay", "route", "add", "default", "via", "198.51.100.1")
        self.ip("relay", "-6", "route", "add", "default", "via", "fd00:6::1")
        self.ip("client", "route", "add", "default", "via", "192.0.2.1")
        self.ip("client", "-6", "route", "add", "default", "via", "fd00:5::1")
        self.ip("client", "route", "add", RELAY4 + "/32", "via", "192.0.2.1", "dev", "eth0")
        self.ip("client", "-6", "route", "add", RELAY6 + "/128", "via", "fd00:5::1", "dev", "eth0")
        self.command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                     "-keyout", str(self.temporary / "dns.key"), "-out", str(self.temporary / "dns.crt"),
                     "-subj", "/CN=dns.vpn005.invalid", "-addext", "subjectAltName=DNS:dns.vpn005.invalid")
        for name in ("client", "relay"):
            (self.temporary / (name + ".key")).write_text(self.command("wg", "genkey").stdout)
            os.chmod(self.temporary / (name + ".key"), 0o600)
        (self.temporary / "obfs.key").write_text(secrets.token_hex(32))
        # Both real processes enforce strict read-only secret-file permissions.
        os.chmod(self.temporary / "obfs.key", 0o400)
        os.chown(self.temporary / "obfs.key", 65534, 65534)
        self.wg("relay", 51820, "10.13.13.1/24", INNER6 + "/64")
        client_pub = self.command("wg", "pubkey", input=(self.temporary / "client.key").read_text()).stdout.strip()
        self.run("relay", "wg", "set", "wg0", "peer", client_pub, "allowed-ips", "10.13.13.2/32,fd13:13::2/128")
        (self.temporary / "dns-mode").write_text("good")
        for role in ("router", "relay"):
            self.background(role, [sys.executable, self.script, "--serve", role, self.temporary, self.output], role + "-fixture.log")
        env = {"PATH": os.environ["PATH"], "HOME": str(self.temporary), "RUST_LOG": "error",
               "ADMIN_API_KEY": secrets.token_hex(32), "WG_OBFUSCATION_KEY_FILE": str(self.temporary / "obfs.key"),
               "WG_PORT": "443", "WG_INTERNAL_PORT": "51820", "WG_MTU": "1419",
               "WG_INTERFACE": "wg0", "WG_OBFUSCATION_ENABLED": "true",
               "SYNC_OUTBOX_DIR": str(self.temporary / "outbox"), "EXPLICIT_PROXY_ENABLED": "false"}
        self.background("relay", [self.root / "target/debug/ssl-proxy"], "ssl-proxy.log", env=env)
        for role in ("router", "relay"):
            for _ in range(40):
                if (self.temporary / (role + ".ready")).exists():
                    break
                time.sleep(0.1)
            else:
                raise ValueError(f"{role} owned fixture failed to start")
        time.sleep(0.3)

    def wg(self, role, port, addr4, addr6):
        self.ip(role, "link", "add", "wg0", "type", "wireguard")
        self.run(role, "wg", "set", "wg0", "listen-port", port, "private-key", self.temporary / (role + ".key"))
        self.ip(role, "addr", "add", addr4, "dev", "wg0")
        self.ip(role, "-6", "addr", "add", addr6, "dev", "wg0", "nodad")
        self.ip(role, "link", "set", "wg0", "mtu", "1419", "up")

    def start_shim(self):
        env = {"PATH": os.environ["PATH"], "HOME": str(self.temporary), "RUST_LOG": "error",
               "WG_OBFUSCATION_KEY_FILE": str(self.temporary / "obfs.key"), "WG_OBFS_SERVER_ADDR": RELAY4 + ":443",
               "WG_OBFS_SHIM_LISTEN_ADDR": "127.0.0.1:51821"}
        self.shim = self.background("client", [self.shim_binary],
                                    "shim-" + secrets.token_hex(3) + ".log", uid=65534, env=env)
        time.sleep(0.2)

    def select(self, profile):
        if self.shim:
            self.shim.kill()
            self.shim.wait()
            self.shim = None
        if self.run("client", "ip", "link", "show", "wg0", check=False).returncode == 0:
            self.ip("client", "link", "del", "wg0")
        self.policy(profile)
        self.wg("client", 51819, "10.13.13.2/32", "fd13:13::2/128")
        relay_pub = self.command("wg", "pubkey", input=(self.temporary / "relay.key").read_text()).stdout.strip()
        endpoint = "127.0.0.1:51821" if profile == "shim-aead" else RELAY4 + ":51820"
        self.run("client", "wg", "set", "wg0", "fwmark", "51820", "peer", relay_pub,
                 "allowed-ips", "0.0.0.0/0,::/0", "endpoint", endpoint, "persistent-keepalive", "1")
        if profile == "shim-aead":
            self.start_shim()
        self.tunnel_routes(True)

    def tunnel_routes(self, enable):
        operation = "replace" if enable else "del"
        for family in ((), ("-6",)):
            for prefix in (("0.0.0.0/1", "128.0.0.0/1") if not family else ("::/1", "8000::/1")):
                self.run("client", "ip", *family, "route", operation, prefix, "dev", "wg0", check=enable)

    def policy(self, profile, enable=True):
        if not enable:
            self.run("client", "nft", "delete", "table", "inet", "wg_containment")
            return
        text = (self.root / "config/client/leak-containment-linux.nft.example").read_text()
        for key, value in {"PHYSICAL_INTERFACE": "eth0", "WG_INTERFACE": "wg0", "SHIM_UID": "65534",
                           "RELAY_IPV4": RELAY4, "RELAY_IPV6": RELAY6, "RELAY_PORT": "443"}.items():
            text = text.replace("__" + key + "__", value)
        if self.run("client", "nft", "list", "table", "inet", "wg_containment", check=False).returncode == 0:
            # Atomic replacement: no interval of unrestricted fixture egress.
            text = "delete table inet wg_containment\n" + text
        self.run("client", "nft", "-f", "-", input=text)
        # The current real relay has no IPv6 listener. Do not leave an unused
        # IPv6 candidate exception open merely because the reference is dual-stack.
        self.run("client", "nft", "flush", "set", "inet", "wg_containment", "relay6")
        if profile == "direct-wg":
            # Explicit CONTROL-ONLY kernel exception; production shim policy stays UID-bound.
            self.run("client", "nft", "insert", "rule", "inet", "wg_containment", "output",
                     "oifname", "eth0", "ip", "daddr", RELAY4, "udp", "dport", "51820",
                     "meta", "mark", "51820", "accept")

    def probes(self, nonce):
        output = self.run("client", "setpriv", "--reuid=65533", "--regid=65533", "--clear-groups",
                          "--bounding-set=-all", "--no-new-privs", sys.executable, self.script, "--probe", nonce)
        return json.loads(output.stdout)

    def capture_start(self, identifier):
        self.captures = []
        for namespace, interface, kind in (("client", "eth0", "physical"), ("client", "wg0", "tunnel"), ("relay", "eth0", "relay")):
            name = identifier + "-" + kind + ".pcap"
            process = self.background(namespace, ["tcpdump", "-U", "-n", "-s", "0", "-Z", "root", "-i", interface,
                                      "-w", self.output / name], identifier + "-" + kind + ".log")
            self.captures.append(process)
        time.sleep(0.25)
        require(all(process.poll() is None for process in self.captures), "capture failed to start")

    def capture_stop(self):
        for process in self.captures:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
        for process in self.captures:
            process.wait(timeout=5)
            require(process.returncode == 0, "capture failed or interface disappeared")
        self.captures = []

    def restore_physical(self):
        """Restore the static underlay after link changes and before later rows."""
        self.ip("client", "link", "set", "eth0", "up")
        self.ip("client", "addr", "replace", CLIENT4 + "/24", "dev", "eth0")
        self.ip("client", "-6", "addr", "replace", CLIENT6 + "/64", "dev", "eth0", "nodad")
        for family, gateway, relay in (((), "192.0.2.1", RELAY4 + "/32"),
                                       (("-6",), "fd00:5::1", RELAY6 + "/128")):
            self.ip("client", *family, "route", "replace", "default", "via", gateway, "dev", "eth0")
            self.ip("client", *family, "route", "replace", relay, "via", gateway, "dev", "eth0")

    def row(self, profile, scenario, control=False):
        identifier = profile + "-" + scenario
        nonce = "vpn005-" + secrets.token_hex(6)
        result = {"os": "linux", "profile": profile, "scenario": scenario, "status": "fail", "nonce": nonce}
        self.policy(profile)
        self.tunnel_routes(True)
        self.ip("client", "link", "set", "wg0", "up")
        (self.temporary / "dns-mode").write_text("good")
        self.capture_start(identifier)
        try:
            startup_observed = None
            if scenario == "startup-before-wg":
                # Capture before making WG unavailable, then generate the first
                # application probes of this scenario before activating WG.
                self.tunnel_routes(False)
                self.ip("client", "link", "set", "wg0", "down")
                startup_observed = self.probes(nonce + "-failure")
                require(not any(startup_observed.values()), "application escaped before WG activation")
                self.ip("client", "link", "set", "wg0", "up")
                self.tunnel_routes(True)
            # A fresh kernel handshake plus real traffic proves capture/path health
            # before every destructive/failure-window probe.
            for _ in range(10):
                baseline = self.probes(nonce)
                if all(baseline.values()):
                    break
                time.sleep(0.3)
            require(all(baseline.values()), f"real {profile} baseline failed: {baseline}")
            handshake = self.run("client", "wg", "show", "wg0", "latest-handshakes").stdout.strip().split()
            result["handshake_epoch"] = int(handshake[-1])
            routes = {"ipv4": json.loads(self.ip("client", "-j", "route", "get", RELAY4).stdout),
                      "ipv6": json.loads(self.ip("client", "-j", "-6", "route", "get", RELAY6).stdout)}
            route_name = identifier + "-routes.json"
            write_json(self.output / route_name, routes)
            expected = dict.fromkeys(TRAFFIC, True)
            if control:
                self.policy(profile, False)
                self.tunnel_routes(False)
            elif scenario in ("reconnect", "wg-interface-removal"):
                # Keep capture interface allocated while absent routing simulates
                # startup/reconnect. Actual interface deletion is separately blocked.
                self.tunnel_routes(False)
                self.ip("client", "link", "set", "wg0", "down")
                expected = dict.fromkeys(TRAFFIC, False)
            elif scenario == "shim-crash" and profile == "shim-aead":
                self.shim.kill()
                self.shim.wait()
                self.shim = None
                expected = dict.fromkeys(TRAFFIC, False)
            elif scenario == "shim-restart" and profile == "shim-aead":
                self.shim.kill()
                self.shim.wait()
                self.start_shim()
                time.sleep(1)
            elif scenario in ("dns-dot-outage", "certificate-failure", "dns-timeout"):
                mode = {"dns-dot-outage": "outage", "certificate-failure": "certificate-failure", "dns-timeout": "timeout"}[scenario]
                (self.temporary / "dns-mode").write_text(mode)
                expected["dns4"] = expected["dns6"] = False
            elif scenario == "network-change":
                self.ip("client", "link", "set", "eth0", "down")
                self.ip("client", "link", "set", "eth0", "up")
                self.restore_physical()
                # The validator expects recovered tunnel traffic after this flap.
            elif scenario == "ipv4-only":
                self.ip("client", "-6", "addr", "del", CLIENT6 + "/64", "dev", "eth0")
            elif scenario == "outer-udp-blocked":
                self.run("router", "nft", "-f", "-", input="table inet block_outer { chain forward { type filter hook forward priority -10; policy accept; udp dport { 443, 51820 } drop; } }")
                expected = dict.fromkeys(TRAFFIC, False)
            if scenario == "lan-denied":
                # Give application destinations physical routes to exercise LAN/
                # bootstrap denial without changing the physical exception tuple.
                self.tunnel_routes(False)
                expected = dict.fromkeys(TRAFFIC, False)
            if scenario == "startup-before-wg":
                expected = dict.fromkeys(TRAFFIC, False)
            observed = startup_observed if startup_observed is not None else self.probes(nonce + "-failure")
            if not control:
                require(observed == expected, f"failure-window outcome differs: expected={expected}, observed={observed}")
            self.capture_stop()
            physical_name, tunnel_name = identifier + "-physical.pcap", identifier + "-tunnel.pcap"
            app, dns, outer, _ = counts(packets(self.output / physical_name), packets(self.output / tunnel_name), profile)
            require(outer > 0, "no outer packets captured")
            require((app > 0 and dns > 0) if control else (app == 0 and dns == 0), "leak detector control/containment failed")
            result.update(status="pass", capture_valid=True, outer_route_uses_physical_interface=True,
                          protected_dns_verified=True, unexpected_application_packets=app, unexpected_dns_packets=dns,
                          traffic=baseline, attempts=dict.fromkeys(TRAFFIC, 1),
                          failure_window_success=observed, failure_window_expected=expected,
                          captures={"physical": physical_name, "tunnel": tunnel_name,
                                    "relay": identifier + "-relay.pcap"},
                          routes=route_name, dns_evidence="dns.jsonl")
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            result.update(status="fail", reason=str(error), capture_valid=False)
        finally:
            if self.captures:
                try:
                    self.capture_stop()
                except (ValueError, subprocess.SubprocessError):
                    pass
            self.run("router", "nft", "delete", "table", "inet", "block_outer", check=False)
            (self.temporary / "dns-mode").write_text("good")
            self.ip("client", "link", "set", "wg0", "up")
            self.restore_physical()
            self.tunnel_routes(True)
            if profile == "shim-aead" and self.shim is None:
                self.start_shim()
        return result

    def execute(self):
        try:
            self.setup()
            for profile in PROFILES:
                self.select(profile)
                self.data["controls"].append(self.row(profile, "uncontained-control", True))
                for scenario in SCENARIOS:
                    blockers = {
                        "sleep-resume": "network namespaces cannot prove actual OS suspend/resume; OS adapter/evidence required",
                        "ipv6-only": "real ssl-proxy relay binds IPv4 only; IPv6-only outer profile requires separately scoped runtime change",
                        "wg-interface-removal": "deleting capture interface invalidates per-interface capture; OS capture adapter required",
                    }
                    if scenario in blockers:
                        self.data["results"].append({"os": "linux", "profile": profile, "scenario": scenario,
                                                     "status": "blocked", "capture_valid": False, "reason": blockers[scenario]})
                    else:
                        self.data["results"].append(self.row(profile, scenario))
                    write_json(self.output / "results.json", self.data)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            self.data["setup_error"] = str(error)
            write_json(self.output / "results.json", self.data)
            raise
        finally:
            self.cleanup()
        validate(self.output)

    def cleanup(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        for name in reversed(tuple(self.namespaces.values())):
            self.command("ip", "netns", "del", name, check=False)
        shutil.rmtree(self.temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test", action="store_true")
    group.add_argument("--validate", metavar="DIRECTORY")
    group.add_argument("--run-linux", metavar="DIRECTORY", help=argparse.SUPPRESS)
    group.add_argument("--probe", metavar="NONCE", help=argparse.SUPPRESS)
    group.add_argument("--serve", nargs=3, metavar=("ROLE", "PRIVATE_DIR", "OUTPUT_DIR"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.run_linux:
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.self_test:
            self_test()
        elif args.validate:
            validate(args.validate)
            print("PASS: complete Linux capture matrix and leak controls verified")
        elif args.run_linux:
            LinuxFixture(args.run_linux).execute()
        elif args.probe:
            probe(args.probe)
        else:
            serve(*args.serve)
        return 0
    except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError, struct.error) as error:
        print(f"FAIL/BLOCKED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
