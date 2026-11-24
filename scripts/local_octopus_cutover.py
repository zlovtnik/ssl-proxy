"""Verify the local Rust Octopus stack and optionally check Mac WireGuard egress."""

import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "-f", "docker-compose.yaml"]


def run(*args, data=None, env=None, timeout=60):
    return subprocess.run(args, input=data, capture_output=True, text=True, check=True,
                          timeout=timeout, cwd=ROOT, env=env).stdout.strip()


def dc(*args, **kwargs):
    return run(*COMPOSE, *args, **kwargs)


def sql(query):
    return dc("exec", "-T", "postgres", "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
              "-U", "platform_admin", "-d", "sync", "-c", query)


def wait_for(description, check):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(2)
    raise RuntimeError(f"timed out waiting for {description}")


def database():
    for domain in ("octopus_core", "atheros_search"):
        manifest = (ROOT / "sql/postgres" / domain / "manifest.yaml").read_text()
        digest = re.search(r"^manifest_sha256: ([0-9a-f]{64})$", manifest, re.M)
        if digest is None:
            raise RuntimeError(f"{domain} manifest is missing its checksum")
        checksum = digest[1]
        if sql(f"SELECT ready AND applied_checksum='{checksum}' AND required_checksum=applied_checksum "
               f"FROM {domain}.schema_readiness WHERE domain='{domain}'") != "t":
            raise RuntimeError(f"{domain} has not applied the local manifest")
    print("Verified Octopus and Atheros Search PostgreSQL schema checksums", flush=True)


def switch(image):
    candidate = json.loads(run("docker", "image", "inspect", image))[0]
    if candidate["Config"]["Entrypoint"] != ["/app/octopus"] or candidate["Os"] != "linux":
        raise ValueError("expected the built native Octopus Linux image")
    previous = json.loads(run("docker", "inspect", dc("ps", "-q", "octopus")))[0]
    old_command = " ".join(previous["Config"]["Cmd"] or [])
    scala = "exec java -jar /app/octopus.jar" in old_command
    if not scala and previous["Image"] != candidate["Id"]:
        raise RuntimeError("existing coordinator is neither the expected Scala service nor the requested native image")
    database()
    # Build and verify Search before replacing the existing coordinator.
    subprocess.run([*COMPOSE, "build", "atheros-search-init", "atheros-search"], cwd=ROOT, check=True)
    dc("run", "--rm", "-T", "--no-deps", "atheros-search-init")
    dc("up", "-d", "--no-build", "--no-deps", "--wait", "--wait-timeout", "180", "atheros-search", timeout=210)
    search()
    if scala:
        rollback = "ssl-proxy-local-octopus-rollback:" + previous["Image"].split(":")[1][:16]
        run("docker", "image", "tag", previous["Image"], rollback)
    run("docker", "image", "tag", candidate["Id"], "ssl-proxy-local-octopus-native:dev")
    up = ("up", "-d", "--pull", "never", "--no-build", "--no-deps", "--wait", "--wait-timeout", "210", "octopus")
    try:
        dc(*up, env=dict(os.environ, DOCKER_DEFAULT_PLATFORM="linux/" + candidate["Architecture"]), timeout=250)
        if run("docker", "inspect", "-f", "{{.Image}}", dc("ps", "-q", "octopus")) != candidate["Id"]:
            raise RuntimeError("running coordinator image differs from the requested build")
        ingestion()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        if scala:
            print(f"Native acceptance failed. Restoring {rollback}.", file=sys.stderr, flush=True)
            dc("-f", "docker-compose.octopus-scala.yaml", *up,
               env=dict(os.environ, LOCAL_OCTOPUS_SCALA_IMAGE=rollback), timeout=250)
        raise


def http(url, *options, data=None):
    return run("curl", "--noproxy", "*", "--fail", "--silent", "--show-error", "--max-time", "15",
               *options, url, data=data)


def endpoint(service, port):
    return "http://" + dc("port", service, str(port))


def search():
    base = endpoint("atheros-search", 8080)
    http(base + "/readyz")
    token = dc("run", "--rm", "-T", "--no-deps", "--entrypoint", "cat",
               "atheros-search-init", "/search/client.token")
    body = http(base + "/v1/search", "-H", "@-", "-H", "Content-Type: application/json",
                "--data-binary", '{"query":"example.com","kind":"SEARCH_KIND_PROXY_EVENT","mode":"SEARCH_MODE_SPARSE","topK":1}',
                data=f"Authorization: Bearer {token}\n")
    response = json.loads(body)
    if response.get("modeUsed", response.get("mode_used")) != "SEARCH_MODE_SPARSE":
        raise RuntimeError("Search did not return a sparse query response")
    print("Verified authenticated Atheros Search sparse query", flush=True)


def ingestion():
    if dc("exec", "-T", "octopus", "readlink", "/proc/1/exe") != "/app/octopus":
        raise RuntimeError("Octopus PID 1 is not the Rust executable")
    base = endpoint("octopus", 8081)
    try:
        readiness = json.loads(http(base + "/ready"))
    except json.JSONDecodeError as error:
        raise RuntimeError("native readiness response is not valid JSON") from error
    components = readiness.get("components") if isinstance(readiness, dict) else None
    processors = components.get("processors") if isinstance(components, dict) else None
    if not isinstance(processors, dict) or processors.get("status") != "UP":
        raise RuntimeError("native processor readiness failed")
    key = "local-smoke-" + uuid.uuid4().hex
    event = dict(stream_name="custom.raw", dedupe_key=key, payload_ref="inline://json/e30",
                 observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    topic = "sync.scan.request"
    dc("exec", "-T", "redpanda", "rpk", "topic", "produce", topic, "--brokers", "redpanda:9092",
       data=json.dumps(event) + "\n")
    def committed():
        result = sql("SELECT group_id,partition_id,record_offset FROM octopus_core.ingestion_evidence "
                     f"WHERE topic='{topic}' AND dedupe_key='{key}' AND disposition='processed' "
                     f"AND EXISTS (SELECT 1 FROM octopus_core.sync_events WHERE dedupe_key='{key}')")
        if not result:
            return False
        group, partition, offset = result.split("|")
        rows = dc("exec", "-T", "redpanda", "rpk", "group", "describe", group, "--brokers", "redpanda:9092")
        return any(parts[:2] == [topic, partition] and len(parts) > 2 and parts[2].isdigit()
                   and int(parts[2]) > int(offset) for parts in map(str.split, rows.splitlines()))
    wait_for(f"database evidence and broker commit for {key}", committed)
    print(f"Verified native ingestion and Kafka offset for {key}", flush=True)


def proxy():
    http(endpoint("ssl-proxy", 9098) + "/ready")
    dc("exec", "-T", "ssl-proxy", "ip", "link", "show", "wg0")


def vpn():
    if not dc("ps", "-q", "--status", "running", "mac-egress-bridge"):
        raise RuntimeError("start the Mac egress bridge with make local-egress-up")
    name = "example.com"
    route = run("route", "-n", "get", "10.13.13.1")
    interface = re.search(r"^\s*interface:\s*(\S+)\s*$", route, re.M)
    if not interface or not re.fullmatch(r"utun\d+", interface[1]):
        actual = interface[1] if interface else "unknown interface"
        raise RuntimeError(f"WireGuard DNS address 10.13.13.1 routes through {actual}; expected a utun interface")
    answers = run("dig", "@10.13.13.1", name, "A", "+short", "+time=3", "+tries=1")
    addresses = [line for line in answers.splitlines() if re.fullmatch(r"[0-9.]+", line)]
    if not addresses:
        raise RuntimeError("the VPN DNS server returned no IPv4 address")
    address = str(ipaddress.IPv4Address(addresses[0]))
    route = run("route", "-n", "get", address)
    if not re.search(r"^\s*interface:\s*utun\d+\s*$", route, re.M):
        raise RuntimeError("enable the local WireGuard client on this Mac before testing tunnel egress")
    since = sql("SELECT clock_timestamp()")
    http(f"https://{name}/", "-4", "--resolve", f"{name}:443:{address}")
    wait_for("new VPN proxy event for example.com", lambda:
             sql("SELECT EXISTS (SELECT 1 FROM octopus_core.proxy_events "
                 f"WHERE host='{name}:443' AND event_time >= '{since}'::timestamptz "
                 "AND peer_ip <<= inet '10.13.13.0/24')") == "t")
    print("Verified VPN DNS, tunnel HTTPS and a fresh PostgreSQL proxy event", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", help="switch to an already-built native image; omit to test the running stack")
    parser.add_argument("--vpn", action="store_true", help="also verify Mac WireGuard DNS, HTTPS and proxy ingestion")
    args = parser.parse_args()
    if args.vpn:
        COMPOSE.extend(["-f", "docker-compose.mac-egress.yaml"])
    try:
        proxy()
        if args.image:
            switch(args.image)
        else:
            database()
            search()
            ingestion()
        if args.vpn:
            vpn()
        print("Local stack checks passed")
    except subprocess.CalledProcessError as error:
        sys.exit((error.stderr or "").strip() or f"command failed with status {error.returncode}")
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        sys.exit(str(error))
