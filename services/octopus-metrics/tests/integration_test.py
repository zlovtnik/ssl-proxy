"""Real adapter contracts, using only ephemeral Testcontainers services."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
import unittest

import boto3
from botocore.config import Config as S3Config
import psycopg2
import redis
from testcontainers.core.container import DockerContainer
from testcontainers.community.postgres import PostgresContainer

ROOT = Path(__file__).resolve().parents[3]
BUILD: Path


def eventually(check, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except (OSError, ValueError, redis.RedisError):
            pass
        time.sleep(0.05)
    raise AssertionError("fixture did not become ready")


class AdapterContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resources = ExitStack()
        cls.addClassCleanup(cls.resources.close)
        cls.pg = cls.resources.enter_context(PostgresContainer(
            "postgres:17-alpine", username="fixture", password="fixture-only",
            dbname="test_octopus_metrics"))
        cls.cache = cls.resources.enter_context(DockerContainer("redis:7.4.3-alpine")
            .with_exposed_ports(6379))
        cls.minio = cls.resources.enter_context(DockerContainer(
            "elestio/minio@sha256:25348a257f1ece1b192f25f6cd9854618fa86422ac87b494b5d4e629c556d4bd")
            .with_env("MINIO_ROOT_USER", "fixture-access")
            .with_env("MINIO_ROOT_PASSWORD", "fixture-secret")
            .with_command("server /data").with_exposed_ports(9000))
        cls.admin = psycopg2.connect(host=cls.pg.get_container_host_ip(),
            port=cls.pg.get_exposed_port(5432), user="fixture", password="fixture-only",
            dbname="test_octopus_metrics")
        cls.addClassCleanup(cls.admin.close)
        cls.admin.autocommit = True
        # This account and DDL exist only in the container created above.
        with cls.admin.cursor() as cursor:
            cursor.execute("SELECT current_database()")
            assert cursor.fetchone()[0].startswith("test_octopus_metrics")
            cursor.execute("CREATE ROLE octopus_metrics LOGIN PASSWORD 'metrics-fixture'")
            cursor.execute("ALTER ROLE octopus_metrics SET timezone TO 'Pacific/Honolulu'")
            manifest = (ROOT / "sql/postgres/octopus_core/manifest.yaml").read_text()
            apply_order = manifest.split("apply_order:\n", 1)[1].split("retired:", 1)[0]
            for relative in re.findall(r"^  - (.+)$", apply_order, re.MULTILINE):
                cursor.execute((ROOT / "sql/postgres/octopus_core" / relative).read_text())
            checksum = re.search(r"manifest_sha256: ([a-f0-9]{64})", manifest).group(1)
            version = re.search(r"schema_version: (\d+)", manifest).group(1)
            cursor.execute("UPDATE octopus_core.schema_readiness SET required_version=%s, "
                "applied_version=%s, required_checksum=%s, applied_checksum=%s, ready=true "
                "WHERE domain='octopus_core'", (version, version, checksum, checksum))
            grants = (ROOT / "sql/postgres/octopus_core/grants/metrics_read_only.sql.tmpl").read_text()
            cursor.execute(grants.replace("{{OCTOPUS_METRICS_ACCOUNT}}", "octopus_metrics"))
        cls.redis = redis.Redis(host=cls.cache.get_container_host_ip(),
            port=int(cls.cache.get_exposed_port(6379)))
        eventually(cls.redis.ping)
        cls.s3_url = f"http://{cls.minio.get_container_host_ip()}:{cls.minio.get_exposed_port(9000)}"
        cls.s3 = boto3.client("s3", endpoint_url=cls.s3_url, aws_access_key_id="fixture-access",
            aws_secret_access_key="fixture-secret", region_name="us-east-1",
            config=S3Config(signature_version="s3v4", connect_timeout=2, read_timeout=2))
        deadline = time.monotonic() + 30
        while True:
            try:
                cls.s3.create_bucket(Bucket="ssl-proxy-stats")
                break
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        cls.env = dict(os.environ, POSTGRES_HOST=cls.pg.get_container_host_ip(),
            POSTGRES_PORT=str(cls.pg.get_exposed_port(5432)), POSTGRES_DATABASE="test_octopus_metrics",
            POSTGRES_USER="octopus_metrics", POSTGRES_PASSWORD="metrics-fixture",
            POSTGRES_SSL_MODE="disable", POSTGRES_SSL_SERVER_NAME="", POSTGRES_SSL_CA_PATH="",
            STATS_LOCAL_DEV="true", MINIO_ENDPOINT=cls.s3_url,
            MINIO_ACCESS_KEY_ID="fixture-access", MINIO_SECRET_ACCESS_KEY="fixture-secret",
            REDIS_ADDR=f"{cls.cache.get_container_host_ip()}:{cls.cache.get_exposed_port(6379)}",
            REDIS_PASSWORD="", STATS_JOB_TIMEOUT_SECONDS="3")
        cls.env.pop("POSTGRES_PASSWORD_FILE", None)

    def probe(self, mode, at="2026-10-08T12:30:00Z", payload=None, env=None, success=True):
        with tempfile.TemporaryDirectory(prefix="octopus-metrics-probe-") as directory:
            args = [str(BUILD / "metrics-probe"), mode, at]
            if payload is not None:
                file = Path(directory) / "snapshot.json"
                file.write_text(json.dumps(payload))
                args.append(str(file))
            result = subprocess.run(args, env=env or self.env, capture_output=True, text=True, timeout=15)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_01_empty_database_has_measured_zero_and_null_peaks(self):
        snapshot = json.loads(self.probe("snapshot").stdout)
        self.assertIsNone(snapshot["peakRecordsDay"])
        self.assertEqual(snapshot["lifetimeTotals"]["recordsTotal"], 0)
        self.assertEqual(len(snapshot["throughput7d"]["series"]), 168)
        self.assertTrue(all(point["records"] == 0 for point in snapshot["throughput7d"]["series"]))

    def test_02_real_sql_preserves_utc_ties_and_complete_hour(self):
        times = ["2026-09-28T11:00:00Z"] * 2 + ["2026-10-05T11:00:00Z"] * 3 + \
            ["2026-10-06T11:00:00Z"] * 3 + ["2026-10-08T11:00:00Z"] * 4 + ["2026-10-08T12:00:00Z"]
        with self.admin.cursor() as cursor:
            for offset, timestamp in enumerate(times):
                cursor.execute("INSERT INTO octopus_core.ingestion_evidence "
                    "(topic, partition_id, record_offset, group_id, group_version, artifact_sha256, "
                    "payload_sha256, first_seen_at) VALUES ('fixture', 0, %s, 'fixture', '1', %s, %s, %s)",
                    (offset, "0" * 64, "0" * 64, timestamp))
        snapshot = json.loads(self.probe("snapshot").stdout)
        self.assertEqual(snapshot["peakRecordsDay"], 5)
        self.assertEqual(snapshot["peakRecordsDayDate"], "2026-10-08")
        self.assertEqual(snapshot["peakRecordsWeek"], 11)
        self.assertEqual(snapshot["peakRecordsWeekStart"], "2026-10-05")
        self.assertEqual(snapshot["peakRecordsWeekEnd"], "2026-10-11")
        self.assertEqual(snapshot["lifetimeTotals"]["recordsTotal"], 13)
        self.assertEqual(snapshot["lifetimeTotals"]["daysCounted"], 4)
        self.assertEqual(snapshot["throughput24h"]["series"][-1],
            {"bucketStart": "2026-10-08T11:00:00Z", "records": 4})
        # Equal daily counts select the earliest UTC date.
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE octopus_core.ingestion_evidence SET first_seen_at='2026-10-07T11:00:00Z' "
                "WHERE record_offset IN (11,12)")
        tied = json.loads(self.probe("snapshot").stdout)
        self.assertEqual(tied["peakRecordsDayDate"], "2026-10-05")

    def test_03_runtime_role_cannot_read_payloads_or_write(self):
        connection = psycopg2.connect(host=self.env["POSTGRES_HOST"], port=self.env["POSTGRES_PORT"],
            user="octopus_metrics", password="metrics-fixture", dbname="test_octopus_metrics")
        self.addCleanup(connection.close)
        connection.autocommit = True
        with connection.cursor() as cursor:
            for query in ["SELECT payload_sha256 FROM octopus_core.ingestion_evidence", 
                          "DELETE FROM octopus_core.ingestion_evidence",
                          "CREATE TABLE octopus_core.forbidden (id int)"]:
                with self.assertRaises(psycopg2.errors.InsufficientPrivilege):
                    cursor.execute(query)

    def test_04_preflight_fails_closed_on_not_ready_or_checksum_drift(self):
        with self.admin.cursor() as cursor:
            cursor.execute("UPDATE octopus_core.schema_readiness SET ready=false")
            try:
                self.assertEqual(self.probe("verify", success=False).stderr, "schema")
            finally:
                cursor.execute("UPDATE octopus_core.schema_readiness SET ready=true")
            cursor.execute("SELECT required_checksum FROM octopus_core.schema_readiness")
            previous = cursor.fetchone()[0]
            cursor.execute("UPDATE octopus_core.schema_readiness SET required_checksum=%s, applied_checksum=%s",
                ("0" * 64, "0" * 64))
            try:
                self.assertEqual(self.probe("verify", success=False).stderr, "schema")
            finally:
                cursor.execute("UPDATE octopus_core.schema_readiness SET required_checksum=%s, applied_checksum=%s",
                    (previous, previous))

    def test_05_database_deadline_discards_blocked_connection(self):
        self.admin.autocommit = False
        try:
            with self.admin.cursor() as cursor:
                cursor.execute("LOCK TABLE octopus_core.ingestion_evidence IN ACCESS EXCLUSIVE MODE")
            start = time.monotonic()
            result = self.probe("snapshot", env=dict(self.env, STATS_JOB_TIMEOUT_SECONDS="1"), success=False)
            self.assertEqual(result.stderr, "timeout")
            self.assertLess(time.monotonic() - start, 4)
        finally:
            self.admin.rollback()
            self.admin.autocommit = True
        self.probe("snapshot")

    def test_06_redis_and_minio_reject_older_and_concurrent_publications(self):
        older = {"asOf": "2026-10-08T12:30:00Z", "version": 0}
        newer = {"asOf": "2026-10-08T12:30:00.900Z", "version": 1}
        for mode in ["redis", "object"]:
            self.probe(mode, newer["asOf"], newer)
            self.probe(mode, older["asOf"], older)
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(lambda _: self.probe(mode, older["asOf"], older), range(4)))
                self.assertTrue(all(result.returncode == 0 for result in results))
            stored = self.redis.get("stats:current:v2") if mode == "redis" else \
                self.s3.get_object(Bucket="ssl-proxy-stats", Key="stats/latest.json")["Body"].read()
            self.assertEqual(json.loads(stored), newer)
        nano = {"asOf": "2026-10-08T12:30:00.900000001Z", "version": 2}
        self.redis.set("stats:current:v2", json.dumps(nano))
        self.s3.put_object(Bucket="ssl-proxy-stats", Key="stats/latest.json", Body=json.dumps(nano).encode())
        self.probe("redis", newer["asOf"], newer)
        self.probe("object", newer["asOf"], newer)
        self.assertEqual(json.loads(self.redis.get("stats:current:v2")), nano)
        self.assertEqual(json.loads(self.s3.get_object(Bucket="ssl-proxy-stats", Key="stats/latest.json")["Body"].read()), nano)

    def test_07_service_health_live_bridge_publication_and_shutdown(self):
        class LiveHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                body = json.dumps({"asOf": at, "liveStrip": {"ingestProcessedRatePerSec": 2.5,
                    "pendingLedgerCount": 9, "brokerLagCount": 16300000,
                    "lastIngestSuccessAt": None, "backpressureActive": False}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        import urllib.request
        server = ThreadingHTTPServer(("127.0.0.1", 0), LiveHandler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        env = dict(self.env, STATS_OCTOPUS_LIVE_URL=f"http://127.0.0.1:{server.server_port}/internal/metrics/live",
            STATS_HTTP_PORT=str(port), STATS_PUBLISH_INTERVAL_SECONDS="1", STATS_LIVE_INTERVAL_SECONDS="1",
            STATS_HISTORY_INTERVAL_SECONDS="1", STATS_PEAKS_INTERVAL_SECONDS="1")
        with tempfile.TemporaryFile(mode="w+t") as log:
            process = subprocess.Popen([str(BUILD / "octopus-metrics")], env=env, stderr=log)
            try:
                def healthy():
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/ready", timeout=1) as response:
                        return response.status == 200
                eventually(healthy)
                snapshot = eventually(lambda: json.loads(self.redis.get("stats:current:v2") or "{}")
                    if json.loads(self.redis.get("stats:current:v2") or "{}").get("liveStrip") else None)
                self.assertEqual(snapshot["lifetimeTotals"]["recordsTotal"], 13)
                self.assertEqual(snapshot["liveStrip"]["pendingLedgerCount"], 9)
                self.assertEqual(snapshot["liveStrip"]["ingestProcessedRatePerSec"], 2.5)
                self.assertEqual(snapshot["liveStrip"]["brokerLagCount"], 16300000)
                self.assertEqual(len(snapshot["throughput24h"]["series"]), 24)
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=1) as response:
                    self.assertIn(b"octopus_metrics_publish_total", response.read())
                keys = self.s3.list_objects_v2(Bucket="ssl-proxy-stats")["Contents"]
                self.assertTrue(any(item["Key"].startswith("stats/history/") for item in keys))
                self.assertTrue(any(item["Key"].startswith("stats/daily/") for item in keys))
            finally:
                process.terminate()
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
            log.seek(0)
            self.assertEqual(code, 0, log.read())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    args = parser.parse_args()
    BUILD = args.build.resolve()
    unittest.main(argv=[__file__], verbosity=2)
