"""Exercise a registry-pinned native coordinator and its Scala rollback on disposable data."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

import yaml

from image_contract import KustomizationLoader, load_image_contracts, validate_digest
from octopus_image_contract import NATIVE_PATH, check_image, source_revisions
from octopus_rehearse_promotion import PROD, ROOT, SERVICE, deployment, render


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, cwd=ROOT, timeout=kwargs.pop("timeout", 60),
                                   **kwargs).strip()


def wait_for(description, check):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(2)
    raise RuntimeError(f"timed out waiting for {description}")


def smoke(directory, digest, config_only):
    docs = list(yaml.load_all(render(ROOT), Loader=KustomizationLoader))
    pod = deployment(docs)["spec"]["template"]["spec"]
    (container,) = (c for c in pod["containers"] if c["name"] == SERVICE)
    security = container["securityContext"]
    if (security["runAsUser"], security["runAsGroup"], security["readOnlyRootFilesystem"],
        security["runAsNonRoot"], security["allowPrivilegeEscalation"],
        security["capabilities"]["drop"]) != (1000, 1000, True, True, False, ["ALL"]):
        raise ValueError("production container security settings differ from the G4 fixture")
    for probe, path in (("startupProbe", "/live"), ("livenessProbe", "/live"), ("readinessProbe", "/ready")):
        if container[probe]["httpGet"] != {"path": path, "port": 8081}:
            raise ValueError(f"production {probe} differs from the G4 fixture")
    if container["resources"]["limits"] != {"cpu": "2", "memory": "4Gi"}:
        raise ValueError("production resource limits differ from the G4 fixture")
    rollback = container["image"]
    candidate = rollback.split("@")[0] + "@" + digest
    if candidate == rollback:
        raise ValueError("expected distinct candidate and rollback images")
    schema = next(c.reference for c in load_image_contracts(ROOT, "prod")
                  if c.service == "postgres-runtime-schema")
    env = {e["name"]: e["value"] for e in container["env"] if "value" in e}
    bootstrap = run("kustomize", "build", "--load-restrictor", "LoadRestrictionsNone",
                    ROOT / PROD / "bootstrap")
    maps = {d["metadata"]["name"]: d["data"] for d in yaml.load_all(bootstrap, Loader=KustomizationLoader)
            if d["kind"] == "ConfigMap" and "data" in d}
    topics_dir = directory / "topics"
    topics_dir.mkdir(mode=0o755)
    for key in ("topics.manifest", "topics.properties"):
        (topics_dir / key).write_text(maps["ssl-proxy-topics-manifest"][key])
        (topics_dir / key).chmod(0o444)

    # Use an independent Compose project and remove all published host ports.
    project = "octopus-g4-" + uuid.uuid4().hex
    compose = ["docker", "compose", "-p", project, "-f", ROOT / "docker-compose.yaml",
               "-f", directory / "override.yaml"]
    def dc(*args, **kwargs):
        return run(*compose, *args, **kwargs)

    def overlay(image):
        # Resolve production group identities, including the shared ConfigMap entries.
        group_env = {}
        for e in container["env"]:
            if e["name"].endswith("_CONSUMER"):
                if "value" in e:
                    group_env[e["name"]] = e["value"]
                else:
                    ref = e["valueFrom"]["configMapKeyRef"]
                    group_env[e["name"]] = maps[ref["name"]][ref["key"]]
        kept = ("OCTOPUS_ENABLED_PROCESSORS", "OCTOPUS_ENVIRONMENT", "SYNC_OUTBOX_DIR",
                "SYNC_REDPANDA_TOPIC_PARTITIONS", "SYNC_REDPANDA_TOPIC_MANIFEST",
                "POSTGRES_SCHEMA_MANIFEST_SHA256", "POSTGRES_PASSWORD_FILE", "POSTGRES_SSL_CA_PATH")
        runtime_env = {**group_env, **{key: env[key] for key in kept}}
        if image == rollback:
            runtime_env["JAVA_TOOL_OPTIONS"] = env["JAVA_TOOL_OPTIONS"]
        overlay_text = f"""
services:
  postgres:
    ports: !reset []
  redpanda:
    ports: !reset []
  postgres-schema:
    build: !reset null
    image: {schema}
  redpanda-init:
    volumes:
      - {topics_dir}:/config:ro
  local-init:
    volumes:
      - g4-password:/g4-password
      - g4-ca:/g4-ca
    entrypoint: ["/bin/sh", "-ec"]
    command:
      - |
        init-local-material
        install -m 0440 -g 1000 /octopus-secrets/octopus_runtime.password /g4-password/password
        install -m 0444 /octopus-secrets/ca.crt /g4-ca/ca.crt
  octopus:
    build: !reset null
    image: {image}
    platform: linux/amd64
    entrypoint: !reset null
    command: !reset null
    ports: !reset []
    restart: "no"
    user: "1000:1000"
    read_only: true
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    cpus: 2
    mem_limit: 4g
    tmpfs: ["/tmp", "/sync-outbox:uid=1000,gid=1000"]
    environment: {json.dumps(runtime_env)}
    volumes: !override
      - g4-ca:/var/run/pgbouncer-tls:ro
      - g4-password:/var/run/postgres-password:ro
      - {topics_dir}:/app/docker/redpanda:ro
volumes:
  g4-ca: {{}}
  g4-password: {{}}
"""
        (directory / "override.yaml").write_text(overlay_text)

    def sql(query):
        return dc("exec", "-T", "postgres", "psql", "-XAt", "-v", "ON_ERROR_STOP=1",
                  "-U", "platform_admin", "-d", "sync", "-c", query)

    def broker(*args, **kwargs):
        return dc("exec", "-T", "redpanda", "rpk", *args, "--brokers", "redpanda:9092", **kwargs)

    def health():
        for path in ("/live", "/ready", "/health", "/actuator/health", "/metrics", "/actuator/prometheus"):
            body = dc("exec", "-T", "octopus", "wget", "-T", "5", "-qO-", "http://localhost:8081" + path)
            if path in ("/metrics", "/actuator/prometheus"):
                if "# TYPE " not in body:
                    raise ValueError(f"missing Prometheus metrics at {path}")
            elif json.loads(body)["status"] != "UP":
                raise ValueError(f"unhealthy {path}")
            elif path != "/live" and json.loads(body)["components"]["processors"]["status"] != "UP":
                raise ValueError(f"enabled processors unready at {path}")

    def broker_unready():
        # GNU wget in the native image returns 8 for an HTTP error.
        result = subprocess.run(
            [*compose, "exec", "-T", "octopus", "wget", "-S", "--content-on-error",
             "-t", "1", "-T", "5", "-O-", "http://localhost:8081/ready"],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 8 or " 503 " not in result.stderr:
            return False
        components = json.loads(result.stdout)["components"]
        return components["postgres"]["status"] == "UP" and components["processors"]["status"] == "DOWN"

    topic = "sync.scan.request"
    group = env["SYNC_SCAN_CONSUMER"]
    wire = json.dumps(dict(stream_name="custom.raw", dedupe_key=project, payload_ref="inline://json/e30",
                           observed_at=datetime.now(timezone.utc).isoformat()))
    def committed(count):
        # rpk 24.2 group describe columns start with TOPIC PARTITION CURRENT-OFFSET.
        rows = [line.split() for line in broker("group", "describe", group).splitlines()]
        return any(row[:3] == [topic, "0", str(count)] for row in rows)

    def assert_evidence(count):
        rows = sql("SELECT record_offset, disposition FROM octopus_core.ingestion_evidence "
                   f"WHERE topic='{topic}' AND partition_id=0 AND group_id='{group}' AND dedupe_key='{project}' "
                   "ORDER BY record_offset")
        expected = ["0|processed"] + [f"{n}|duplicate" for n in range(1, count)]
        if rows.splitlines() != expected or sql("SELECT count(*) FROM octopus_core.sync_events "
                                                f"WHERE dedupe_key='{project}'") != "1":
            raise ValueError(f"unexpected durable evidence after {count} records: {rows}")

    for image in (rollback, candidate):
        overlay(image)
        services = json.loads(dc("config", "--format", "json"))["services"]
        coordinator = services["octopus"]
        if (coordinator["image"] != image or any(coordinator.get(k) for k in ("entrypoint", "command", "build"))
                or any(services[s].get("ports") for s in ("postgres", "redpanda", "octopus"))):
            raise RuntimeError("expected image defaults and isolated fixture ports")
    if config_only:
        print("Validated native and rollback Compose configurations")
        return
    source_revisions(ROOT, NATIVE_PATH)
    for image in (candidate, rollback):
        run("docker", "pull", "--platform", "linux/amd64", image, timeout=600)
    check_image(candidate, ROOT, native=True)
    try:
        for count, image in enumerate((candidate, candidate, rollback), start=1):
            overlay(image)
            if count == 2:
                dc("stop", "redpanda")
                dc("up", "-d", "--no-deps", "octopus")
                wait_for("503 from enabled processors while broker is offline", broker_unready)
                dc("exec", "-T", "octopus", "wget", "-T", "5", "-qO-", "http://localhost:8081/live")
                dc("start", "redpanda")
            flags = ["--build"] if count == 1 else ["--no-deps"]
            dc("up", "-d", *flags, "--wait", "--wait-timeout", "240", "octopus", timeout=900)
            health()
            schema_ok = sql("SELECT ready AND applied_checksum=required_checksum AND "
                            f"applied_checksum='{env['POSTGRES_SCHEMA_MANIFEST_SHA256']}' "
                            "FROM octopus_core.schema_readiness WHERE domain='octopus_core'")
            if schema_ok != "t":
                raise ValueError("production Octopus schema contract failed")
            if count > 1:
                wait_for("previous broker offset", lambda: committed(count - 1))
                assert_evidence(count - 1)
            broker("topic", "produce", topic, "--partition", "0", input=wire + "\n")
            wait_for("scan group commit", lambda: committed(count))
            assert_evidence(count)
            cid = dc("ps", "-q", "octopus")
            print(f"{image} committed={count} " +
                  run("docker", "stats", "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}", cid),
                  flush=True)
            if image == candidate:
                dc("stop", "-t", "30", "octopus")
                if run("docker", "inspect", "-f", "{{.State.ExitCode}} {{.State.OOMKilled}}", cid) != "0 false":
                    raise RuntimeError("coordinator did not exit cleanly on SIGTERM")
    finally:
        dc("down", "--volumes", "--remove-orphans", timeout=120)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("digest", type=validate_digest)
    parser.add_argument("--config-only", action="store_true", help="validate both Compose renders offline")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="octopus-g4-runtime-") as temp:
        smoke(Path(temp), args.digest, args.config_only)
