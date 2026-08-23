#!/usr/bin/env python3
"""Validate the canonical PostgreSQL runtime schema contract."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / "sql" / "postgres"
DOMAINS = ("octopus_core", "atheros_search", "schema_migrator", "keycloak")


def scalar(text: str, key: str) -> str:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(\S+)\s*$", text)
    return match.group(1) if match else ""


def apply_order(text: str) -> list[str]:
    match = re.search(r"(?ms)^apply_order:\n((?:  - .+\n)+)", text)
    return re.findall(r"(?m)^  - (.+)$", match.group(1)) if match else []


def main() -> int:
    failures: list[str] = []
    if (ROOT / "integration_console").exists():
        failures.append("obsolete integration_console schema exists")
    for domain in DOMAINS:
        directory = ROOT / domain
        manifest = directory / "manifest.yaml"
        if not manifest.is_file():
            failures.append(f"{domain}: missing manifest.yaml")
            continue
        text = manifest.read_text()
        if scalar(text, "database") != "sync":
            failures.append(f"{domain}: database must be sync")
        ordered = apply_order(text)
        recorded: dict[str, str] = {}
        checksums = directory / "checksums.sha256"
        if checksums.is_file():
            for line in checksums.read_text().splitlines():
                digest, _, relative = line.partition("  ")
                recorded[relative] = digest
        digest = hashlib.sha256()
        for relative in ordered:
            path = directory / relative
            if not path.is_file():
                failures.append(f"{domain}: missing {relative}")
                continue
            data = path.read_bytes()
            actual = hashlib.sha256(data).hexdigest()
            if recorded.get(relative) != actual:
                failures.append(f"{domain}/{relative}: checksum mismatch")
            digest.update(relative.encode())
            digest.update(b"\0")
            digest.update(data)
            digest.update(b"\0")
        if digest.hexdigest() != scalar(text, "manifest_sha256"):
            failures.append(f"{domain}: manifest checksum mismatch")

    sql = "\n".join(path.read_text() for path in ROOT.rglob("*.sql"))
    for label, pattern in {
        "stored routine": r"\bCREATE\s+(?:FUNCTION|PROCEDURE)\b",
        "trigger": r"\bCREATE\s+TRIGGER\b",
        "cron extension": r"\bpg_cron\b",
        "materialized view": r"\bMATERIALIZED\s+VIEW\b",
    }.items():
        if re.search(pattern, sql, re.I):
            failures.append(f"forbidden {label}")
    for required in (
        "PARTITION BY RANGE",
        "FOR UPDATE SKIP LOCKED",
        "USING hnsw",
        "VECTOR(768)",
        "jsonb",
        "timestamptz",
    ):
        source = sql
        if required == "FOR UPDATE SKIP LOCKED":
            source += "\n" + "\n".join(
                path.read_text() for path in (REPO / "services").rglob("*.scala")
            )
            source += "\n" + "\n".join(
                path.read_text() for path in (REPO / "services").rglob("*.go")
            )
        if required.lower() not in source.lower():
            failures.append(f"missing PostgreSQL feature: {required}")

    state_manifest = (ROOT / "schema_migrator" / "manifest.yaml").read_text()
    contract = (
        REPO
        / "apps/schema-migrator/src/main/resources/state-migrations/manifest.properties"
    ).read_text()
    expected = scalar(state_manifest, "manifest_sha256")
    if f"checksum={expected}" not in contract:
        failures.append("schema-migrator runtime checksum is stale")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("PostgreSQL schema contract is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
