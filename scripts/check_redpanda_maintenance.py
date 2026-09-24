#!/usr/bin/env python3
"""Validate Redpanda maintenance topics and the bounded-retention contract."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
TOPICS = ROOT / "cyber-stack/base/redpanda-maintenance/topics.tsv"
PLATFORM_CONFIG = ROOT / "cyber-stack/base/platform-config/configmap.yaml"

# Maximum retention.ms allowed for a topic by the disk workmap. A future edit
# that silently raises these windows must fail the review gate.
MAX_RETENTION_MS = {"wireless.audit": 604800000}


def maintenance_topics() -> set[str]:
    configured: set[str] = set()
    for line_number, raw in enumerate(TOPICS.read_text(encoding="utf-8").splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 5:
            raise ValueError(f"{TOPICS}:{line_number}: expected five tab-separated fields")
        topic, keep_days, gate, required_groups, evidence_group = fields
        if not topic or topic in configured:
            raise ValueError(f"{TOPICS}:{line_number}: topic is empty or duplicated")
        if not keep_days.isdigit() or int(keep_days) < 1:
            raise ValueError(f"{TOPICS}:{line_number}: keep_days must be >= 1")
        if gate not in {"none", "pg"}:
            raise ValueError(f"{TOPICS}:{line_number}: gate must be none or pg")
        if required_groups in {"", "-"}:
            raise ValueError(f"{TOPICS}:{line_number}: required_groups must not be empty")
        if gate == "pg" and evidence_group in {"", "-"}:
            raise ValueError(f"{TOPICS}:{line_number}: pg gate requires evidence_group")
        if gate == "pg" and topic != "wireless.audit":
            raise ValueError(f"{TOPICS}:{line_number}: pg gate is only defined for wireless.audit")
        configured.add(topic)
    if not configured:
        raise ValueError(f"{TOPICS}: no maintenance topics")
    return configured


def topic_manifest() -> str:
    for document in yaml.safe_load_all(PLATFORM_CONFIG.read_text(encoding="utf-8")):
        if isinstance(document, dict) and document.get("metadata", {}).get("name") == "ssl-proxy-topics-manifest":
            return document["data"]["topics.manifest"]
    raise ValueError(f"{PLATFORM_CONFIG}: ssl-proxy-topics-manifest not found")


def validate() -> None:
    maintained = maintenance_topics()
    manifest_topics: set[str] = set()
    for line_number, raw in enumerate(topic_manifest().splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("|")
        if len(fields) != 5:
            raise ValueError(f"topics.manifest:{line_number}: expected five fields")
        topic, partitions, replicas, retention_ms, retention_bytes = fields
        manifest_topics.add(topic)
        if not partitions.isdigit() or int(partitions) < 1:
            raise ValueError(f"topics.manifest:{line_number}: {topic} has no partition count")
        if not replicas.isdigit() or int(replicas) < 1:
            raise ValueError(f"topics.manifest:{line_number}: {topic} has no replica count")
        if retention_ms.lstrip("-").isdigit() and int(retention_ms) >= 0:
            maximum = MAX_RETENTION_MS.get(topic)
            if maximum is not None and int(retention_ms) > maximum:
                raise ValueError(
                    f"topics.manifest:{line_number}: {topic} retention.ms "
                    f"{retention_ms} exceeds the {maximum}ms budget"
                )
        else:
            raise ValueError(f"topics.manifest:{line_number}: {topic} has invalid retention.ms")
        if not retention_bytes.lstrip("-").isdigit() or int(retention_bytes) < 1:
            raise ValueError(
                f"topics.manifest:{line_number}: {topic} lacks a per-partition "
                "retention.bytes cap"
            )
    missing = maintained - manifest_topics
    if missing:
        raise ValueError("maintenance topics absent from manifest: " + ", ".join(sorted(missing)))


if __name__ == "__main__":
    try:
        validate()
    except (KeyError, TypeError, ValueError, yaml.YAMLError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
