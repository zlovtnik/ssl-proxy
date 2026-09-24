#!/usr/bin/env python3
"""Reconcile Redpanda topic retention settings against the tracked manifest.

The tracked manifest is the only source of truth for topic retention. This
tool reports drift (``plan`` / ``check``) and, with an explicit confirmation,
applies the manifest to a live cluster (``apply``). Topic creation, partition
counting and replication stay with the redpanda-init Job.

Exit codes: 0 clean or applied, 1 runtime/usage error, 2 drift detected.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "cyber-stack/base/platform-config/configmap.yaml"
MANIFEST_CONFIGMAP = "ssl-proxy-topics-manifest"
RETENTION_KEYS = ("retention.ms", "retention.bytes")
APPLY_CONFIRMATION = "APPLY-TOPIC-CONFIG"


class ReconcileError(RuntimeError):
    """The manifest or the live cluster could not be read."""


@dataclass(frozen=True)
class TopicSpec:
    topic: str
    partitions: int
    replicas: int
    retention_ms: int
    retention_bytes: int

    @property
    def desired_config(self) -> dict[str, str]:
        return {
            "retention.ms": str(self.retention_ms),
            "retention.bytes": str(self.retention_bytes),
        }


@dataclass(frozen=True)
class LiveTopic:
    partitions: int
    config: dict[str, str]


def load_manifest(path: Path) -> list[TopicSpec]:
    text = path.read_text(encoding="utf-8")
    entries: list[str] = []
    if path.suffix in {".yaml", ".yml"}:
        for document in yaml.safe_load_all(text):
            if not isinstance(document, dict):
                continue
            if document.get("metadata", {}).get("name") == MANIFEST_CONFIGMAP:
                entries = str(document["data"]["topics.manifest"]).splitlines()
                break
        else:
            raise ReconcileError(f"{path}: ConfigMap {MANIFEST_CONFIGMAP} not found")
    else:
        entries = text.splitlines()

    specs: list[TopicSpec] = []
    for number, raw in enumerate(entries, 1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("|")
        if len(fields) != 5:
            raise ReconcileError(f"{path}:{number}: expected five fields")
        topic, partitions, replicas, retention_ms, retention_bytes = fields
        try:
            spec = TopicSpec(
                topic=topic,
                partitions=int(partitions),
                replicas=int(replicas),
                retention_ms=int(retention_ms),
                retention_bytes=int(retention_bytes),
            )
        except ValueError as error:
            raise ReconcileError(f"{path}:{number}: non-numeric field") from error
        if spec.partitions < 1 or spec.replicas < 1:
            raise ReconcileError(f"{path}:{number}: {topic} needs partitions and replicas")
        if spec.retention_ms < 0 or spec.retention_bytes < 1:
            raise ReconcileError(f"{path}:{number}: {topic} is unbounded")
        specs.append(spec)
    if not specs:
        raise ReconcileError(f"{path}: no topics")
    return specs


class RpkClient:
    def __init__(self, brokers: str, executable: str = "rpk") -> None:
        self.brokers = brokers
        self.executable = executable

    def run(self, *args: str) -> str:
        command = [self.executable, *args, "--brokers", self.brokers]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, check=False
            )
        except FileNotFoundError as error:
            raise ReconcileError(f"missing command: {self.executable}") from error
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise ReconcileError(f"{' '.join(command)}: {detail}")
        return completed.stdout

    def describe(self, topic: str) -> LiveTopic:
        summary = self.run("topic", "describe", topic, "--print-summary")
        partitions = _summary_int(summary, "PARTITIONS")
        if partitions is None:
            raise ReconcileError(f"{topic}: could not read partition count")
        config: dict[str, str] = {}
        for line in self.run("topic", "describe", topic, "-c").splitlines():
            fields = line.split()
            if len(fields) < 2 or fields[0] in {"KEY", "#", "CONFIGS"}:
                continue
            config.setdefault(fields[0], fields[1])
        return LiveTopic(partitions=partitions, config=config)

    def alter(self, topic: str, settings: dict[str, str]) -> None:
        args = ["topic", "alter-config", topic]
        for key, value in settings.items():
            args.extend(["--set", f"{key}={value}"])
        self.run(*args)


def _summary_int(summary: str, label: str) -> int | None:
    lines = summary.splitlines()
    for index, line in enumerate(lines):
        fields = line.split()
        if len(fields) >= 2 and fields[0] == label:
            try:
                return int(fields[1])
            except ValueError:
                return None
        if len(fields) >= 3 and fields[0] == "NAME" and fields[1] == label:
            try:
                return int(fields[2])
            except ValueError:
                return None
        if len(fields) == 2 and fields[0] == "NAME" and fields[1] == label:
            if index + 1 >= len(lines):
                return None
            following = lines[index + 1].split()
            if len(following) >= 2:
                try:
                    return int(following[1])
                except ValueError:
                    return None
            return None
    return None


@dataclass(frozen=True)
class Drift:
    topic: str
    reason: str

    def __str__(self) -> str:
        return f"{self.topic}: {self.reason}"


def diff(specs: list[TopicSpec], client: RpkClient) -> tuple[list[Drift], dict[str, dict[str, str]]]:
    drift: list[Drift] = []
    planned: dict[str, dict[str, str]] = {}
    for spec in specs:
        live = client.describe(spec.topic)
        if live.partitions != spec.partitions:
            drift.append(
                Drift(spec.topic, f"partitions {live.partitions} != {spec.partitions}")
            )
            continue
        settings = {
            key: value
            for key, value in spec.desired_config.items()
            if live.config.get(key) != value
        }
        if settings:
            planned[spec.topic] = settings
            rendered = ", ".join(f"{k}={v} (live {live.config.get(k, 'unset')})" for k, v in settings.items())
            drift.append(Drift(spec.topic, rendered))
    return drift, planned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode",
        choices=("plan", "check", "apply"),
        nargs="?",
        default="plan",
        help="plan reports drift, check fails on drift, apply writes the manifest",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--brokers", default=os.environ.get("RPK_BROKERS", "ssl-proxy-redpanda:9092"))
    parser.add_argument("--rpk", default=os.environ.get("RPK", "rpk"))
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)

    try:
        specs = load_manifest(args.manifest)
        client = RpkClient(args.brokers, executable=args.rpk)
        drift, planned = diff(specs, client)
    except ReconcileError as error:
        print(f"topic-reconcile: {error}", file=sys.stderr)
        return 1

    if not drift:
        print(f"topic-reconcile: {len(specs)} topics match {args.manifest}")
        return 0
    for item in drift:
        print(f"topic-reconcile: drift {item}")
    if args.mode == "plan":
        return 0
    if args.mode == "check":
        return 2
    if args.confirm != APPLY_CONFIRMATION:
        print(
            f"topic-reconcile: refusing to apply without --confirm {APPLY_CONFIRMATION}",
            file=sys.stderr,
        )
        return 1

    failed = False
    for spec in specs:
        settings = planned.get(spec.topic)
        if not settings:
            continue
        try:
            client.alter(spec.topic, settings)
        except ReconcileError as error:
            print(f"topic-reconcile: {error}", file=sys.stderr)
            failed = True
    try:
        remaining, _ = diff(specs, client)
    except ReconcileError as error:
        print(f"topic-reconcile: {error}", file=sys.stderr)
        return 1
    if remaining:
        for item in remaining:
            print(f"topic-reconcile: unresolved drift {item}", file=sys.stderr)
        return 1
    if failed:
        return 1
    print(f"topic-reconcile: applied {len(planned)} topic setting(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
