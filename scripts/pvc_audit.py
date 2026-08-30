#!/usr/bin/env python3
"""Report unowned, untracked and unreferenced Kubernetes PVC candidates.

This command is intentionally read-only. Deletion remains an explicitly
approved platform operation because reclaim policies can destroy data.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence


class PVCAuditError(RuntimeError):
    """The Kubernetes storage inventory could not be evaluated safely."""


@dataclass(frozen=True)
class Candidate:
    namespace: str
    name: str
    phase: str
    requested: str
    volume: str
    reclaim_policy: str
    storage_class: str


def items(payload: Mapping[str, Any], label: str) -> list[Mapping[str, Any]]:
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise PVCAuditError(f"{label} inventory does not contain an items list")
    return [item for item in raw_items if isinstance(item, Mapping)]


def pod_claim_references(payload: Mapping[str, Any]) -> set[tuple[str, str]]:
    references: set[tuple[str, str]] = set()
    for pod in items(payload, "pod"):
        metadata = pod.get("metadata")
        spec = pod.get("spec")
        if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
            continue
        namespace = str(metadata.get("namespace") or "default")
        volumes = spec.get("volumes")
        if not isinstance(volumes, list):
            continue
        for volume in volumes:
            if not isinstance(volume, Mapping):
                continue
            claim = volume.get("persistentVolumeClaim")
            if isinstance(claim, Mapping) and isinstance(claim.get("claimName"), str):
                references.add((namespace, claim["claimName"]))
    return references


def persistent_volumes(payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for volume in items(payload, "persistent volume"):
        metadata = volume.get("metadata")
        if isinstance(metadata, Mapping) and isinstance(metadata.get("name"), str):
            result[metadata["name"]] = volume
    return result


def find_candidates(
    pvc_payload: Mapping[str, Any],
    pv_payload: Mapping[str, Any],
    pod_payload: Mapping[str, Any],
) -> tuple[Candidate, ...]:
    referenced = pod_claim_references(pod_payload)
    volumes = persistent_volumes(pv_payload)
    candidates: list[Candidate] = []
    for claim in items(pvc_payload, "PVC"):
        metadata = claim.get("metadata")
        spec = claim.get("spec")
        status = claim.get("status")
        if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
            continue
        namespace = str(metadata.get("namespace") or "default")
        name = str(metadata.get("name") or "")
        if not name or (namespace, name) in referenced:
            continue
        if metadata.get("ownerReferences"):
            continue
        annotations = metadata.get("annotations")
        if isinstance(annotations, Mapping) and annotations.get(
            "argocd.argoproj.io/tracking-id"
        ):
            continue
        volume_name = str(spec.get("volumeName") or "")
        volume = volumes.get(volume_name, {})
        volume_spec = volume.get("spec") if isinstance(volume, Mapping) else {}
        if not isinstance(volume_spec, Mapping):
            volume_spec = {}
        resources = spec.get("resources")
        requests = resources.get("requests") if isinstance(resources, Mapping) else {}
        requested = requests.get("storage") if isinstance(requests, Mapping) else ""
        phase = status.get("phase") if isinstance(status, Mapping) else ""
        candidates.append(
            Candidate(
                namespace=namespace,
                name=name,
                phase=str(phase or "unknown"),
                requested=str(requested or "unknown"),
                volume=volume_name or "unbound",
                reclaim_policy=str(volume_spec.get("persistentVolumeReclaimPolicy") or "unknown"),
                storage_class=str(spec.get("storageClassName") or "unknown"),
            )
        )
    return tuple(sorted(candidates, key=lambda item: (item.namespace, item.name)))


def kubectl_json(context: str | None, resource: str) -> Mapping[str, Any]:
    command = ["kubectl"]
    if context:
        command.extend(("--context", context))
    command.extend(("get", resource, "--all-namespaces", "-o", "json"))
    completed = subprocess.run(command, capture_output=True, check=False)
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise PVCAuditError(f"kubectl {resource} inventory failed: {detail}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise PVCAuditError(f"kubectl {resource} returned invalid JSON") from error
    if not isinstance(payload, Mapping):
        raise PVCAuditError(f"kubectl {resource} returned a non-object")
    return payload


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--context")
    result.add_argument("--format", choices=("table", "json"), default="table")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        candidates = find_candidates(
            kubectl_json(arguments.context, "persistentvolumeclaims"),
            kubectl_json(arguments.context, "persistentvolumes"),
            kubectl_json(arguments.context, "pods"),
        )
        if arguments.format == "json":
            print(json.dumps([asdict(candidate) for candidate in candidates], indent=2))
        elif not candidates:
            print("No unowned, untracked and unreferenced PVC candidates found.")
        else:
            print("NAMESPACE\tNAME\tPHASE\tREQUESTED\tVOLUME\tRECLAIM\tSTORAGECLASS")
            for candidate in candidates:
                print(
                    "\t".join(
                        (
                            candidate.namespace,
                            candidate.name,
                            candidate.phase,
                            candidate.requested,
                            candidate.volume,
                            candidate.reclaim_policy,
                            candidate.storage_class,
                        )
                    )
                )
            print(
                "Candidates are evidence only; verify backups and obtain explicit deletion approval."
            )
        return 0
    except PVCAuditError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
