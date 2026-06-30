from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True, slots=True)
class FailureSignature:
    name: str
    pattern: str
    cause: str
    fix: str
    retry: str


@dataclass(frozen=True, slots=True)
class FailureClassification:
    name: str
    cause: str
    fix: str
    retry: str
    matched: bool


def _signature_file() -> Path:
    return Path(str(resources.files("sslproxy_ops") / "signatures.yaml"))


def load_signatures(path: Path | None = None) -> list[FailureSignature]:
    raw = yaml.safe_load((path or _signature_file()).read_text()) or []
    signatures: list[FailureSignature] = []
    for item in raw:
        typed = dict[str, Any](item)
        signatures.append(
            FailureSignature(
                name=str(typed["name"]),
                pattern=str(typed["pattern"]),
                cause=str(typed["cause"]),
                fix=str(typed["fix"]),
                retry=str(typed["retry"]),
            )
        )
    return signatures


def classify_text(
    text: str,
    *,
    signatures: list[FailureSignature] | None = None,
    default_name: str = "unknown",
    default_cause: str = "Unclassified failure",
    default_fix: str = "Inspect diagnostics bundle",
    default_retry: str = "manual",
) -> FailureClassification:
    for signature in (signatures if signatures is not None else load_signatures()):
        if re.search(signature.pattern, text, flags=re.IGNORECASE | re.MULTILINE):
            return FailureClassification(
                name=signature.name,
                cause=signature.cause,
                fix=signature.fix,
                retry=signature.retry,
                matched=True,
            )
    return FailureClassification(
        name=default_name,
        cause=default_cause,
        fix=default_fix,
        retry=default_retry,
        matched=False,
    )
