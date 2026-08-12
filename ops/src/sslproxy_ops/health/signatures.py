from __future__ import annotations

import re
import sre_constants
import sre_parse
import warnings
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

warnings.filterwarnings(
    "ignore",
    message=".*is deprecated",
    category=DeprecationWarning,
    module=__name__,
)

MAX_TEXT_LENGTH = 1_000_000


@dataclass(frozen=True, slots=True)
class FailureSignature:
    name: str
    pattern: str
    cause: str
    fix: str
    retry: str
    compiled: re.Pattern[str] = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class FailureClassification:
    name: str
    cause: str
    fix: str
    retry: str
    matched: bool


_REPEAT_OPS = frozenset({sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, sre_constants.REPEAT})


def _walk_repeat(subpattern: sre_parse.SubPattern, in_repeat: bool) -> bool:
    for op, av in subpattern:
        if op in _REPEAT_OPS:
            if in_repeat:
                return True
            if _walk_repeat(av[2], in_repeat=True):
                return True
        elif op == sre_constants.SUBPATTERN:
            if _walk_repeat(av[3], in_repeat):
                return True
        elif op == sre_constants.BRANCH:
            for branch in av[1]:
                if _walk_repeat(branch, in_repeat):
                    return True
    return False


def _validate_pattern(pattern: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        parsed = sre_parse.parse(pattern)
    if _walk_repeat(parsed, in_repeat=False):
        raise ValueError(
            f"Pattern contains nested quantifiers (ReDoS risk): {pattern!r}"
        )


def _signature_file() -> Path:
    return Path(str(resources.files("sslproxy_ops") / "signatures.yaml"))


def load_signatures(path: Path | None = None) -> list[FailureSignature]:
    raw = yaml.safe_load((path or _signature_file()).read_text()) or []
    signatures: list[FailureSignature] = []
    for item in raw:
        typed = dict[str, Any](item)
        pattern = str(typed["pattern"])
        _validate_pattern(pattern)
        compiled = re.compile(pattern, flags=re.IGNORECASE | re.MULTILINE)
        signatures.append(
            FailureSignature(
                name=str(typed["name"]),
                pattern=pattern,
                cause=str(typed["cause"]),
                fix=str(typed["fix"]),
                retry=str(typed["retry"]),
                compiled=compiled,
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
    bounded = text[:MAX_TEXT_LENGTH]
    for signature in (signatures if signatures is not None else load_signatures()):
        if signature.compiled.search(bounded):
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
