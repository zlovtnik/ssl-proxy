from __future__ import annotations

import platform
from dataclasses import dataclass, field
from datetime import datetime
from zoneinfo import ZoneInfo

from sslproxy_ops.config import Settings
from sslproxy_ops.health.signatures import FailureClassification, classify_text


class UpReadyError(RuntimeError):
    pass


@dataclass(slots=True)
class UpReadyContext:
    settings: Settings
    run_ts: str = field(
        default_factory=lambda: datetime.now(ZoneInfo("America/New_York")).strftime(
            "%Y-%m-%dT%H:%M:%S%z"
        )
    )
    host_arch: str = field(default_factory=platform.machine)
    last_failed_check: str = ""
    last_failure_text: str = ""
    last_failure: FailureClassification = field(
        default_factory=lambda: classify_text("")
    )
    auto_fixed_classes: set[str] = field(default_factory=set)
    peer_configs: dict[str, str] = field(default_factory=dict)
    peer_key_helper_ready: bool = False
    tidb_tls_cert_checksum: str = ""

    def classify(self, text: str) -> FailureClassification:
        self.last_failure_text = text
        self.last_failure = classify_text(text)
        return self.last_failure

    def fail(self, message: str) -> None:
        raise UpReadyError(message)


def step(step_id: str, message: str) -> None:
    print(f"[up-ready][{step_id}] {message}")


def warn(message: str) -> None:
    print(f"[up-ready][WARN] {message}", file=__import__("sys").stderr)


def desired_obfuscation_value(profile_mode: str) -> str:
    return "true" if profile_mode in {"iphone", "linux-shim", "mac"} else "false"
