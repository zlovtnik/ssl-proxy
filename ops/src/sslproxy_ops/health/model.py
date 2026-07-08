from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HealthResult:
    name: str
    ok: bool
    detail: str = ""
    duration: float = 0.0
    attempts: int = 1


HealthValue = HealthResult | bool | str | None
HealthFn = Callable[[], Awaitable[HealthValue] | HealthValue]


@dataclass(frozen=True, slots=True)
class HealthCheck:
    name: str
    fn: HealthFn
    retries: int = 1
    timeout: float | None = None
    retry_delay: float = 0.0
