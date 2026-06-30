from __future__ import annotations

import asyncio
import inspect
import time

from sslproxy_ops.health.model import HealthCheck, HealthResult


async def _call_check(check: HealthCheck) -> HealthResult:
    started = time.monotonic()
    attempts = max(1, check.retries)
    last_detail = ""

    for attempt in range(1, attempts + 1):
        try:
            value = check.fn()
            if inspect.isawaitable(value):
                if check.timeout is None:
                    value = await value
                else:
                    value = await asyncio.wait_for(value, timeout=check.timeout)

            duration = time.monotonic() - started
            if isinstance(value, HealthResult):
                return HealthResult(
                    name=value.name,
                    ok=value.ok,
                    detail=value.detail,
                    duration=duration,
                    attempts=attempt,
                )
            if isinstance(value, bool):
                return HealthResult(check.name, value, duration=duration, attempts=attempt)
            if isinstance(value, str):
                return HealthResult(check.name, True, value, duration=duration, attempts=attempt)
            return HealthResult(check.name, True, duration=duration, attempts=attempt)
        except Exception as exc:  # noqa: BLE001 - health checks report failures as data.
            last_detail = str(exc) or exc.__class__.__name__
            if attempt < attempts and check.retry_delay > 0:
                await asyncio.sleep(check.retry_delay)

    return HealthResult(
        check.name,
        False,
        last_detail,
        duration=time.monotonic() - started,
        attempts=attempts,
    )


async def run_checks(checks: list[HealthCheck]) -> list[HealthResult]:
    return list(await asyncio.gather(*(_call_check(check) for check in checks)))

