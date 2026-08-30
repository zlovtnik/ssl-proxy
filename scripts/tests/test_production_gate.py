from __future__ import annotations

import json
import sys
import threading
import time
import unittest
from pathlib import Path
from typing import Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from production_gate import (  # noqa: E402
    APPLICATIONS,
    CommandResult,
    KUBECTL_REQUEST_TIMEOUT,
    RBAC_MAX_WORKERS,
    ProductionGate,
)


REVISION = "a" * 40
STALE_REVISION = "b" * 40


def application(
    name: str,
    *,
    revision: str = REVISION,
    sync: str = "Synced",
    health: str = "Healthy",
    operation: str = "Succeeded",
    message: str = "",
) -> dict[str, object]:
    status: dict[str, object] = {
        "sync": {"revision": revision, "status": sync},
        "health": {"status": health},
        "operationState": {"phase": operation, "message": message},
    }
    return {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {"name": name},
        "status": status,
    }


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeRunner:
    def __init__(
        self,
        rounds: Sequence[Mapping[str, dict[str, object] | CommandResult]],
        *,
        rbac: bool = False,
        unexpectedly_allowed: set[tuple[str, str, str]] | None = None,
        clock: FakeClock | None = None,
        query_seconds: float = 0.0,
    ) -> None:
        self.rounds = rounds
        self.rbac = rbac
        self.unexpectedly_allowed = unexpectedly_allowed or set()
        self.clock = clock
        self.query_seconds = query_seconds
        self.application_calls = 0
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str]) -> CommandResult:
        command = tuple(command)
        self.commands.append(command)
        if "auth" in command and "can-i" in command:
            if not self.rbac:
                raise AssertionError("unexpected RBAC check")
            verb = command[command.index("can-i") + 1]
            resource = command[command.index("can-i") + 2]
            scope = (
                "*"
                if "--all-namespaces" in command
                else command[command.index("--namespace") + 1]
            )
            allowed = verb == "get" and resource.startswith(
                "applications.argoproj.io/ssl-proxy-prod-"
            )
            if (verb, resource, scope) in self.unexpectedly_allowed:
                allowed = True
            return CommandResult(0 if allowed else 1, "yes\n" if allowed else "no\n", "")
        if self.clock is not None:
            self.clock.advance(self.query_seconds)
        name = command[command.index("applications.argoproj.io") + 1]
        round_index = min(self.application_calls // len(APPLICATIONS), len(self.rounds) - 1)
        self.application_calls += 1
        value = self.rounds[round_index][name]
        if isinstance(value, CommandResult):
            return value
        return CommandResult(0, json.dumps(value), "")


def healthy_round() -> dict[str, dict[str, object]]:
    return {name: application(name) for name in APPLICATIONS}


def run_gate(
    rounds: Sequence[Mapping[str, dict[str, object] | CommandResult]],
    *,
    timeout: float = 0,
    verify_rbac: bool = False,
    unexpectedly_allowed: set[tuple[str, str, str]] | None = None,
    query_seconds: float = 0.0,
    poll_interval: float = 1.0,
) -> tuple[int, str, FakeRunner, FakeClock]:
    clock = FakeClock()
    runner = FakeRunner(
        rounds,
        rbac=verify_rbac,
        unexpectedly_allowed=unexpectedly_allowed,
        clock=clock,
        query_seconds=query_seconds,
    )
    gate = ProductionGate(
        REVISION,
        timeout_seconds=timeout,
        poll_interval_seconds=poll_interval,
        verify_rbac=verify_rbac,
        runner=runner,
        clock=clock,
        sleeper=clock.sleep,
    )
    returncode, report = gate.run()
    return returncode, report, runner, clock


class ProductionGateTest(unittest.TestCase):
    def test_eventual_success_requires_all_three_applications(self) -> None:
        stale = {
            name: application(name, revision=STALE_REVISION) for name in APPLICATIONS
        }

        returncode, report, runner, _ = run_gate((stale, healthy_round()), timeout=5)

        self.assertEqual(0, returncode, report)
        self.assertEqual(6, runner.application_calls)
        self.assertIn("Attempt 2", report)
        self.assertIn("RESULT: PASSED", report)

    def test_stale_revision_fails_on_timeout(self) -> None:
        stale = {
            name: application(name, revision=STALE_REVISION) for name in APPLICATIONS
        }

        returncode, report, _, _ = run_gate((stale,))

        self.assertEqual(1, returncode)
        self.assertIn(f"revision={STALE_REVISION}", report)
        self.assertIn("timed out waiting for exact revision", report)

    def test_missing_application_fails(self) -> None:
        state: dict[str, dict[str, object] | CommandResult] = healthy_round()
        state[APPLICATIONS[1]] = CommandResult(
            1,
            "",
            f'Error from server (NotFound): applications.argoproj.io "{APPLICATIONS[1]}" not found',
        )

        returncode, report, _, _ = run_gate((state,))

        self.assertEqual(1, returncode)
        self.assertIn(f"{APPLICATIONS[1]}: MISSING", report)

    def test_out_of_sync_application_fails(self) -> None:
        state = healthy_round()
        state[APPLICATIONS[0]] = application(APPLICATIONS[0], sync="OutOfSync")

        returncode, report, _, _ = run_gate((state,))

        self.assertEqual(1, returncode)
        self.assertIn("sync=OutOfSync", report)

    def test_degraded_and_progressing_applications_fail(self) -> None:
        for health in ("Degraded", "Progressing"):
            with self.subTest(health=health):
                state = healthy_round()
                state[APPLICATIONS[2]] = application(
                    APPLICATIONS[2], health=health, operation="Running"
                )

                returncode, report, _, _ = run_gate((state,))

                self.assertEqual(1, returncode)
                self.assertIn(f"health={health}", report)
                self.assertIn("operation=Running", report)

    def test_unchanged_state_times_out_without_unbounded_diagnostics(self) -> None:
        state = healthy_round()
        state[APPLICATIONS[0]] = application(APPLICATIONS[0], health="Progressing")

        returncode, report, runner, _ = run_gate((state,), timeout=3)

        self.assertEqual(1, returncode)
        self.assertEqual(12, runner.application_calls)
        self.assertEqual(1, report.count("Attempt "))
        self.assertIn("RESULT: FAILED", report)

    def test_operation_diagnostics_are_sanitized(self) -> None:
        state = healthy_round()
        state[APPLICATIONS[0]] = application(
            APPLICATIONS[0],
            health="Degraded",
            message=(
                "password=hunter2 token=topsecret "
                "https://alice:credential@example.test/path "
                '"authorization":"Bearer gate-token"'
            ),
        )

        returncode, report, _, _ = run_gate((state,))

        self.assertEqual(1, returncode)
        self.assertNotIn("hunter2", report)
        self.assertNotIn("topsecret", report)
        self.assertNotIn("credential", report)
        self.assertNotIn("gate-token", report)
        self.assertIn("[REDACTED]", report)

    def test_rbac_preflight_allows_only_gate_reads(self) -> None:
        returncode, report, runner, _ = run_gate(
            (healthy_round(),), verify_rbac=True
        )

        self.assertEqual(0, returncode, report)
        self.assertIn("RBAC preflight", report)
        self.assertIn("Secret reads", report)
        rbac_checks = [command for command in runner.commands if "can-i" in command]
        self.assertEqual(72, len(rbac_checks))
        self.assertTrue(
            all(
                f"--request-timeout={KUBECTL_REQUEST_TIMEOUT}" in command
                for command in rbac_checks
            )
        )
        secret_checks = [
            command
            for command in runner.commands
            if "can-i" in command
            and command[command.index("can-i") + 2] == "secrets"
            and command[command.index("can-i") + 1] in ("get", "list", "watch")
        ]
        self.assertEqual(9, len(secret_checks))
        for verb in ("get", "list", "watch"):
            self.assertEqual(
                3,
                sum(
                    command[command.index("can-i") + 1] == verb
                    for command in secret_checks
                ),
            )
        self.assertTrue(any("--all-namespaces" in command for command in secret_checks))
        self.assertTrue(
            any(("--namespace", "argocd") == command[-3:-1] for command in secret_checks)
        )
        self.assertTrue(
            any(
                ("--namespace", "prod-ssl-proxy") == command[-3:-1]
                for command in secret_checks
            )
        )
        mutation_checks = [
            command
            for command in runner.commands
            if "can-i" in command
            and command[command.index("can-i") + 1 : command.index("can-i") + 3]
            == ("patch", "deployments.apps")
        ]
        self.assertEqual(3, len(mutation_checks))
        self.assertTrue(
            any("--all-namespaces" in command for command in mutation_checks)
        )
        self.assertTrue(
            any(("--namespace", "argocd") == command[-3:-1] for command in mutation_checks)
        )
        self.assertTrue(
            any(
                ("--namespace", "prod-ssl-proxy") == command[-3:-1]
                for command in mutation_checks
            )
        )

    def test_rbac_preflight_rejects_namespace_local_secret_access(self) -> None:
        returncode, report, _, _ = run_gate(
            (healthy_round(),),
            verify_rbac=True,
            unexpectedly_allowed={("get", "secrets", "prod-ssl-proxy")},
        )

        self.assertEqual(1, returncode)
        self.assertIn(
            "Secret get isolation failed in namespace prod-ssl-proxy", report
        )
        self.assertIn("RESULT: FAILED (RBAC preflight)", report)

    def test_rbac_failures_are_reported_in_declaration_order(self) -> None:
        returncode, report, _, _ = run_gate(
            (healthy_round(),),
            verify_rbac=True,
            unexpectedly_allowed={
                ("delete", "rolebindings.rbac.authorization.k8s.io", "prod-ssl-proxy"),
                ("get", "secrets", "*"),
            },
        )

        self.assertEqual(1, returncode)
        first = report.index("Secret get isolation failed in all namespaces")
        last = report.index(
            "mutation isolation failed in namespace prod-ssl-proxy for delete rolebindings"
        )
        self.assertLess(first, last)

    def test_rbac_preflight_uses_bounded_concurrency(self) -> None:
        class TrackingRunner:
            def __init__(self) -> None:
                self.active = 0
                self.maximum = 0
                self.lock = threading.Lock()

            def __call__(self, command: Sequence[str]) -> CommandResult:
                if "can-i" in command:
                    with self.lock:
                        self.active += 1
                        self.maximum = max(self.maximum, self.active)
                    time.sleep(0.005)
                    verb = command[command.index("can-i") + 1]
                    resource = command[command.index("can-i") + 2]
                    allowed = verb == "get" and resource.startswith(
                        "applications.argoproj.io/ssl-proxy-prod-"
                    )
                    with self.lock:
                        self.active -= 1
                    return CommandResult(0, "yes\n" if allowed else "no\n", "")
                name = command[command.index("applications.argoproj.io") + 1]
                return CommandResult(0, json.dumps(application(name)), "")

        runner = TrackingRunner()
        gate = ProductionGate(REVISION, timeout_seconds=0, runner=runner)

        returncode, report = gate.run()

        self.assertEqual(0, returncode, report)
        self.assertGreater(runner.maximum, 1)
        self.assertLessEqual(runner.maximum, RBAC_MAX_WORKERS)

    def test_polling_subtracts_query_time_from_next_sleep(self) -> None:
        stale = {
            name: application(name, revision=STALE_REVISION) for name in APPLICATIONS
        }

        returncode, _, _, clock = run_gate(
            (stale,), timeout=1.5, query_seconds=0.2, poll_interval=1.0
        )

        self.assertEqual(1, returncode)
        self.assertAlmostEqual(0.4, clock.sleeps[0])

    def test_over_interval_queries_trigger_next_attempt_immediately(self) -> None:
        stale = {
            name: application(name, revision=STALE_REVISION) for name in APPLICATIONS
        }

        returncode, _, runner, clock = run_gate(
            (stale,), timeout=2.5, query_seconds=0.4, poll_interval=1.0
        )

        self.assertEqual(1, returncode)
        self.assertEqual([0.0, 0.0], clock.sleeps)
        self.assertEqual(9, runner.application_calls)

    def test_query_time_honors_deadline_without_extra_sleep(self) -> None:
        stale = {
            name: application(name, revision=STALE_REVISION) for name in APPLICATIONS
        }

        returncode, _, runner, clock = run_gate(
            (stale,), timeout=1.0, query_seconds=0.4, poll_interval=1.0
        )

        self.assertEqual(1, returncode)
        self.assertEqual([], clock.sleeps)
        self.assertEqual(3, runner.application_calls)


if __name__ == "__main__":
    unittest.main()
