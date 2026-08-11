from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Sequence
from unittest import mock

import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from image_contract import FIRST_PARTY_SERVICES, ImageContract  # noqa: E402
from recover_stack import (  # noqa: E402
    CommandResult,
    REGISTRY_LOOKUP_WORKER_LIMIT,
    RecoveryReporter,
    RegistryTags,
    argo_applications_for,
    kustomize_build_command,
)
from platform_input_contract import (  # noqa: E402
    CONTRACT_RELATIVE_PATH,
    load_platform_input_contract,
)


PIN = "sha256:" + "a" * 64
STALE = "sha256:" + "b" * 64
HEAD = "1" * 40
PLATFORM_CONTRACT = load_platform_input_contract(REPOSITORY_ROOT)
PLATFORM_INPUTS = PLATFORM_CONTRACT.by_identity()


def write_contract(root: Path, environment: str) -> None:
    matrix = root / "cyber-stack" / "matrix" / environment
    repository_prefix = f"registry.test:5000/{environment}"
    for slice_name, services in (
        ("app-stack", FIRST_PARTY_SERVICES[:-1]),
        ("data-plane", FIRST_PARTY_SERVICES[-1:]),
    ):
        path = matrix / slice_name / "kustomization.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "apiVersion: kustomize.config.k8s.io/v1beta1\n"
            "kind: Kustomization\n"
            "images:\n"
            + "".join(
                f"  - name: {service}\n"
                f"    newName: {repository_prefix}/{service}\n"
                f"    digest: {PIN}\n"
                for service in services
            ),
            encoding="utf-8",
        )
    bootstrap = matrix / "bootstrap" / "kustomization.yaml"
    bootstrap.parent.mkdir(parents=True, exist_ok=True)
    bootstrap.write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: []\n",
        encoding="utf-8",
    )
    (matrix / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        f"namespace: {environment}-ssl-proxy\n"
        "images:\n"
        + "".join(
            f"  - name: {service}\n"
            f"    newName: {repository_prefix}/{service}\n"
            f"    digest: {PIN}\n"
            for service in FIRST_PARTY_SERVICES
        ),
        encoding="utf-8",
    )


def rendered_documents(environment: str) -> dict[str, str]:
    namespace = f"{environment}-ssl-proxy"
    prefix = f"registry.test:5000/{environment}"
    bootstrap = f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: platform-config
  namespace: {namespace}
"""
    app_stack = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: proxy
  namespace: {namespace}
spec:
  replicas: 1
  template:
    spec:
      initContainers:
        - name: prepare
          image: busybox:1.36
      containers:
        - name: proxy
          image: {prefix}/ssl-proxy@{PIN}
          env:
            - name: PLATFORM_ENDPOINT
              valueFrom:
                configMapKeyRef:
                  name: platform-endpoint
                  key: endpoint
      volumes:
        - name: credentials
          secret:
            secretName: platform-runtime
"""
    data_plane = f"""apiVersion: batch/v1
kind: Job
metadata:
  name: schema
  namespace: {namespace}
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: schema
          image: {prefix}/tidb-runtime-schema@{PIN}
"""
    return {
        "bootstrap": bootstrap,
        "app-stack": app_stack,
        "data-plane": data_plane,
        "aggregate": "---\n".join((bootstrap, app_stack, data_plane)),
    }


class FakeRunner:
    def __init__(
        self,
        environment: str,
        *,
        secret_present: bool = True,
        config_map_present: bool = True,
        healthy_argo: bool = True,
        drift: bool = False,
        argo_revision: str = HEAD,
        contexts: tuple[str, ...] = ("wiretrap-k3s",),
        current_context: str = "wiretrap-k3s",
        cluster_reachable: bool = True,
        cluster_error: str = "connection refused",
        missing_input_key: tuple[str, str, str] | None = None,
        event_message: str | None = None,
    ) -> None:
        self.environment = environment
        self.secret_present = secret_present
        self.config_map_present = config_map_present
        self.healthy_argo = healthy_argo
        self.drift = drift
        self.argo_revision = argo_revision
        self.contexts = contexts
        self.current_context = current_context
        self.cluster_reachable = cluster_reachable
        self.cluster_error = cluster_error
        self.missing_input_key = missing_input_key
        self.event_message = event_message
        self.commands: list[tuple[str, ...]] = []
        self.rendered = rendered_documents(environment)

    def __call__(self, command: Sequence[str], _root: Path) -> CommandResult:
        command = tuple(command)
        self.commands.append(command)
        if command[:3] == ("git", "rev-parse", "HEAD"):
            return CommandResult(0, HEAD + "\n", "")
        if command[:3] == ("git", "status", "--porcelain"):
            return CommandResult(0, "", "")
        if command[1:4] == ("config", "current-context"):
            if self.current_context:
                return CommandResult(0, self.current_context + "\n", "")
            return CommandResult(1, "", "current-context is not set")
        if command[1:3] == ("config", "get-contexts"):
            if command[3:5] == ("-o", "name"):
                output = "".join(f"{context}\n" for context in self.contexts)
                return CommandResult(0, output, "")
            requested = command[3]
            if requested in self.contexts:
                return CommandResult(0, requested + "\n", "")
            return CommandResult(1, "", f"error: context {requested} not found")
        if "version" in command and "--request-timeout=5s" in command:
            if self.cluster_reachable:
                return CommandResult(0, '{"serverVersion": {}}\n', "")
            return CommandResult(1, "", self.cluster_error)
        if command[0] == "fake-kustomize":
            path = Path(command[-1])
            label = path.name if path.name in ("bootstrap", "data-plane", "app-stack") else "aggregate"
            return CommandResult(0, self.rendered[label], "")
        if "applications.argoproj.io" in command:
            items = []
            for index, (name, path) in enumerate(
                argo_applications_for(self.environment).items()
            ):
                healthy = self.healthy_argo or index > 0
                items.append(
                    {
                        "apiVersion": "argoproj.io/v1alpha1",
                        "kind": "Application",
                        "metadata": {"name": name},
                        "spec": {"source": {"path": path}},
                        "status": {
                            "sync": {
                                "revision": self.argo_revision,
                                "status": "Synced" if healthy else "OutOfSync",
                            },
                            "health": {"status": "Healthy" if healthy else "Degraded"},
                        },
                    }
                )
            return CommandResult(0, json.dumps({"items": items}), "")
        if "secret" in command:
            if not self.secret_present:
                return CommandResult(0, "", "")
            name = command[command.index("secret") + 1]
            entry = PLATFORM_INPUTS.get(("Secret", name))
            if entry is None:
                return CommandResult(0, f"secret/{name}\n", "")
            keys = [
                key
                for key in entry.keys
                if self.missing_input_key != ("Secret", name, key)
            ]
            output = "\n".join(
                (f"__SSL_PROXY_PRESENT__\t{entry.secret_type}", *keys, "")
            )
            return CommandResult(0, output, "")
        if "configmap" in command:
            if not self.config_map_present:
                return CommandResult(0, "", "")
            name = command[command.index("configmap") + 1]
            entry = PLATFORM_INPUTS.get(("ConfigMap", name))
            if entry is None:
                return CommandResult(0, f"configmap/{name}\n", "")
            keys = [
                key
                for key in entry.keys
                if self.missing_input_key != ("ConfigMap", name, key)
            ]
            output = "\n".join(("__SSL_PROXY_PRESENT__", *keys, ""))
            return CommandResult(0, output, "")
        if "deployments.apps,statefulsets.apps,daemonsets.apps,jobs.batch" in command:
            live_digest = STALE if self.drift else PIN
            ready = 0 if self.drift else 1
            document = {
                "items": [
                    {
                        "apiVersion": "apps/v1",
                        "kind": "Deployment",
                        "metadata": {"name": "proxy"},
                        "spec": {
                            "replicas": 1,
                            "template": {
                                "spec": {
                                    "initContainers": [
                                        {"name": "prepare", "image": "busybox:1.36"}
                                    ],
                                    "containers": [
                                        {
                                            "name": "proxy",
                                            "image": f"registry.test:5000/{self.environment}/ssl-proxy@{live_digest}",
                                        }
                                    ],
                                }
                            },
                        },
                        "status": {
                            "readyReplicas": ready,
                            "availableReplicas": ready,
                            "updatedReplicas": ready,
                        },
                    }
                ]
            }
            return CommandResult(0, json.dumps(document), "")
        if command[-3:] == ("pods", "-o", "json"):
            live_digest = STALE if self.drift else PIN
            pod = {
                "metadata": {"name": "proxy-abc"},
                "spec": {
                    "initContainers": [{"name": "prepare", "image": "busybox:1.36"}],
                    "containers": [
                        {
                            "name": "proxy",
                            "image": f"registry.test:5000/{self.environment}/ssl-proxy@{live_digest}",
                        }
                    ],
                },
                "status": {
                    "phase": "Pending" if self.drift else "Running",
                    "conditions": [{"type": "Ready", "status": "False" if self.drift else "True"}],
                    "initContainerStatuses": [
                        {"name": "prepare", "imageID": "containerd://sha256:" + "c" * 64}
                    ],
                    "containerStatuses": [
                        {
                            "name": "proxy",
                            "imageID": f"docker-pullable://registry.test:5000/{self.environment}/ssl-proxy@{live_digest}",
                        }
                    ],
                },
            }
            return CommandResult(0, json.dumps({"items": [pod]}), "")
        if "events" in command:
            items = []
            if self.drift or self.event_message is not None:
                items.append(
                    {
                        "lastTimestamp": "2026-08-11T12:00:00Z",
                        "reason": "Failed",
                        "message": self.event_message or "image pull failed",
                        "involvedObject": {"kind": "Pod", "name": "proxy-abc"},
                    }
                )
            return CommandResult(0, json.dumps({"items": items}), "")
        raise AssertionError(f"unexpected command: {command}")


def registry_ok(_contract: object, _plain_http: bool) -> RegistryTags:
    return RegistryTags("KNOWN", ("latest", "abc1234"))


class RecoverStackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        write_contract(self.root, "prod")
        write_contract(self.root, "dev")
        target = self.root / CONTRACT_RELATIVE_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPOSITORY_ROOT / CONTRACT_RELATIVE_PATH, target)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def reporter(self, environment: str, runner: FakeRunner) -> RecoveryReporter:
        return RecoveryReporter(
            self.root,
            environment,
            "wiretrap-k3s",
            "fake-kustomize",
            True,
            runner=runner,
            registry_resolver=registry_ok,
        )

    def test_healthy_aligned_stack_returns_zero(self) -> None:
        runner = FakeRunner("prod")

        returncode, report = self.reporter("prod", runner).run()

        self.assertEqual(0, returncode, report)
        self.assertIn("Kubernetes context: wiretrap-k3s", report)
        self.assertIn("ssl-proxy-prod-app-stack", report)
        self.assertIn("ConfigMap/ssl-proxy-prod-tidb-endpoint: PRESENT", report)
        self.assertIn("Secret/minio-credentials: PRESENT", report)
        self.assertIn("values suppressed", report)
        self.assertIn("regular/proxy", report)
        self.assertIn("init/prepare", report)
        self.assertIn("imageID=docker-pullable://", report)
        self.assertTrue(report.rstrip().endswith("RESULT: HEALTHY"))
        render_commands = [command for command in runner.commands if command[0] == "fake-kustomize"]
        self.assertEqual(4, len(render_commands))

    def test_empty_context_uses_current_context(self) -> None:
        runner = FakeRunner("prod", current_context="active-cluster", contexts=("active-cluster",))
        reporter = RecoveryReporter(
            self.root,
            "prod",
            "",
            "fake-kustomize",
            True,
            runner=runner,
            registry_resolver=registry_ok,
        )

        returncode, report = reporter.run()

        self.assertEqual(0, returncode, report)
        self.assertIn(
            "Kubernetes context: active-cluster (kubectl current-context)", report
        )

    def test_configured_kubectl_is_used_for_every_cluster_query(self) -> None:
        runner = FakeRunner("prod")
        reporter = RecoveryReporter(
            self.root,
            "prod",
            "wiretrap-k3s",
            "fake-kustomize",
            True,
            kubectl="/opt/platform/kubectl",
            runner=runner,
            registry_resolver=registry_ok,
        )

        returncode, report = reporter.run()

        self.assertEqual(0, returncode, report)
        cluster_commands = [
            command
            for command in runner.commands
            if command[0] not in ("git", "fake-kustomize")
        ]
        self.assertTrue(cluster_commands)
        self.assertTrue(
            all(command[0] == "/opt/platform/kubectl" for command in cluster_commands)
        )
        makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn('--kubectl "$(KUBECTL)"', makefile)

    def test_unknown_explicit_context_fails_once_without_live_queries(self) -> None:
        runner = FakeRunner("prod", contexts=("active-cluster",))
        reporter = RecoveryReporter(
            self.root,
            "prod",
            "missing-cluster",
            "fake-kustomize",
            True,
            runner=runner,
            registry_resolver=registry_ok,
        )

        returncode, report = reporter.run()

        self.assertEqual(1, returncode)
        self.assertIn(
            'Kubernetes context "missing-cluster" is not configured; '
            "available: active-cluster",
            report,
        )
        self.assertEqual(1, report.count("not configured"))
        self.assertFalse(any("applications.argoproj.io" in command for command in runner.commands))
        self.assertFalse(any("secret" in command for command in runner.commands))
        self.assertFalse(any("configmap" in command for command in runner.commands))

    def test_unreachable_cluster_fails_once_without_live_queries(self) -> None:
        runner = FakeRunner("prod", cluster_reachable=False)

        returncode, report = self.reporter("prod", runner).run()

        self.assertEqual(1, returncode)
        self.assertIn("Kubernetes API is unreachable", report)
        self.assertEqual(1, report.count("connection refused"))
        self.assertFalse(any("applications.argoproj.io" in command for command in runner.commands))

    def test_render_returns_documents_and_git_head_separately(self) -> None:
        reporter = self.reporter("prod", FakeRunner("prod"))

        rendered, git_head = reporter._render()

        self.assertEqual(HEAD, git_head)
        self.assertEqual(
            {"bootstrap", "data-plane", "app-stack", "aggregate"}, set(rendered)
        )

    def test_kubectl_uses_its_kustomize_subcommand(self) -> None:
        path = self.root / "cyber-stack" / "matrix" / "prod"

        self.assertEqual(
            (
                "kubectl",
                "kustomize",
                str(path),
                "--load-restrictor",
                "LoadRestrictionsNone",
            ),
            kustomize_build_command("kubectl", path),
        )

    def test_argo_mapping_is_derived_from_environment(self) -> None:
        self.assertEqual(
            "cyber-stack/matrix/dev/app-stack",
            argo_applications_for("dev")["ssl-proxy-dev-app-stack"],
        )
        self.assertEqual(
            "cyber-stack/matrix/prod/data-plane",
            argo_applications_for("prod")["ssl-proxy-prod-data-plane"],
        )

    def test_argo_revision_must_exactly_match_full_local_head(self) -> None:
        short_runner = FakeRunner("prod", argo_revision=HEAD[:6])
        abbreviated_runner = FakeRunner("prod", argo_revision=HEAD[:7])

        short_returncode, short_report = self.reporter("prod", short_runner).run()
        abbreviated_returncode, abbreviated_report = self.reporter(
            "prod", abbreviated_runner
        ).run()

        self.assertEqual(1, short_returncode, short_report)
        self.assertEqual(1, abbreviated_returncode, abbreviated_report)
        self.assertIn(f"revision={HEAD[:6]} local=DIFF", short_report)
        self.assertIn(f"revision={HEAD[:7]} local=DIFF", abbreviated_report)
        self.assertIn("Argo CD Application revision mismatch", short_report)
        self.assertIn("Argo CD Application revision mismatch", abbreviated_report)

    def test_warning_events_and_command_errors_are_sanitized(self) -> None:
        event_runner = FakeRunner(
            "prod",
            event_message=(
                "pull https://alice:url-password@example.test/image "
                "Authorization: Bearer bearer-token DB_PASSWORD='hunter two' "
                "dsn=service:dsn-password@tcp(tidb:4000)/db "
                '{"password":"json-password","authorization":"Bearer json-token"}'
            ),
        )

        returncode, report = self.reporter("prod", event_runner).run()

        self.assertEqual(0, returncode, report)
        for value in (
            "url-password",
            "bearer-token",
            "hunter two",
            "dsn-password",
            "json-password",
            "json-token",
        ):
            self.assertNotIn(value, report)
        self.assertIn("[REDACTED]", report)

        error_runner = FakeRunner(
            "prod",
            cluster_reachable=False,
            cluster_error="request failed token=error-token password=error-password",
        )
        error_returncode, error_report = self.reporter("prod", error_runner).run()

        self.assertEqual(1, error_returncode)
        self.assertNotIn("error-token", error_report)
        self.assertNotIn("error-password", error_report)

    def test_full_report_precedes_nonzero_for_all_blocker_classes(self) -> None:
        runner = FakeRunner(
            "prod",
            secret_present=False,
            config_map_present=False,
            healthy_argo=False,
            drift=True,
        )

        returncode, report = self.reporter("prod", runner).run()

        self.assertEqual(1, returncode)
        self.assertIn("ConfigMap/ssl-proxy-prod-tidb-endpoint: MISSING", report)
        self.assertIn("Secret/minio-credentials: MISSING", report)
        self.assertIn("sync=OutOfSync health=Degraded", report)
        self.assertIn("image Deployment/proxy proxy: DRIFT", report)
        self.assertIn("Pod/proxy-abc: UNHEALTHY", report)
        self.assertIn("RECENT WARNING EVENTS", report)
        self.assertIn("image pull failed", report)
        self.assertLess(report.index("RECENT WARNING EVENTS"), report.index("BLOCKER SUMMARY"))
        self.assertTrue(report.rstrip().endswith("blockers)"))

    def test_missing_platform_key_is_reported_without_values(self) -> None:
        runner = FakeRunner(
            "prod",
            missing_input_key=("Secret", "proxy-admin-key", "api-key"),
        )

        returncode, report = self.reporter("prod", runner).run()

        self.assertEqual(1, returncode)
        self.assertIn("Secret/proxy-admin-key: PRESENT", report)
        self.assertIn("missing-keys=api-key", report)
        self.assertNotIn("stringData", report)
        self.assertNotIn(".data", report)

    def test_dev_skips_argo_queries(self) -> None:
        runner = FakeRunner("dev")

        returncode, report = self.reporter("dev", runner).run()

        self.assertEqual(0, returncode, report)
        self.assertIn("SKIPPED: dev Applications are prohibited", report)
        self.assertFalse(
            any("applications.argoproj.io" in command for command in runner.commands)
        )

    def test_unreachable_registry_is_unknown_and_does_not_fail_health(self) -> None:
        runner = FakeRunner("prod")
        reporter = RecoveryReporter(
            self.root,
            "prod",
            "wiretrap-k3s",
            "fake-kustomize",
            True,
            runner=runner,
            registry_resolver=lambda _contract, _plain_http: RegistryTags(
                "UNKNOWN", detail="connection refused"
            ),
        )

        returncode, report = reporter.run()

        self.assertEqual(0, returncode, report)
        self.assertIn("tags=UNKNOWN (connection refused)", report)

    def test_registry_lookup_worker_count_is_capped(self) -> None:
        reporter = self.reporter("prod", FakeRunner("prod"))
        contracts = tuple(
            ImageContract(f"service-{index}", "app-stack", f"registry.test/s{index}", PIN)
            for index in range(REGISTRY_LOOKUP_WORKER_LIMIT + 3)
        )

        with mock.patch(
            "recover_stack.concurrent.futures.ThreadPoolExecutor",
            wraps=ThreadPoolExecutor,
        ) as executor:
            reporter._report_registry(contracts)

        executor.assert_called_once_with(max_workers=REGISTRY_LOOKUP_WORKER_LIMIT)


if __name__ == "__main__":
    unittest.main()
