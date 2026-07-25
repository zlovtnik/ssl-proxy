"""Tests for stackctl readiness gate checking (gates.py)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from gates import (
    _discover_resource,
    _resolve_gate_resource,
    _wait_condition,
    parse_timeout_seconds,
    wait_for_gate,
    wait_for_gates,
)
from shell import ShellError

# ---------------------------------------------------------------------------
# Gate model helper (avoid circular import from stackctl)
# ---------------------------------------------------------------------------


def _make_gate(
    resource: str | None = None,
    discover: dict | None = None,
    condition: str | None = None,
):
    """Create a minimal Gate-like object for testing."""
    from types import SimpleNamespace

    return SimpleNamespace(resource=resource, discover=discover, condition=condition)


class TestParseTimeoutSeconds:
    """Test Helm-style timeout parsing."""

    def test_minutes(self):
        assert parse_timeout_seconds("15m") == "900s"

    def test_seconds(self):
        assert parse_timeout_seconds("300s") == "300s"

    def test_hours_and_minutes(self):
        assert parse_timeout_seconds("1h30m") == "5400s"

    def test_hours_only(self):
        assert parse_timeout_seconds("2h") == "7200s"

    def test_default_timeout(self):
        assert parse_timeout_seconds("10m") == "600s"

    def test_empty_string_returns_default(self):
        assert parse_timeout_seconds("") == "600s"

    def test_invalid_string_returns_default(self):
        assert parse_timeout_seconds("not-a-timeout") == "600s"

    def test_mixed_whitespace(self):
        assert parse_timeout_seconds(" 1h 30m ") == "5400s"

    def test_large_timeout(self):
        assert parse_timeout_seconds("24h") == "86400s"


class TestWaitCondition:
    """Test condition resolution for different gate types."""

    def test_condition_complete(self):
        gate = _make_gate(condition="complete")
        assert _wait_condition(gate) == "condition=complete"

    def test_statefulset_default(self):
        gate = _make_gate(resource="statefulset/ssl-proxy-tidb")
        result = _wait_condition(gate)
        assert "jsonpath" in result
        assert "readyReplicas" in result
        assert "replicas" in result

    def test_daemonset_default(self):
        gate = _make_gate(resource="daemonset/atheros-sensor")
        result = _wait_condition(gate)
        assert "jsonpath" in result
        assert "numberReady" in result
        assert "desiredNumberScheduled" in result

    def test_deployment_default(self):
        gate = _make_gate(resource="deployment/my-app")
        assert _wait_condition(gate) == "condition=Available"

    def test_job_with_condition_complete(self):
        gate = _make_gate(discover={"kind": "Job"}, condition="complete")
        assert _wait_condition(gate) == "condition=complete"

    def test_unknown_resource_defaults_to_available(self):
        gate = _make_gate(resource="custom/my-resource")
        assert _wait_condition(gate) == "condition=Available"

    def test_discover_without_resource_uses_default(self):
        gate = _make_gate(discover={"kind": "Deployment"})
        assert _wait_condition(gate) == "condition=Available"

    def test_discover_job_without_condition_defaults_available(self):
        gate = _make_gate(discover={"kind": "Job"})
        assert _wait_condition(gate) == "condition=Available"


class TestResolveGateResource:
    """Test resource resolution from gate config."""

    def test_resource_directly_returned(self):
        gate = _make_gate(resource="statefulset/ssl-proxy-tidb")
        result = _resolve_gate_resource(gate, "ssl-proxy-tidb", "default", None, None)
        assert result == "statefulset/ssl-proxy-tidb"

    def test_discover_calls_kubectl(self):
        gate = _make_gate(discover={"kind": "Deployment"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="deployment.apps/ssl-proxy-redis\n",
                stderr="",
            )
            result = _resolve_gate_resource(
                gate, "ssl-proxy-redis", "default", None, None
            )
            assert result == "deployment.apps/ssl-proxy-redis"
            mock_kubectl.assert_called_once()
            # Verify label selector uses release name
            args = mock_kubectl.call_args[0]
            assert "-l" in args
            label_idx = args.index("-l")
            assert "app.kubernetes.io/name=ssl-proxy-redis" in args[label_idx + 1]

    def test_discover_no_match_returns_none(self):
        gate = _make_gate(discover={"kind": "Deployment"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="",
                stderr="",
            )
            result = _resolve_gate_resource(
                gate, "ssl-proxy-redis", "default", None, None
            )
            assert result is None

    def test_discover_kubectl_error_returns_none(self):
        gate = _make_gate(discover={"kind": "Deployment"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="Error from server",
            )
            result = _resolve_gate_resource(
                gate, "ssl-proxy-redis", "default", None, None
            )
            assert result is None

    def test_neither_resource_nor_discover_returns_none(self):
        gate = _make_gate()
        result = _resolve_gate_resource(gate, "release", "default", None, None)
        assert result is None

    def test_discover_rejects_multiple_matches(self):
        gate = _make_gate(discover={"kind": "Pod"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="pod/pod-1\npod/pod-2\npod/pod-3\n",
                stderr="",
            )
            with pytest.raises(RuntimeError, match="expected exactly one"):
                _resolve_gate_resource(gate, "release", "default", None, None)


class TestDiscoverResource:
    """Test the _discover_resource helper directly."""

    def test_successful_discovery(self):
        gate = _make_gate(discover={"kind": "StatefulSet"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="statefulset.apps/ssl-proxy-tidb\n",
                stderr="",
            )
            result = _discover_resource(
                gate, "ssl-proxy-tidb", "default", None, None
            )
            assert result == "statefulset.apps/ssl-proxy-tidb"

    def test_kubectl_error_returns_none(self):
        gate = _make_gate(discover={"kind": "StatefulSet"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="Error",
            )
            result = _discover_resource(
                gate, "ssl-proxy-tidb", "default", None, None
            )
            assert result is None

    def test_empty_output_returns_none(self):
        gate = _make_gate(discover={"kind": "StatefulSet"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="",
                stderr="",
            )
            result = _discover_resource(
                gate, "ssl-proxy-tidb", "default", None, None
            )
            assert result is None

    def test_context_and_kubeconfig_propagated(self):
        gate = _make_gate(discover={"kind": "Deployment"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="deployment/my-app\n",
                stderr="",
            )
            _discover_resource(
                gate, "my-app", "prod", context="prod-cluster", kubeconfig=None
            )
            assert mock_kubectl.call_args[1]["context"] == "prod-cluster"


class TestWaitForGate:
    """Test single gate waiting."""

    def test_successful_wait_with_resource(self):
        gate = _make_gate(resource="deployment/my-app")
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="deployment.apps/my-app condition met\n",
                stderr="",
            )
            wait_for_gate(gate, "my-app", "default", timeout="5m")
            mock_kubectl.assert_called_once()
            args = mock_kubectl.call_args[0]
            assert "wait" in args
            assert "deployment/my-app" in args
            assert "--for=condition=Available" in " ".join(args)
            assert "--timeout=300s" in " ".join(args)

    def test_successful_wait_with_discover(self):
        gate = _make_gate(discover={"kind": "StatefulSet"})
        with patch("gates.kubectl") as mock_kubectl:
            # First call is discover, second is wait
            mock_kubectl.side_effect = [
                subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout="statefulset.apps/ssl-proxy-tidb\n", stderr="",
                ),
                subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout="statefulset.apps/ssl-proxy-tidb condition met\n", stderr="",
                ),
            ]
            wait_for_gate(gate, "ssl-proxy-tidb", "default", timeout="10m")
            assert mock_kubectl.call_count == 2

    def test_resource_not_found_raises_runtime_error(self):
        gate = _make_gate(discover={"kind": "Deployment"})
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr="",
            )
            with pytest.raises(RuntimeError) as exc_info:
                wait_for_gate(gate, "my-app", "default")
            assert "could not discover resource" in str(exc_info.value)

    def test_wait_timeout_raises_shell_error(self):
        gate = _make_gate(resource="deployment/my-app")
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.side_effect = ShellError(
                command=("kubectl", "wait", "deployment/my-app", "--for=condition=Available"),
                returncode=1,
                stdout="",
                stderr="timed out waiting for the condition",
            )
            with pytest.raises(ShellError) as exc_info:
                wait_for_gate(gate, "my-app", "default", timeout="5s")
            assert "timed out" in str(exc_info.value)

    def test_default_timeout_used_when_none_provided(self):
        gate = _make_gate(resource="deployment/my-app")
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="condition met\n", stderr="",
            )
            wait_for_gate(gate, "my-app", "default", timeout=None)
            args_str = " ".join(mock_kubectl.call_args[0])
            assert "--timeout=600s" in args_str

    def test_statefulset_jsonpath_condition(self):
        gate = _make_gate(resource="statefulset/ssl-proxy-tidb")
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="condition met\n", stderr="",
            )
            wait_for_gate(gate, "ssl-proxy-tidb", "default")
            args_str = " ".join(mock_kubectl.call_args[0])
            assert "jsonpath" in args_str
            assert "readyReplicas" in args_str

    def test_job_complete_condition(self):
        gate = _make_gate(discover={"kind": "Job"}, condition="complete")
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.side_effect = [
                subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout="job.batch/ssl-proxy-tidb-schema\n", stderr="",
                ),
                subprocess.CompletedProcess(
                    args=[], returncode=0,
                    stdout="condition met\n", stderr="",
                ),
            ]
            wait_for_gate(gate, "ssl-proxy-tidb-schema", "default")
            args_str = " ".join(mock_kubectl.call_args[0])
            assert "condition=complete" in args_str


class TestWaitForGates:
    """Test waiting for multiple gates sequentially."""

    def test_all_gates_succeed(self):
        gates = [
            _make_gate(resource="deployment/app-a"),
            _make_gate(resource="deployment/app-b"),
        ]
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="condition met\n", stderr="",
            )
            wait_for_gates(gates, "release", "default")
            assert mock_kubectl.call_count == 2

    def test_first_gate_failure_stops_iteration(self):
        gates = [
            _make_gate(resource="deployment/app-a"),
            _make_gate(resource="deployment/app-b"),
        ]
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.side_effect = [
                ShellError(
                    command=("kubectl", "wait", "deployment/app-a"),
                    returncode=1,
                    stdout="",
                    stderr="timed out",
                ),
            ]
            with pytest.raises(ShellError):
                wait_for_gates(gates, "release", "default")
            assert mock_kubectl.call_count == 1

    def test_empty_gates_list(self):
        wait_for_gates([], "release", "default")
        # No kubectl calls should be made

    def test_context_propagated_to_all_gates(self):
        gates = [
            _make_gate(resource="deployment/app-a"),
            _make_gate(resource="deployment/app-b"),
        ]
        with patch("gates.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[], returncode=0,
                stdout="condition met\n", stderr="",
            )
            wait_for_gates(gates, "release", "default", context="prod")
            for call_args in mock_kubectl.call_args_list:
                assert call_args[1]["context"] == "prod"
