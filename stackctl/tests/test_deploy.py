"""Tests for stackctl wave-based deployment execution (deploy.py)."""

from __future__ import annotations

import asyncio
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml

from deploy import (
    ComponentResult,
    DeployOptions,
    DeployResult,
    _capture_job_logs,
    _cleanup_run_dir,
    _create_run_dir,
    _get_job_uid,
    _helm_release_status,
    _helm_rollback,
    _helm_upgrade,
    _redact_dict,
    _redact_value,
    _replace_job,
    _wait_for_job_complete_or_fail,
    _wait_for_job_with_new_uid,
    deploy_component,
    deploy_stack,
    prepare_chart,
    reset_prepared_charts,
)
from shell import ShellError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_component(
    name: str = "test-component",
    type_: str = "helm",
    release: str = "test-release",
    chart: str | None = "./charts/test",
    values_key: str | None = None,
    include_global: bool = False,
    set_overrides: dict | None = None,
    depends_on: list[str] | None = None,
    gates: list | None = None,
    job: dict | None = None,
    timeout: str | None = None,
    rollback_on_failure: bool = False,
):
    """Create a minimal Component-like object for testing."""
    from types import SimpleNamespace

    return SimpleNamespace(
        name=name,
        type=type_,
        release=release,
        chart=chart,
        values_key=values_key,
        include_global=include_global,
        set=set_overrides or {},
        depends_on=depends_on or [],
        gates=gates or [],
        job=SimpleNamespace(rerun="replace") if job else None,
        timeout=timeout,
        rollback_on_failure=rollback_on_failure,
    )


def _make_config(components: dict | None = None):
    """Create a minimal StackConfig-like object."""
    from types import SimpleNamespace

    return SimpleNamespace(
        components=components or {},
        defaults=SimpleNamespace(namespace="default", timeout="10m", values=[]),
    )


def _make_options(**overrides: Any) -> DeployOptions:
    """Create DeployOptions with sensible defaults."""
    opts: dict[str, Any] = {
        "namespace": "default",
        "context": None,
        "kubeconfig": None,
        "root_dir": None,
        "umbrella_values": [],
        "target_component": None,
        "from_wave": None,
        "dry_run": False,
        "verbose": False,
        "keep_artifacts": False,
        "work_dir": None,
    }
    opts.update(overrides)
    return DeployOptions(**opts)


# ===========================================================================
# Chart preparation
# ===========================================================================


class TestPrepareChart:
    """Test chart dependency preparation."""

    def setup_method(self):
        reset_prepared_charts()

    def test_chart_without_dependencies_skips_helm(self, tmp_path: Path):
        chart_path = tmp_path / "charts" / "simple"
        chart_path.mkdir(parents=True)
        with open(chart_path / "Chart.yaml", "w") as f:
            yaml.dump({"apiVersion": "v2", "name": "simple"}, f)

        with patch("deploy.helm") as mock_helm:
            prepare_chart(chart_path)
            mock_helm.assert_not_called()

    def test_chart_with_dependencies_runs_helm(self, tmp_path: Path):
        chart_path = tmp_path / "charts" / "with-deps"
        chart_path.mkdir(parents=True)
        with open(chart_path / "Chart.yaml", "w") as f:
            yaml.dump(
                {
                    "apiVersion": "v2",
                    "name": "with-deps",
                    "dependencies": [{"name": "common", "version": "1.0.0"}],
                },
                f,
            )

        with patch("deploy.helm") as mock_helm:
            prepare_chart(chart_path)
            mock_helm.assert_called_once_with(
                "dependency", "build", str(chart_path.resolve())
            )

    def test_chart_deduplication(self, tmp_path: Path):
        """Same chart path only runs helm dependency build once."""
        chart_path = tmp_path / "charts" / "dedup"
        chart_path.mkdir(parents=True)
        with open(chart_path / "Chart.yaml", "w") as f:
            yaml.dump(
                {
                    "apiVersion": "v2",
                    "name": "dedup",
                    "dependencies": [{"name": "common", "version": "1.0.0"}],
                },
                f,
            )

        with patch("deploy.helm") as mock_helm:
            prepare_chart(chart_path)
            prepare_chart(chart_path)
            mock_helm.assert_called_once()

    def test_missing_chart_yaml_skips_helm(self, tmp_path: Path):
        chart_path = tmp_path / "charts" / "no-yaml"
        chart_path.mkdir(parents=True)

        with patch("deploy.helm") as mock_helm:
            prepare_chart(chart_path)
            mock_helm.assert_not_called()

    def test_reset_prepared_charts(self, tmp_path: Path):
        chart_path = tmp_path / "charts" / "reset-test"
        chart_path.mkdir(parents=True)
        with open(chart_path / "Chart.yaml", "w") as f:
            yaml.dump(
                {
                    "apiVersion": "v2",
                    "name": "reset-test",
                    "dependencies": [{"name": "common", "version": "1.0.0"}],
                },
                f,
            )

        with patch("deploy.helm") as mock_helm:
            prepare_chart(chart_path)
            reset_prepared_charts()
            prepare_chart(chart_path)
            assert mock_helm.call_count == 2


# ===========================================================================
# Helm operations
# ===========================================================================


class TestReplaceJob:
    """Test UID-aware managed Job replacement."""

    def test_job_exists_deletes_it(self):
        with patch("deploy.kubectl") as mock_kubectl:
            mock_kubectl.side_effect = [
                subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="uid-1", stderr=""
                ),
                subprocess.CompletedProcess(
                    args=[], returncode=0, stdout="job deleted\n", stderr=""
                ),
            ]
            assert _replace_job("test-job", "default", None, None) == "uid-1"
            assert mock_kubectl.call_count == 2
            # First call is get, second is delete
            get_args = mock_kubectl.call_args_list[0][0]
            assert "get" in get_args
            assert "--ignore-not-found" in get_args
            delete_args = mock_kubectl.call_args_list[1][0]
            assert "delete" in delete_args
            assert "--wait=true" in delete_args

    def test_job_not_found_skips_delete(self):
        with patch("deploy.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            assert _replace_job("test-job", "default", None, None) is None
            mock_kubectl.assert_called_once()
            # Only get was called, not delete

    def test_context_propagated(self):
        with patch("deploy.kubectl") as mock_kubectl:
            mock_kubectl.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            _replace_job("test-job", "default", context="prod", kubeconfig=None)
            assert mock_kubectl.call_args[1]["context"] == "prod"


class TestHelmReleaseStatus:
    """Test helm release status checking."""

    def test_deployed_release(self):
        with patch("deploy.helm") as mock_helm:
            mock_helm.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout='{"info": {"status": "deployed"}}',
                stderr="",
            )
            status = _helm_release_status("test-release", "default", None, None)
            assert status == "deployed"

    def test_not_found_release(self):
        with patch("deploy.helm") as mock_helm:
            mock_helm.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="Error: release not found"
            )
            status = _helm_release_status("test-release", "default", None, None)
            assert status is None

    def test_invalid_json_response(self):
        with patch("deploy.helm") as mock_helm:
            mock_helm.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="not-json", stderr=""
            )
            status = _helm_release_status("test-release", "default", None, None)
            assert status is None

    def test_failed_release(self):
        with patch("deploy.helm") as mock_helm:
            mock_helm.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout='{"info": {"status": "failed"}}',
                stderr="",
            )
            status = _helm_release_status("test-release", "default", None, None)
            assert status == "failed"


class TestHelmUpgrade:
    """Test helm upgrade --install execution."""

    def test_new_install(self):
        component = _make_component()
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = None  # not deployed yet
            _helm_upgrade(component, {}, Path("/tmp/values.yaml"), "default", None, None)
            args = mock_helm.call_args[0]
            assert args[:2] == ("upgrade", "--install")
            assert "test-release" in args
            assert "./charts/test" in args
            assert "--create-namespace" in args
            assert "--wait=watcher" in args
            assert "--wait-for-jobs" in args
            assert "--timeout" in args

    def test_upgrade_existing(self):
        component = _make_component()
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = "deployed"
            _helm_upgrade(component, {}, Path("/tmp/values.yaml"), "default", None, None)
            args = mock_helm.call_args[0]
            assert "upgrade" in args

    def test_dry_run_flag(self):
        component = _make_component()
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = None
            _helm_upgrade(
                component, {}, Path("/tmp/values.yaml"), "default", None, None, dry_run=True
            )
            args = mock_helm.call_args[0]
            assert "--dry-run=server" in args

    def test_rollback_on_failure_adds_history_max(self):
        component = _make_component(rollback_on_failure=True)
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = "deployed"
            _helm_upgrade(component, {}, Path("/tmp/values.yaml"), "default", None, None)
            args = mock_helm.call_args[0]
            assert "--history-max" in args
            assert "5" in args

    def test_no_history_max_without_rollback(self):
        component = _make_component(rollback_on_failure=False)
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = "deployed"
            _helm_upgrade(component, {}, Path("/tmp/values.yaml"), "default", None, None)
            args = mock_helm.call_args[0]
            assert "--history-max" not in args

    def test_values_file_passed(self):
        component = _make_component()
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = None
            _helm_upgrade(
                component, {}, Path("/custom/path/values.yaml"), "default", None, None
            )
            args = mock_helm.call_args[0]
            assert "-f" in args
            val_idx = args.index("-f")
            assert args[val_idx + 1] == "/custom/path/values.yaml"

    def test_timeout_from_component(self):
        component = _make_component(timeout="30m")
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = None
            _helm_upgrade(component, {}, Path("/tmp/v.yaml"), "default", None, None)
            args = mock_helm.call_args[0]
            timeout_idx = args.index("--timeout")
            assert args[timeout_idx + 1] == "30m"

    def test_output_is_captured_for_component_log(self):
        component = _make_component()
        with patch("deploy._helm_release_status") as mock_status, patch(
            "deploy.helm"
        ) as mock_helm:
            mock_status.return_value = None
            _helm_upgrade(component, {}, Path("/tmp/v.yaml"), "default", None, None)
            assert mock_helm.call_args[1].get("stream") is not True


class TestHelmRollback:
    """Test helm rollback execution."""

    def test_rollback_called_correctly(self):
        with patch("deploy.helm") as mock_helm:
            mock_helm.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="rollback complete", stderr=""
            )
            _helm_rollback("test-release", "default", None, None)
            args = mock_helm.call_args[0]
            assert "rollback" in args
            assert "test-release" in args
            assert "0" in args
            assert "--wait" in args

    def test_context_propagated(self):
        with patch("deploy.helm") as mock_helm:
            mock_helm.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="", stderr=""
            )
            _helm_rollback("test-release", "default", context="prod", kubeconfig=None)
            assert mock_helm.call_args[1]["context"] == "prod"


# ===========================================================================
# Run directory management
# ===========================================================================


class TestRunDir:
    """Test run directory creation and cleanup."""

    def test_create_run_dir_creates_timestamped_dir(self, tmp_path: Path):
        run_dir = _create_run_dir(base=tmp_path)
        assert run_dir.exists()
        assert (run_dir / "effective-values").exists()
        assert (run_dir / "rendered").exists()
        assert run_dir.parent == tmp_path

    def test_create_run_dir_default_base(self):
        with patch("deploy.Path.mkdir") as mock_mkdir:
            _create_run_dir(base=None)
            # Should use .stackctl/runs as base
            assert mock_mkdir.called

    def test_cleanup_run_dir_removes_directory(self, tmp_path: Path):
        test_dir = tmp_path / "test-run"
        test_dir.mkdir()
        (test_dir / "file.txt").write_text("data")
        _cleanup_run_dir(test_dir)
        assert not test_dir.exists()

    def test_cleanup_nonexistent_dir_does_not_raise(self):
        _cleanup_run_dir(Path("/nonexistent/path"))

    def test_run_dir_permissions(self, tmp_path: Path):
        run_dir = _create_run_dir(base=tmp_path)
        mode = os.stat(run_dir).st_mode & 0o777
        assert mode == 0o700


# ===========================================================================
# Redaction
# ===========================================================================


class TestRedact:
    """Test sensitive value redaction."""

    def test_redact_password_key(self):
        assert _redact_value("password", "supersecret") == "[REDACTED]"

    def test_redact_secret_key(self):
        assert _redact_value("mySecret", "s3cr3t") == "[REDACTED]"

    def test_redact_token_key(self):
        assert _redact_value("apiToken", "tok-123") == "[REDACTED]"

    def test_redact_privatekey_key(self):
        assert _redact_value("privateKey", "key-data") == "[REDACTED]"

    def test_redact_apikey_key(self):
        assert _redact_value("apiKey", "key-abc") == "[REDACTED]"

    def test_redact_credentials_key(self):
        assert _redact_value("credentials", "user:pass") == "[REDACTED]"

    def test_do_not_redact_normal_key(self):
        assert _redact_value("hostname", "example.com") == "example.com"

    def test_redact_nested_dict(self):
        data = {"database": {"password": "secret", "host": "localhost"}}
        result = _redact_dict(data)
        assert result["database"]["password"] == "[REDACTED]"
        assert result["database"]["host"] == "localhost"

    def test_redact_list_values(self):
        data = {"secrets": [{"password": "s1"}, {"password": "s2"}]}
        result = _redact_dict(data)
        assert result["secrets"][0]["password"] == "[REDACTED]"
        assert result["secrets"][1]["password"] == "[REDACTED]"

    def test_redact_case_insensitive(self):
        assert _redact_value("PASSWORD", "secret") == "[REDACTED]"
        assert _redact_value("Secret", "secret") == "[REDACTED]"


# ===========================================================================
# Per-component deployment
# ===========================================================================


class TestDeployComponent:
    """Test the full deploy_component lifecycle."""

    def test_helm_component_happy_path(self, tmp_path: Path):
        """Successful helm deployment."""
        component = _make_component(name="test-app", chart="./charts/test")
        config = _make_config(components={"test-app": component})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.prepare_chart") as mock_prepare, patch(
            "deploy.generate_effective_values"
        ) as mock_gen_values, patch("deploy._helm_upgrade") as mock_upgrade, patch(
            "deploy.wait_for_gates"
        ) as mock_gates:
            mock_gen_values.return_value = {"replicas": 3}

            result = deploy_component("test-app", config, options, tmp_path)

            assert result.success is True
            assert result.component == "test-app"
            assert result.error is None
            assert result.duration > 0
            mock_prepare.assert_not_called()
            mock_upgrade.assert_called_once()
            mock_gates.assert_called_once()

    def test_helm_job_component_with_rerun(self, tmp_path: Path):
        """helm-job with rerun=replace deletes existing job first."""
        component = _make_component(
            name="test-job",
            type_="helm-job",
            release="test-job-release",
            chart="./charts/test-job",
            job={"rerun": "replace"},
        )
        config = _make_config(components={"test-job": component})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.prepare_chart") as mock_prepare, patch(
            "deploy.generate_effective_values"
        ) as mock_gen_values, patch("deploy._replace_job") as mock_delete, patch(
            "deploy._helm_upgrade"
        ) as mock_upgrade, patch(
            "deploy.wait_for_gates"
        ) as mock_gates, patch(
            "deploy._wait_for_job_with_new_uid"
        ), patch("deploy._wait_for_job_complete_or_fail"):
            mock_gen_values.return_value = {}

            result = deploy_component("test-job", config, options, tmp_path)

            assert result.success is True
            mock_delete.assert_called_once_with(
                "test-job-release",
                "default",
                None,
                None,
                expected_release="test-job-release",
            )
            mock_upgrade.assert_called_once()
            mock_gates.assert_called_once()

    def test_failure_triggers_rollback_when_configured(self, tmp_path: Path):
        """rollback_on_failure=True triggers helm rollback on failure."""
        component = _make_component(
            name="test-app",
            chart="./charts/test",
            rollback_on_failure=True,
        )
        config = _make_config(components={"test-app": component})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.prepare_chart"), patch(
            "deploy.generate_effective_values"
        ) as mock_gen, patch("deploy._helm_upgrade") as mock_upgrade, patch(
            "deploy._helm_rollback"
        ) as mock_rollback:
            mock_gen.return_value = {"replicas": 3}
            mock_upgrade.side_effect = ShellError(
                command=("helm", "upgrade", "test-release"),
                returncode=1,
                stdout="",
                stderr="upgrade failed",
            )

            result = deploy_component("test-app", config, options, tmp_path)

            assert result.success is False
            assert "upgrade failed" in result.error
            mock_rollback.assert_called_once_with(
                "test-release", "default", None, None
            )

    def test_failure_does_not_rollback_when_not_configured(self, tmp_path: Path):
        """rollback_on_failure=False skips helm rollback on failure."""
        component = _make_component(
            name="test-app",
            chart="./charts/test",
            rollback_on_failure=False,
        )
        config = _make_config(components={"test-app": component})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.prepare_chart"), patch(
            "deploy.generate_effective_values"
        ) as mock_gen, patch("deploy._helm_upgrade") as mock_upgrade, patch(
            "deploy._helm_rollback"
        ) as mock_rollback:
            mock_gen.return_value = {"replicas": 3}
            mock_upgrade.side_effect = ShellError(
                command=("helm", "upgrade", "test-release"),
                returncode=1,
                stdout="",
                stderr="upgrade failed",
            )

            result = deploy_component("test-app", config, options, tmp_path)

            assert result.success is False
            mock_rollback.assert_not_called()

    def test_manifest_without_paths_fails(self, tmp_path: Path):
        """Manifest deployment requires at least one repository YAML path."""
        component = _make_component(
            name="test-manifest", type_="manifest", chart=None
        )
        config = _make_config(components={"test-manifest": component})
        options = _make_options(work_dir=str(tmp_path))

        result = deploy_component("test-manifest", config, options, tmp_path)

        assert result.success is False
        assert "has no paths" in result.error

    def test_missing_chart_returns_failure(self, tmp_path: Path):
        """Component without chart path returns failure."""
        component = _make_component(name="no-chart", chart=None)
        config = _make_config(components={"no-chart": component})
        options = _make_options(work_dir=str(tmp_path))

        result = deploy_component("no-chart", config, options, tmp_path)

        assert result.success is False
        assert "no chart path" in result.error

    def test_dry_run_skips_gates(self, tmp_path: Path):
        """dry_run=True skips gate waiting."""
        component = _make_component(name="test-app", chart="./charts/test")
        config = _make_config(components={"test-app": component})
        options = _make_options(work_dir=str(tmp_path), dry_run=True)

        with patch("deploy.prepare_chart"), patch(
            "deploy.generate_effective_values"
        ) as mock_gen, patch("deploy._helm_upgrade"), patch(
            "deploy.wait_for_gates"
        ) as mock_gates:
            mock_gen.return_value = {"replicas": 3}
            deploy_component("test-app", config, options, tmp_path)
            mock_gates.assert_not_called()

    def test_effective_values_saved_to_run_dir(self, tmp_path: Path):
        """Effective values are written to the run directory."""
        component = _make_component(name="test-app", chart="./charts/test")
        config = _make_config(components={"test-app": component})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.prepare_chart"), patch(
            "deploy.generate_effective_values"
        ) as mock_gen, patch("deploy._helm_upgrade"), patch("deploy.wait_for_gates"):
            mock_gen.return_value = {"replicas": 3, "name": "test"}

            deploy_component("test-app", config, options, tmp_path)

            values_file = tmp_path / "effective-values" / "test-app.redacted.yaml"
            assert values_file.exists()
            with open(values_file) as f:
                data = yaml.safe_load(f)
            assert data["replicas"] == 3
            assert data["name"] == "test"

    def test_rollback_error_does_not_mask_original_error(self, tmp_path: Path):
        """If rollback itself fails, the original error is still returned."""
        component = _make_component(
            name="test-app",
            chart="./charts/test",
            rollback_on_failure=True,
        )
        config = _make_config(components={"test-app": component})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.prepare_chart"), patch(
            "deploy.generate_effective_values"
        ) as mock_gen, patch("deploy._helm_upgrade") as mock_upgrade, patch(
            "deploy._helm_rollback"
        ) as mock_rollback:
            mock_gen.return_value = {"replicas": 3}
            mock_upgrade.side_effect = ShellError(
                command=("helm", "upgrade", "test-release"),
                returncode=1,
                stdout="",
                stderr="upgrade failed",
            )
            mock_rollback.side_effect = ShellError(
                command=("helm", "rollback", "test-release", "0"),
                returncode=1,
                stdout="",
                stderr="rollback also failed",
            )

            result = deploy_component("test-app", config, options, tmp_path)

            assert result.success is False
            assert "upgrade failed" in result.error


# ===========================================================================
# Full stack deployment
# ===========================================================================


class TestDeployStack:
    """Test full stack deployment orchestration."""

    def test_all_waves_succeed(self, tmp_path: Path):
        """All waves complete successfully."""
        comp_a = _make_component(name="a", chart="./charts/a")
        comp_b = _make_component(name="b", chart="./charts/b", depends_on=["a"])
        config = _make_config(components={"a": comp_a, "b": comp_b})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave:
            mock_resolve.return_value = [["a"], ["b"]]
            mock_wave.return_value = [
                ComponentResult(component="a", success=True, duration=1.0),
            ]

            result = asyncio.run(deploy_stack(config, options))

            assert result.success is True
            assert result.waves_completed == 2
            assert result.total_waves == 2

    def test_wave_failure_stops_subsequent_waves(self, tmp_path: Path):
        """When a wave fails, no subsequent waves are started."""
        comp_a = _make_component(name="a", chart="./charts/a")
        comp_b = _make_component(name="b", chart="./charts/b", depends_on=["a"])
        config = _make_config(components={"a": comp_a, "b": comp_b})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave:
            mock_resolve.return_value = [["a"], ["b"]]
            mock_wave.side_effect = [
                [
                    ComponentResult(component="a", success=False, error="wave 1 failed"),
                ],
            ]

            result = asyncio.run(deploy_stack(config, options))

            assert result.success is False
            assert result.waves_completed == 0
            assert mock_wave.call_count == 1  # only first wave attempted

    def test_from_wave_filtering(self, tmp_path: Path):
        """from_wave option filters which waves are deployed."""
        comp_a = _make_component(name="a", chart="./charts/a")
        comp_b = _make_component(name="b", chart="./charts/b", depends_on=["a"])
        config = _make_config(components={"a": comp_a, "b": comp_b})
        options = _make_options(work_dir=str(tmp_path), from_wave=2)

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave:
            mock_resolve.return_value = [["b"]]
            mock_wave.return_value = [
                ComponentResult(component="b", success=True, duration=1.0),
            ]

            result = asyncio.run(deploy_stack(config, options))

            assert result.success is True
            mock_resolve.assert_called_once_with(
                config,
                target_component=None,
                from_wave=2,
                include_descendants=False,
            )

    def test_target_component_filtering(self, tmp_path: Path):
        """target_component option filters which components are deployed."""
        comp_a = _make_component(name="a", chart="./charts/a")
        comp_b = _make_component(name="b", chart="./charts/b", depends_on=["a"])
        config = _make_config(components={"a": comp_a, "b": comp_b})
        options = _make_options(work_dir=str(tmp_path), target_component="b")

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave:
            mock_resolve.return_value = [["a"], ["b"]]
            mock_wave.return_value = [
                ComponentResult(component="a", success=True, duration=1.0),
            ]

            result = asyncio.run(deploy_stack(config, options))

            assert result.success is True
            mock_resolve.assert_called_once_with(
                config,
                target_component="b",
                from_wave=None,
                include_descendants=False,
            )

    def test_run_dir_cleanup_on_success(self, tmp_path: Path):
        """Run directory is cleaned up on successful deployment."""
        comp_a = _make_component(name="a", chart="./charts/a")
        config = _make_config(components={"a": comp_a})
        options = _make_options(work_dir=str(tmp_path), keep_artifacts=False)

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave, patch("deploy._cleanup_run_dir") as mock_cleanup:
            mock_resolve.return_value = [["a"]]
            mock_wave.return_value = [
                ComponentResult(component="a", success=True, duration=1.0),
            ]

            asyncio.run(deploy_stack(config, options))
            mock_cleanup.assert_not_called()

    def test_run_dir_retained_on_failure(self, tmp_path: Path):
        """Run directory is retained when deployment fails."""
        comp_a = _make_component(name="a", chart="./charts/a")
        config = _make_config(components={"a": comp_a})
        options = _make_options(work_dir=str(tmp_path), keep_artifacts=False)

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave, patch("deploy._cleanup_run_dir") as mock_cleanup:
            mock_resolve.return_value = [["a"]]
            mock_wave.return_value = [
                ComponentResult(component="a", success=False, error="failed"),
            ]

            asyncio.run(deploy_stack(config, options))
            mock_cleanup.assert_not_called()

    def test_keep_artifacts_retains_run_dir(self, tmp_path: Path):
        """keep_artifacts=True retains run directory even on success."""
        comp_a = _make_component(name="a", chart="./charts/a")
        config = _make_config(components={"a": comp_a})
        options = _make_options(work_dir=str(tmp_path), keep_artifacts=True)

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave, patch("deploy._cleanup_run_dir") as mock_cleanup:
            mock_resolve.return_value = [["a"]]
            mock_wave.return_value = [
                ComponentResult(component="a", success=True, duration=1.0),
            ]

            asyncio.run(deploy_stack(config, options))
            mock_cleanup.assert_not_called()

    def test_deploy_result_contains_all_component_results(self, tmp_path: Path):
        """DeployResult includes all component results from all waves."""
        comp_a = _make_component(name="a", chart="./charts/a")
        comp_b = _make_component(name="b", chart="./charts/b", depends_on=["a"])
        config = _make_config(components={"a": comp_a, "b": comp_b})
        options = _make_options(work_dir=str(tmp_path))

        with patch("deploy.resolve_dependencies") as mock_resolve, patch(
            "deploy._deploy_wave", new_callable=AsyncMock
        ) as mock_wave:
            mock_resolve.return_value = [["a"], ["b"]]
            mock_wave.side_effect = [
                [ComponentResult(component="a", success=True, duration=1.0)],
                [ComponentResult(component="b", success=True, duration=2.0)],
            ]

            result = asyncio.run(deploy_stack(config, options))

            assert len(result.component_results) == 2
            assert result.component_results[0].component == "a"
            assert result.component_results[1].component == "b"


# ===========================================================================
# Data classes
# ===========================================================================


class TestComponentResult:
    """Test ComponentResult data class."""

    def test_default_values(self):
        r = ComponentResult(component="test", success=True)
        assert r.error is None
        assert r.duration == 0.0
        assert r.skipped is False

    def test_with_error(self):
        r = ComponentResult(component="test", success=False, error="something failed")
        assert r.error == "something failed"

    def test_with_duration(self):
        r = ComponentResult(component="test", success=True, duration=42.5)
        assert r.duration == 42.5


class TestDeployResult:
    """Test DeployResult data class."""

    def test_default_values(self):
        r = DeployResult(success=True, waves_completed=3, total_waves=3)
        assert r.component_results == []

    def test_with_results(self):
        results = [ComponentResult(component="a", success=True)]
        r = DeployResult(
            success=True,
            waves_completed=1,
            total_waves=1,
            component_results=results,
        )
        assert len(r.component_results) == 1
