"""Focused regression tests for kustomize deployment behavior."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import yaml

import pytest

from deploy import (
    DeployOptions,
    _cluster_mutation_snapshot,
    _kustomize_deploy,
    deploy_stack,
)
from stackctl import generate_effective_values, load_config, load_umbrella_values


def test_repository_stack_components_reference_kustomizations():
    root = Path(__file__).resolve().parents[2]
    config_path = root / "stackctl/stack.yaml"
    stack = yaml.safe_load(config_path.read_text())
    config = load_config(config_path)
    umbrella_values = load_umbrella_values(config, root)

    for name, component in stack["components"].items():
        overlay = root / component["chart"]
        assert (overlay / "kustomization.yaml").is_file(), overlay
        assert isinstance(
            generate_effective_values(
                config,
                name,
                umbrella_values,
                root_dir=root,
            ),
            dict,
        )


def test_kustomize_dry_run_renders_without_cluster_apply(
    tmp_path: Path,
):
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    (overlay / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources: []\n"
    )
    component = SimpleNamespace(release="test-release", chart=str(overlay))
    captured: dict[str, Any] = {}

    def fake_build(path: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["kustomization"] = yaml.safe_load(
            (Path(path) / "kustomization.yaml").read_text()
        )
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    with patch("deploy.kustomize_build", side_effect=fake_build):
        _kustomize_deploy(component, "default", None, None, "15m", dry_run=True)

    assert captured["kustomization"] == {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": [],
    }
    assert captured["kwargs"] == {"context": None, "kubeconfig": None}


def test_kustomize_live_deploy_is_rejected(tmp_path: Path):
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    (overlay / "kustomization.yaml").write_text(
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources: []\n"
    )
    component = SimpleNamespace(release="test-release", chart=str(overlay))

    with pytest.raises(RuntimeError, match="Argo CD"):
        _kustomize_deploy(component, "default", None, None, "15m")


def test_stack_live_deploy_is_rejected_before_work_starts():
    config = SimpleNamespace(components={})
    options = DeployOptions(namespace="default")

    with pytest.raises(RuntimeError, match="Argo CD"):
        asyncio.run(deploy_stack(config, options))


def test_cluster_mutation_snapshot_excludes_ephemeral_resources():
    listed = subprocess.CompletedProcess(
        args=[], returncode=0, stdout='{"items": []}', stderr=""
    )
    options = DeployOptions(namespace="default")
    with patch("deploy.kubectl", return_value=listed) as mock_kubectl:
        assert _cluster_mutation_snapshot(options) == {"resources": []}

    kinds = mock_kubectl.call_args.args[1].split(",")
    assert "deployment" in kinds
    assert "configmap" in kinds
    assert "all" not in kinds
    assert "pod" not in kinds
    assert "replicaset" not in kinds
