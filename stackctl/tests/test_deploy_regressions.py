"""Focused regression tests for kustomize deployment behavior."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import yaml

from deploy import DeployOptions, _cluster_mutation_snapshot, _kustomize_deploy


def test_kustomize_deploy_omits_effective_values_configmap_and_passes_timeout(
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

    def fake_apply(path: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["kustomization"] = yaml.safe_load(
            (Path(path) / "kustomization.yaml").read_text()
        )
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    with patch("deploy.kustomize_apply", side_effect=fake_apply):
        _kustomize_deploy(component, "default", None, None, "15m")

    assert captured["kustomization"] == {
        "apiVersion": "kustomize.config.k8s.io/v1beta1",
        "kind": "Kustomization",
        "resources": ["overlay"],
    }
    assert captured["kwargs"]["timeout"] == "15m"


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
