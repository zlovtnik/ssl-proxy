from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from sslproxy_ops.stack.cluster import _resource_ready, preflight, status
from sslproxy_ops.stack.core import Component, StackConfig


def test_preflight_requires_kustomize_after_kubectl(tmp_path: Path):
    with patch(
        "sslproxy_ops.stack.cluster.shutil.which",
        side_effect=lambda name: "/usr/bin/kubectl" if name == "kubectl" else None,
    ):
        with pytest.raises(RuntimeError, match="required tool not found: kustomize"):
            preflight(StackConfig(version=1), tmp_path, "default", None, None)


def test_resource_ready_handles_daemonset_and_job():
    daemonset = {
        "kind": "DaemonSet",
        "metadata": {"generation": 2},
        "status": {
            "observedGeneration": 2,
            "desiredNumberScheduled": 3,
            "numberReady": 3,
        },
    }
    job = {
        "kind": "Job",
        "status": {"conditions": [{"type": "Complete", "status": "True"}]},
    }

    assert _resource_ready(daemonset)[0]
    assert _resource_ready(job)[0]


def test_status_does_not_mark_component_with_no_relevant_resources_healthy():
    config = StackConfig(
        version=1,
        components={
            "api": Component(type="helm", release="api", chart="overlay")
        },
    )
    response = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps({"items": [{"kind": "ConfigMap"}]}),
        stderr="",
    )
    with patch("sslproxy_ops.stack.cluster.kubectl", return_value=response):
        results = status(config, "default", None, None)

    assert len(results) == 1
    assert not results[0].healthy
