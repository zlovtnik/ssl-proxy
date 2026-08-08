from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from sslproxy_ops.stack.deploy import (
    _capture_kustomize_rollback_state,
    _kustomize_rollback,
)


def test_capture_excludes_jobs_and_keeps_previous_manifest():
    manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: default
---
apiVersion: batch/v1
kind: Job
metadata:
  name: migrate
  namespace: default
"""
    live = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "api",
            "namespace": "default",
            "resourceVersion": "42",
            "uid": "uid-1",
        },
        "spec": {"replicas": 2},
        "status": {"readyReplicas": 2},
    }
    with patch("sslproxy_ops.stack.deploy.kubectl") as mock_kubectl:
        mock_kubectl.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(live), stderr=""
        )
        state = _capture_kustomize_rollback_state(manifest, "default", None, None)

    assert len(state) == 1
    assert state[0]["kind"] == "Deployment"
    assert state[0]["previous"]["metadata"]["uid"] == "uid-1"


def test_rollback_restores_sanitized_state_and_deletes_new_resources():
    state = [
        {
            "kind": "Deployment",
            "namespace": "default",
            "name": "api",
            "previous": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "api",
                    "namespace": "default",
                    "uid": "uid-1",
                    "resourceVersion": "42",
                    "creationTimestamp": "2026-01-01T00:00:00Z",
                },
                "spec": {"replicas": 2},
                "status": {"readyReplicas": 2},
            },
        },
        {
            "kind": "ConfigMap",
            "namespace": "default",
            "name": "new-config",
            "previous": None,
        },
    ]

    with patch("sslproxy_ops.stack.deploy.kubectl") as mock_kubectl:
        assert _kustomize_rollback(state, None, None)

    restored = mock_kubectl.call_args_list[0].kwargs["input_text"]
    assert "resourceVersion" not in restored
    assert "creationTimestamp" not in restored
    assert "uid:" not in restored
    assert "status:" not in restored
    assert "replicas: 2" in restored
    assert mock_kubectl.call_args_list[1].args[:3] == (
        "delete",
        "ConfigMap",
        "new-config",
    )
