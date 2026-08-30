from __future__ import annotations

import unittest
from pathlib import Path

import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from pvc_audit import find_candidates  # noqa: E402


class PVCAuditTest(unittest.TestCase):
    def test_only_unowned_untracked_unreferenced_claim_is_reported(self) -> None:
        claims = {
            "items": [
                self.claim("candidate", "pv-candidate"),
                self.claim("used", "pv-used"),
                self.claim("owned", "pv-owned", owner=True),
                self.claim("tracked", "pv-tracked", tracked=True),
            ]
        }
        volumes = {
            "items": [
                {
                    "metadata": {"name": "pv-candidate"},
                    "spec": {"persistentVolumeReclaimPolicy": "Delete"},
                }
            ]
        }
        pods = {
            "items": [
                {
                    "metadata": {"namespace": "default", "name": "consumer"},
                    "spec": {
                        "volumes": [
                            {"persistentVolumeClaim": {"claimName": "used"}}
                        ]
                    },
                }
            ]
        }
        candidates = find_candidates(claims, volumes, pods)
        self.assertEqual(["candidate"], [candidate.name for candidate in candidates])
        self.assertEqual("Delete", candidates[0].reclaim_policy)

    @staticmethod
    def claim(name: str, volume: str, *, owner: bool = False, tracked: bool = False) -> dict:
        metadata: dict = {"namespace": "default", "name": name}
        if owner:
            metadata["ownerReferences"] = [{"kind": "StatefulSet", "name": "owner"}]
        if tracked:
            metadata["annotations"] = {
                "argocd.argoproj.io/tracking-id": "application:/PersistentVolumeClaim:default/name"
            }
        return {
            "metadata": metadata,
            "spec": {
                "volumeName": volume,
                "storageClassName": "local-path",
                "resources": {"requests": {"storage": "10Gi"}},
            },
            "status": {"phase": "Bound"},
        }


if __name__ == "__main__":
    unittest.main()
