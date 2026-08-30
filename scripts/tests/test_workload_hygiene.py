from __future__ import annotations

import unittest
from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class WorkloadHygieneTest(unittest.TestCase):
    def test_controller_history_and_finished_job_retention_are_bounded(self) -> None:
        failures: list[str] = []
        for path in sorted((REPOSITORY_ROOT / "cyber-stack/base").rglob("*.yaml")):
            for index, document in enumerate(
                yaml.safe_load_all(path.read_text(encoding="utf-8")), start=1
            ):
                if not isinstance(document, dict):
                    continue
                kind = document.get("kind")
                spec = document.get("spec")
                if not isinstance(spec, dict):
                    continue
                label = f"{path.relative_to(REPOSITORY_ROOT)} document {index}"
                if kind in {"Deployment", "StatefulSet"}:
                    history = spec.get("revisionHistoryLimit")
                    if not isinstance(history, int) or not 0 <= history <= 3:
                        failures.append(f"{label}: revisionHistoryLimit must be 0..3")
                if kind == "Job":
                    ttl = spec.get("ttlSecondsAfterFinished")
                    if not isinstance(ttl, int) or ttl <= 0:
                        failures.append(f"{label}: ttlSecondsAfterFinished must be positive")
        self.assertEqual([], failures)


if __name__ == "__main__":
    unittest.main()
