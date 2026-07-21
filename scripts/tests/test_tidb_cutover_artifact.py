from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "tidb-cutover-artifact.py"
SPEC = importlib.util.spec_from_file_location("tidb_cutover_artifact", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
cutover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cutover)


class CutoverArtifactTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cutover = {
            "schema_version": 1,
            "kind": "cutover",
            "cluster_id": "redpanda-production-a",
            "captured_at": "2026-07-21T21:00:00Z",
            "group_version": "tidb-v1",
            "partitions": [
                {"group_id": "octopus-wireless-tidb-v1", "topic": "wireless.audit", "partition": 0, "next_offset": 10},
                {"group_id": "octopus-wireless-tidb-v1", "topic": "wireless.audit", "partition": 1, "next_offset": 20},
            ],
        }
        self.audit_end = {
            "schema_version": 1,
            "kind": "audit_end",
            "cluster_id": "redpanda-production-a",
            "captured_at": "2026-07-21T21:30:00Z",
            "cutover_sha256": cutover.canonical_sha256(self.cutover),
            "partitions": [
                {"group_id": "octopus-wireless-tidb-v1", "topic": "wireless.audit", "partition": 0, "end_offset": 12},
                {"group_id": "octopus-wireless-tidb-v1", "topic": "wireless.audit", "partition": 1, "end_offset": 21},
            ],
        }

    def ledger_path(self, rows: list[dict[str, object]]) -> Path:
        handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        with handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        return Path(handle.name)

    def row(self, partition: int, offset: int, status: str) -> dict[str, object]:
        return {
            "group_id": "octopus-wireless-tidb-v1",
            "topic": "wireless.audit",
            "partition": partition,
            "offset": offset,
            "group_version": "tidb-v1",
            "artifact_sha256": cutover.canonical_sha256(self.cutover),
            "status": status,
        }

    def test_clean_bounded_coverage_accepts_processed_and_deduplicated(self) -> None:
        ledger = self.ledger_path(
            [
                self.row(0, 10, "processed"),
                self.row(0, 11, "deduplicated"),
                self.row(1, 20, "processed"),
            ]
        )
        report = cutover.coverage_report(self.cutover, self.audit_end, ledger)
        self.assertTrue(report["clean"])
        self.assertEqual(report["totals"]["expected"], 3)
        self.assertEqual(report["totals"]["deduplicated"], 1)

    def test_gap_blocks_acceptance(self) -> None:
        ledger = self.ledger_path(
            [self.row(0, 10, "processed"), self.row(1, 20, "processed")]
        )
        with self.assertRaisesRegex(cutover.EvidenceError, "unexplained ledger gap"):
            cutover.coverage_report(self.cutover, self.audit_end, ledger)

    def test_retrying_or_parked_blocks_acceptance(self) -> None:
        for status in ("retrying", "parked"):
            with self.subTest(status=status):
                ledger = self.ledger_path(
                    [
                        self.row(0, 10, "processed"),
                        self.row(0, 11, status),
                        self.row(1, 20, "processed"),
                    ]
                )
                with self.assertRaisesRegex(cutover.EvidenceError, "unclean status"):
                    cutover.coverage_report(self.cutover, self.audit_end, ledger)

    def test_pre_cutoff_consumption_blocks_acceptance(self) -> None:
        ledger = self.ledger_path(
            [
                self.row(0, 9, "processed"),
                self.row(0, 10, "processed"),
                self.row(0, 11, "processed"),
                self.row(1, 20, "processed"),
            ]
        )
        with self.assertRaisesRegex(cutover.EvidenceError, "pre-cutoff consumption"):
            cutover.coverage_report(self.cutover, self.audit_end, ledger)

    def test_audit_end_must_reference_exact_cutover(self) -> None:
        changed = dict(self.audit_end, cutover_sha256="0" * 64)
        ledger = self.ledger_path([])
        with self.assertRaisesRegex(cutover.EvidenceError, "different cutover"):
            cutover.coverage_report(self.cutover, changed, ledger)

    def test_non_utc_timestamp_is_rejected(self) -> None:
        changed = dict(self.cutover, captured_at="2026-07-21T17:00:00-04:00")
        with self.assertRaisesRegex(cutover.EvidenceError, "UTC Z suffix"):
            cutover.validate_artifact(changed)

    def test_same_topic_partition_isolated_by_group(self) -> None:
        second = dict(
            self.cutover["partitions"][0],
            group_id="atheros-search-wireless-tidb-v1",
        )
        changed = dict(self.cutover, partitions=[*self.cutover["partitions"], second])
        partitions = cutover.validate_artifact(changed)
        self.assertEqual(len(partitions), 3)

    def test_group_plan_writes_one_rpk_file_per_group(self) -> None:
        second = dict(
            self.cutover["partitions"][0],
            group_id="atheros-search-wireless-tidb-v1",
        )
        changed = dict(self.cutover, partitions=[*self.cutover["partitions"], second])
        with tempfile.TemporaryDirectory() as directory:
            plan = cutover.group_plan(changed, Path(directory))
            self.assertEqual(len(plan["groups"]), 2)
            for group in plan["groups"]:
                offset_file = Path(group["offset_file"])
                self.assertTrue(offset_file.is_file())
                self.assertTrue(offset_file.read_text().startswith("wireless.audit "))

    def test_group_apply_requires_exact_approval_and_cluster(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = cutover.group_plan(self.cutover, Path(directory))
            with self.assertRaisesRegex(cutover.EvidenceError, "approval SHA-256"):
                cutover.apply_group_plan(plan, Path("rpk.yaml"), "0" * 64, plan["cluster_id"])
            with self.assertRaisesRegex(cutover.EvidenceError, "cluster_id"):
                cutover.apply_group_plan(
                    plan,
                    Path("rpk.yaml"),
                    plan["cutover_sha256"],
                    "wrong-cluster",
                )


if __name__ == "__main__":
    unittest.main()
