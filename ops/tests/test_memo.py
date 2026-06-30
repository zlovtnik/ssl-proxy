import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from sslproxy_ops.commands.memo import MemoResult, build_entry, insert_incident, write_incident


class MemoTest(unittest.TestCase):
    def test_insert_incident_after_timeline_header(self):
        original = "# Ops Memory\n\n## Incident Timeline\n- existing\n"
        updated = insert_incident(original, "- new")

        self.assertEqual(updated, "# Ops Memory\n\n## Incident Timeline\n- new\n- existing\n")

    def test_insert_requires_timeline_section(self):
        with self.assertRaises(ValueError):
            insert_incident("# Ops Memory\n", "- new")

    def test_write_incident_updates_file_with_lock(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            memory_file = Path(tmp_dir) / "ops-memory.md"
            shutil.copy(Path(__file__).parent / "fixtures" / "sample-ops-memory.md", memory_file)
            entry = build_entry(
                event="event",
                context="context",
                result=MemoResult.passed,
                profile_mode="iphone",
                signature="none",
                action="manual-note",
                timestamp="2026-01-02T030405-0500",
            )

            write_incident(memory_file, entry)

            text = memory_file.read_text()
            self.assertIn("## Incident Timeline\n- 2026-01-02T030405-0500", text)
            self.assertTrue((Path(tmp_dir) / "ops-memory.md.lock").exists())

    def test_build_entry_formats_timestamp(self):
        entry = build_entry(
            event="event",
            context="context",
            result=MemoResult.failed,
            profile_mode="mac",
            signature="sig",
            action="act",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z"),
        )

        self.assertIn("result=fail | mode=mac | signature=sig", entry)

    def test_build_entry_rejects_multiline_fields(self):
        with self.assertRaises(ValueError):
            build_entry(
                event="event\n- injected",
                context="context",
                result=MemoResult.failed,
                profile_mode="mac",
                signature="sig",
                action="act",
                timestamp="2026-01-02T030405-0500",
            )


if __name__ == "__main__":
    unittest.main()
