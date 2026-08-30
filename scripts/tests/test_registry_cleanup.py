from __future__ import annotations

import datetime as dt
import unittest
from pathlib import Path

import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

from registry_cleanup import (  # noqa: E402
    CONFIRMATION,
    DigestRecord,
    RegistryCleanupError,
    choose_retention,
    next_link,
    parser,
    parse_timestamp,
    reference_digest,
    validate_arguments,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class RegistryCleanupTest(unittest.TestCase):
    def test_apply_accepts_explicit_plain_http_registry(self) -> None:
        arguments = parser().parse_args(
            [
                "--registry",
                "registry.test:5000",
                "--plain-http",
                "--apply",
                "--confirm",
                CONFIRMATION,
            ]
        )

        validate_arguments(arguments)

    def test_retention_protects_pins_latest_recent_and_unknown_dates(self) -> None:
        now = dt.datetime(2026, 8, 30, tzinfo=dt.timezone.utc)
        records = (
            DigestRecord(digest("a"), ("old",), now - dt.timedelta(days=5)),
            DigestRecord(digest("b"), ("pinned",), now - dt.timedelta(days=4)),
            DigestRecord(digest("c"), ("recent",), now - dt.timedelta(days=1)),
            DigestRecord(digest("d"), ("latest",), now - dt.timedelta(days=3)),
            DigestRecord(digest("e"), ("unknown",), None),
        )
        plan = choose_retention(
            "service", records, {digest("b")}, digest("d"), keep_recent=1
        )
        self.assertEqual({digest("a")}, {record.digest for record in plan.delete})
        self.assertEqual(
            {digest("b"), digest("c"), digest("d"), digest("e")},
            {record.digest for record in plan.keep},
        )

    def test_digest_reference_parsing_handles_runtime_prefixes(self) -> None:
        expected = ("registry.test:5000", "team/service", digest("a"))
        self.assertEqual(
            expected,
            reference_digest(
                f"docker-pullable://registry.test:5000/team/service@{digest('a')}"
            ),
        )
        self.assertIsNone(reference_digest("registry.test/service:latest"))

    def test_digest_reference_strips_tag_before_split(self) -> None:
        self.assertEqual(
            ("registry-1.docker.io", "library/redis", digest("a")),
            reference_digest(f"docker://redis:7.4.3-alpine@{digest('a')}"),
        )
        self.assertEqual(
            ("docker.io", "library/redis", digest("b")),
            reference_digest(f"docker://docker.io/library/redis:7.4.3-alpine@{digest('b')}"),
        )
        self.assertEqual(
            ("registry.test:5000", "team/service", digest("c")),
            reference_digest(
                f"docker://registry.test:5000/team/service:latest@{digest('c')}"
            ),
        )

    def test_timestamp_and_pagination_parsing(self) -> None:
        parsed = parse_timestamp("2026-08-30T12:00:00Z")
        self.assertEqual(dt.timezone.utc, parsed.tzinfo)
        self.assertEqual(
            "https://registry.test/v2/_catalog?last=one&n=100",
            next_link(
                '</v2/_catalog?last=one&n=100>; rel="next"',
                "https://registry.test/v2/_catalog?n=100",
            ),
        )

    def test_invalid_pagination_link_is_rejected(self) -> None:
        with self.assertRaises(RegistryCleanupError):
            next_link("not-a-link; rel=next", "https://registry.test/v2/_catalog")


if __name__ == "__main__":
    unittest.main()
