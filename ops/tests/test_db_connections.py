import unittest

from sslproxy_ops.commands.db_connections import redact_connection_log, sha256_text


class DbConnectionsTest(unittest.TestCase):
    def test_sha256_text_matches_shell_fingerprint_contract(self):
        self.assertEqual(
            sha256_text("sync"),
            "75c75efe327a8ef35a072f25117961f5b99e35035dc9bd86493dd29fd7bc07eb",
        )

    def test_redact_connection_log_masks_connection_details(self):
        line = (
            "PSQLException host=db.internal password=s3cr3t token=abc "
            "postgres://sync:s3cr3t@db.internal:5432/sync"
        )

        redacted = redact_connection_log(line)

        self.assertNotIn("s3cr3t", redacted)
        self.assertNotIn("db.internal", redacted)
        self.assertNotIn("abc", redacted)
        self.assertIn("[REDACTED]", redacted)


if __name__ == "__main__":
    unittest.main()
