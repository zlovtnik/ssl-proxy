import unittest

from sslproxy_ops.commands.db_connections import redact_connection_log


class DbConnectionsTest(unittest.TestCase):
    def test_redact_connection_log_masks_connection_details(self):
        line = (
            "SQLException host=db.internal password=s3cr3t token=abc "
            "mysql://octopus:s3cr3t@db.internal:4000/octopus_core"
        )

        redacted = redact_connection_log(line)

        self.assertNotIn("s3cr3t", redacted)
        self.assertNotIn("db.internal", redacted)
        self.assertNotIn("abc", redacted)
        self.assertIn("[REDACTED]", redacted)
        self.assertIn("[REDACTED_DATABASE_URL]", redacted)


if __name__ == "__main__":
    unittest.main()
