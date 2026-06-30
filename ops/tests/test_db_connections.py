import unittest

from sslproxy_ops.commands.db_connections import sha256_text


class DbConnectionsTest(unittest.TestCase):
    def test_sha256_text_matches_shell_fingerprint_contract(self):
        self.assertEqual(
            sha256_text("sync"),
            "75c75efe327a8ef35a072f25117961f5b99e35035dc9bd86493dd29fd7bc07eb",
        )


if __name__ == "__main__":
    unittest.main()
