import unittest

from sslproxy_ops.commands.pipeline import parse_database_url, postgres_env, psql_command


class PipelineTest(unittest.TestCase):
    def test_psql_command_does_not_include_password(self):
        connection = parse_database_url("postgres://sync:p%40ssw0rd@postgres:5432/sync")
        command = psql_command("select 1;")

        self.assertEqual(connection.password, "p@ssw0rd")
        self.assertEqual(postgres_env(connection)["PGPASSWORD"], "p@ssw0rd")
        self.assertNotIn("p@ssw0rd", command)
        self.assertNotIn("postgres://sync", command)


if __name__ == "__main__":
    unittest.main()
