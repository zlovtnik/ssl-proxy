import tempfile
import unittest
from pathlib import Path

from sslproxy_ops.util.ini import (
    contains_unresolved_placeholder,
    peer_names,
    read_dotenv_value,
    read_ini_value,
    trim_key_value,
    uri_encode,
)


class UtilIniTest(unittest.TestCase):
    def test_peer_names_trims_and_validates(self):
        self.assertEqual(peer_names(" peer1,peer_2,peer-3,, "), ["peer1", "peer_2", "peer-3"])
        with self.assertRaises(ValueError):
            peer_names("peer one")

    def test_dotenv_reader_uses_last_value_and_unquotes(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / ".env"
            path.write_text('REGISTRY=old\nREGISTRY="new"\n')
            self.assertEqual(read_dotenv_value(path, "REGISTRY"), "new")

    def test_ini_reader(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "peer.conf"
            path.write_text("[Interface]\nPrivateKey = abc\n")
            self.assertEqual(read_ini_value(path, "Interface", "PrivateKey"), "abc")

    def test_small_helpers(self):
        self.assertEqual(trim_key_value(" a b\n"), "ab")
        self.assertTrue(contains_unresolved_placeholder("<server-local-ip>"))
        self.assertEqual(uri_encode("a b/c"), "a%20b%2Fc")


if __name__ == "__main__":
    unittest.main()

