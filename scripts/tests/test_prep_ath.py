from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "prep_ath.sh"


class PrepAthTest(unittest.TestCase):
    def test_help_does_not_require_the_retired_ops_package(self) -> None:
        completed = subprocess.run(
            ["bash", str(SCRIPT), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Usage: prep_ath.sh", completed.stdout)
        self.assertNotIn("ops-python.sh", completed.stderr)

    def test_prepares_the_requested_interface(self) -> None:
        harness = r'''
source "$1"
require_root() { :; }
ip() {
    if [[ "$1 $2 $3" == "link show dev" ]]; then
        return 0
    fi
    printf 'ip'
    printf ' <%s>' "$@"
    printf '\n'
}
iw() {
    printf 'iw'
    printf ' <%s>' "$@"
    printf '\n'
}
main --reg-domain ca --channel 11 wlxc01c3038d5e8
'''
        completed = subprocess.run(
            ["bash", "-c", harness, "prep-ath-test", str(SCRIPT)],
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            [
                "iw <reg> <set> <CA>",
                "ip <link> <set> <wlxc01c3038d5e8> <down>",
                "iw <wlxc01c3038d5e8> <set> <monitor> <control>",
                "ip <link> <set> <wlxc01c3038d5e8> <up>",
                "iw <dev> <wlxc01c3038d5e8> <set> <channel> <11>",
                "Prepared wlxc01c3038d5e8 for monitor mode (regulatory domain CA, channel 11).",
            ],
        )


if __name__ == "__main__":
    unittest.main()
