from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


SCRIPT = (Path(__file__).resolve().parents[1] / "recover-platform-sync-pgbouncer.sh").read_text()


class RecoveryChecksTest(unittest.TestCase):
    def run_fragment(self, fragment: str, mocks: str, **environment: str):
        # Execute the actual guard sections with shell functions replacing host commands.
        return subprocess.run(
            ["bash", "-c", "set -euo pipefail\n"
             'SYNC_SERVICE=sync.service; SYNC_TIMER=sync.timer; NAMESPACE=test\n'
             'fail() { printf "%s\\n" "$*" >&2; exit 1; }\n'
             + mocks + "\n" + fragment],
            env={**os.environ, **environment}, capture_output=True, text=True,
        )

    def test_timer_is_stopped_before_service_state_is_checked(self) -> None:
        fragment = SCRIPT[SCRIPT.index("timer_was_active=false"):SCRIPT.index('work_dir="$(mktemp')]
        mocks = '''
systemctl() {
    printf '%s\n' "$*" >&2
    case "$1" in
        is-active) [[ $TIMER_ACTIVE == true ]] ;;
        stop) timer_stopped=true ;;
        show)
            [[ ${timer_stopped:-false} == true ]] || return 1
            printf '%s\n' "$SERVICE_STATE" ;;
    esac
}
'''
        for timer_active in ("true", "false"):
            for state in ("inactive", "failed", "active", "activating", "deactivating"):
                with self.subTest(timer=timer_active, state=state):
                    result = self.run_fragment(fragment + '\nprintf "installation allowed\\n"\n',
                                               mocks, TIMER_ACTIVE=timer_active, SERVICE_STATE=state)
                    self.assertEqual(state in ("inactive", "failed"), result.returncode == 0,
                                     result.stderr)
                    self.assertEqual(state in ("inactive", "failed"),
                                     "installation allowed" in result.stdout)
                    calls = result.stderr.splitlines()
                    self.assertLess(calls.index("stop sync.timer"),
                                    calls.index("show sync.service --property=ActiveState --value"))
                    self.assertEqual(timer_active == "true", "start sync.timer" in calls)

    def test_readiness_must_advance_and_have_numeric_success_time(self) -> None:
        fragment = SCRIPT[SCRIPT.index("printf '%s\\n' 'Running platform-sync...'"):]
        mocks = '''
systemctl() {
    if [[ $1 == start ]]; then
        [[ -n $previous_resource_version ]] || return 1
        started=true
    else
        return 1
    fi
}
kubectl() {
    case "$*" in
        *resourceVersion*)
            if [[ ${started:-false} == true ]]; then
                printf '%s' "$NEW_VERSION"
            else
                printf '%s' 100
            fi ;;
        *data.ready*) printf true ;;
        *contract-sha256*) printf '%064d' 0 ;;
        *last-success-unix*) printf '%s' "$SUCCESS_TIME" ;;
        *) return 1 ;;
    esac
}
'''
        for version, timestamp, success in (("101", "1234", True), ("100", "1234", False),
                                            ("", "1234", False), ("101", "invalid", False)):
            with self.subTest(version=version, timestamp=timestamp):
                result = self.run_fragment(fragment, mocks, NEW_VERSION=version, SUCCESS_TIME=timestamp)
                self.assertEqual(success, result.returncode == 0, result.stderr)
                self.assertEqual(success, "Recovery complete" in result.stdout)
                if version == "100":
                    self.assertIn("not updated by this recovery run", result.stderr)


if __name__ == "__main__":
    unittest.main()
