from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


class SensorMonitorInitTest(unittest.TestCase):
    def test_reinitializes_monitor_receiver_before_channel_selection(self) -> None:
        self.check_setup("monitor", change_mode=False)

    def test_converts_managed_interface_before_starting_receiver(self) -> None:
        self.check_setup("managed", change_mode=True)

    def check_setup(self, mode: str, *, change_mode: bool) -> None:
        manifest = next(yaml.safe_load_all(
            (ROOT / "cyber-stack/base/atheros-sensor/daemonset.yaml").read_text()
        ))
        script = manifest["spec"]["template"]["spec"]["initContainers"][0]["args"][0]
        # Shell functions replace every hardware command: no live radio access.
        harness = r'''
ip() { printf 'ip %s\n' "$*"; }
iw() {
    if [ "$*" = 'dev wlan0 info' ]; then
        printf 'type %s\nchannel 6 (2437 MHz)\n' "$TEST_INTERFACE_MODE"
    else
        printf 'iw %s\n' "$*"
    fi
}
'''
        result = subprocess.run(
            ["bash", "-ec", harness + script], text=True, capture_output=True,
            env={**os.environ, "ATH_SENSOR_DEVICE": "wlan0",
                 "ATH_SENSOR_REG_DOMAIN": "US", "ATH_SENSOR_CHANNEL": "6",
                 "TEST_INTERFACE_MODE": mode},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = ["iw reg set US", "ip link set wlan0 down"]
        if change_mode:
            expected.append("iw dev wlan0 set type monitor")
        expected.extend(["ip link set wlan0 up", "iw dev wlan0 set channel 6"])
        self.assertEqual(result.stdout.splitlines(), expected)


if __name__ == "__main__":
    unittest.main()
