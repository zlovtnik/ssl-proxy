import asyncio
import time
import unittest

from sslproxy_ops.health import HealthCheck, run_checks


class HealthRunnerTest(unittest.IsolatedAsyncioTestCase):
    async def test_runs_checks_concurrently(self):
        async def slow_ok():
            await asyncio.sleep(0.05)
            return "ok"

        started = time.monotonic()
        results = await run_checks(
            [
                HealthCheck("one", slow_ok),
                HealthCheck("two", slow_ok),
            ]
        )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 0.09)
        self.assertEqual([result.name for result in results], ["one", "two"])
        self.assertTrue(all(result.ok for result in results))

    async def test_retries_failed_check(self):
        attempts = 0

        def flaky():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise RuntimeError("not yet")
            return True

        [result] = await run_checks([HealthCheck("flaky", flaky, retries=2)])

        self.assertTrue(result.ok)
        self.assertEqual(result.attempts, 2)


if __name__ == "__main__":
    unittest.main()

