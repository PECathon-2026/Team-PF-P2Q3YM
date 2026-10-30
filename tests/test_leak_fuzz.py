import contextlib
import io
import unittest

from privacylens.eval.leak_fuzz import run


class LeakFuzzTests(unittest.TestCase):
    def test_seeded_run_has_no_leaks_and_blocks_raw_observations(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(run(runs=1, seed=1), 0)
        report = output.getvalue()
        self.assertRegex(report, r"(?m)^\s*5\s+1\s+15\s+[1-9]\d*\s+0\s+1\s*$")
        self.assertIn("0 leaks in 1 runs", report)


if __name__ == "__main__":
    unittest.main()
