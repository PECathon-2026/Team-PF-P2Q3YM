import contextlib
import io
import json
import unittest
from pathlib import Path

from privacylens.eval.run_eval import main


ROOT = Path(__file__).resolve().parents[1]


class EvaluationSmokeTests(unittest.TestCase):
    def test_quick_evaluation_compares_protected_and_baseline_leaks(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--runs", "1", "--seed", "1", "--quick"]), 0)
        results = json.loads((ROOT / "eval" / "results.json").read_text(encoding="utf-8"))
        self.assertEqual(results["leakage"]["protected_leaks"], 0)
        self.assertGreater(results["leakage"]["baseline_leaks"], 0)
        self.assertEqual(len(results["context_preservation"]["pages"]), 5)
        self.assertEqual(results["context_preservation"]["questions"], 40)
        self.assertEqual(results["security"]["fault_injections"]["passed"],
                         results["security"]["fault_injections"]["total"])
        self.assertIn("0 leaks in 1 runs on the tested pages and gate pathway", output.getvalue())


if __name__ == "__main__":
    unittest.main()
