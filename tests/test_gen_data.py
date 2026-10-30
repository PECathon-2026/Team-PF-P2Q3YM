import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

from privacylens.detect.patterns import scan_text
from privacylens.detect.structural import scan_elements
from privacylens.eval.gen_data import generate
from privacylens.eval.html_elements import parse_html


class GenDataTests(unittest.TestCase):
    def test_html_recall_and_decoy_precision(self):
        with tempfile.TemporaryDirectory() as tmp:
            generated = generate(tmp)
            self.assertEqual(set(generated["pages"]), {"checkout.html", "login.html", "support.html", "meet.html", "devsettings.html"})
            ground_truth = json.loads((Path(tmp) / "ground_truth.json").read_text(encoding="utf-8"))
            type_totals = defaultdict(int)
            type_hits = defaultdict(int)

            for page, expected in ground_truth["pages"].items():
                path = Path(tmp) / page
                self.assertTrue(path.exists())
                parsed = parse_html(path)
                elements = list(parsed.elements)
                structural = scan_elements(elements)
                text_findings = scan_text(" ".join(e.text for e in elements))
                all_findings = structural + text_findings

                # Verify each seeded secret against detections from parsed HTML only.
                by_id = {e.attributes.get("id"): e for e in elements if e.attributes.get("id")}
                for item in expected["sensitive"]:
                    kind = item["type"]
                    type_totals[kind] += 1
                    field_id = item["selector"][1:]
                    value = item["value"].lower()
                    matching = [f for f in all_findings if f.kind == kind and
                                (f.value.lower() in value or value in f.value.lower() or
                                 f.metadata.get("element_id") == field_id)]
                    self.assertTrue(matching, f"No {kind} finding for {item['id']} in {page}")
                    type_hits[kind] += 1

                # Run both detectors on each decoy element, without passing truth values in.
                for decoy in expected["non_sensitive"]:
                    element = by_id[decoy["id"]]
                    decoy_findings = scan_elements([element]) + scan_text(element.text)
                    self.assertEqual(decoy_findings, [], f"False positive on decoy {decoy['id']} in {page}: {decoy_findings}")

            self.assertEqual(set(type_totals), set(type_hits))
            for kind, total in type_totals.items():
                self.assertEqual(type_hits[kind] / total, 1.0, f"Recall for {kind}")


if __name__ == "__main__":
    unittest.main()
