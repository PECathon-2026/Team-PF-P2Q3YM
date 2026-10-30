"""Coverage report for the synthetic HTML pages, using parsed DOM elements."""
from __future__ import annotations

import json
from pathlib import Path

from ..detect.structural import scan_elements
from .gen_data import ROOT, generate
from .html_elements import parse_html


def evaluate(directory: str | Path = ROOT / "testsite") -> tuple[list[dict], bool]:
    directory = Path(directory)
    truth_path = directory / "ground_truth.json"
    if not truth_path.exists():
        generate(directory)
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    rows: list[dict] = []
    failed = False
    for page, expected in truth["pages"].items():
        elements = list(parse_html(directory / page).elements)
        findings = scan_elements(elements)
        by_id = {str(el.attributes.get("id", "")): el for el in elements if el.attributes.get("id")}
        for kind in sorted({item["type"] for item in expected["sensitive"]}):
            seeds = [item for item in expected["sensitive"] if item["type"] == kind]
            found = 0
            for item in seeds:
                target_id = item["selector"].lstrip("#")
                # Match the detector's parsed element location. GT values never enter detectors.
                if any(f.kind == kind and str(f.metadata.get("element_id", "")) == target_id for f in findings):
                    found += 1
            missed = len(seeds) - found
            failed |= missed > 0
            rows.append({"page": page, "type": kind, "seeded": len(seeds), "found": found, "missed": missed, "decoys": ""})
        false_positives = 0
        for decoy in expected.get("non_sensitive", []):
            element = by_id.get(decoy["selector"].lstrip("#"))
            if element is not None and scan_elements([element]):
                false_positives += 1
        failed |= false_positives > 0
        rows.append({"page": page, "type": "DECOYS", "seeded": len(expected.get("non_sensitive", [])),
                     "found": "", "missed": "", "decoys": false_positives})
    return rows, failed


def main() -> int:
    rows, failed = evaluate()
    headers = ("Page", "Type", "Seeded", "Found", "Missed", "Decoys wrongly flagged")
    widths = [max(len(headers[i]), *(len(str(row[key])) for row in rows)) for i, key in enumerate(("page", "type", "seeded", "found", "missed", "decoys"))]
    print(" | ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        values = (row["page"], row["type"], row["seeded"], row["found"], row["missed"], row["decoys"])
        print(" | ".join(str(value).ljust(widths[i]) for i, value in enumerate(values)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
