import json
import re
import tempfile
import unittest
from pathlib import Path

from privacylens.eval.gen_data import generate
from privacylens.eval.html_elements import parse_html
from privacylens.sanitize.rules import Rules, load_rules
from privacylens.sanitize.sanitize import sanitize
from privacylens.sanitize.vault import Vault


def observation_json(observation):
    return json.dumps({
        "url": observation.snapshot.url,
        "title": observation.snapshot.title,
        "elements": [{"id": e.attributes.get("id"), "text": e.text, "attributes": dict(e.attributes),
                      "selector": e.selector, "metadata": dict(e.metadata)} for e in observation.snapshot.elements],
        "findings": list(observation.findings),
        "redactions": observation.redactions,
        "metadata": dict(observation.metadata),
    }, ensure_ascii=False, sort_keys=True)


class SanitizerTests(unittest.TestCase):
    def test_all_pages_redact_sensitive_values_and_preserve_decoys_and_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            generated = generate(tmp)
            truth = generated["pages"]
            policy = load_rules(Path(__file__).resolve().parents[1] / "config" / "privacy.json")
            self.assertIsInstance(policy, Rules)
            for page, facts in truth.items():
                with self.subTest(page=page):
                    original = parse_html(Path(tmp) / page)
                    clean = sanitize(original, Vault(), policy, full_page=True)
                    text = observation_json(clean)
                    lowered = text.casefold()
                    orig_ids = {e.attributes["id"] for e in original.elements if "id" in e.attributes}
                    clean_ids = {e.attributes["id"] for e in clean.snapshot.elements if "id" in e.attributes}
                    self.assertEqual(clean_ids, orig_ids)
                    self.assertIn("[REDACTED:", text)
                    for sensitive in facts["sensitive"]:
                        raw = sensitive["value"]
                        normalized = re.sub(r"[\s\-\u200b\u200c\u200d\ufeff]", "", raw).casefold()
                        self.assertNotIn(raw.casefold(), lowered)
                        if normalized:
                            self.assertNotIn(normalized, re.sub(r"[\s\-\u200b\u200c\u200d\ufeff]", "", lowered))
                    by_id = {e.attributes.get("id"): e for e in clean.snapshot.elements if e.attributes.get("id")}
                    for decoy in facts["non_sensitive"]:
                        self.assertIn(decoy["value"], by_id[decoy["id"]].text)
                    card = next((v["value"] for v in facts["sensitive"] if v["type"] == "CARD"), None)
                    if card:
                        last_four = re.sub(r"\D", "", card)[-4:]
                        self.assertNotIn(last_four, text)
                    for finding in clean.findings:
                        self.assertNotIn("value", finding)

    def test_minimization_is_default_and_full_page_is_opt_in(self):
        from privacylens.contracts import Element, Snapshot
        snapshot = Snapshot(url="file://", elements=(
            Element("div", text="unrelated " + "x" * 100, attributes={"id": "unrelated"}),
            Element("button", text="Continue " + "y" * 100, attributes={"id": "continue"}),
            Element("div", text="Relevant panel", attributes={"id": "panel", "label": "Checkout details"}),
        ))
        minimized = sanitize(snapshot, Vault(), Rules(), task_keywords=("checkout",))
        self.assertEqual({e.attributes.get("id") for e in minimized.snapshot.elements}, {"continue", "panel"})
        self.assertLessEqual(len(next(e for e in minimized.snapshot.elements if e.attributes.get("id") == "continue").text), 80)
        full = sanitize(snapshot, Vault(), Rules(), full_page=True)
        self.assertEqual(len(full.snapshot.elements), 3)
        self.assertEqual(len(next(e for e in full.snapshot.elements if e.attributes.get("id") == "unrelated").text), 80)

    def test_same_value_uses_same_session_token_across_formats(self):
        from privacylens.contracts import Element, Snapshot
        vault = Vault()
        snapshot = Snapshot(url="file://", elements=(
            Element("input", attributes={"id": "phone-one", "name": "phone", "value": "+91 987-654-3210"}),
            Element("input", attributes={"id": "phone-two", "name": "phone", "value": "9876543210"}),
            Element("input", attributes={"id": "phone-three", "name": "phone", "value": "9123456780"}),
        ))
        clean = sanitize(snapshot, vault, Rules())
        tokens = [e.attributes["value"] for e in clean.snapshot.elements]
        self.assertEqual(tokens, ["[REDACTED:PHONE#1]", "[REDACTED:PHONE#1]", "[REDACTED:PHONE#2]"])


if __name__ == "__main__": unittest.main()
