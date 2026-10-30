import unittest
from dataclasses import FrozenInstanceError

from privacylens.contracts import (
    Action, Element, Finding, GateResult, Rules, RunReport,
    SanitizedObservation, Snapshot, Vault,
)


class ContractsTest(unittest.TestCase):
    def test_all_contracts_instantiate_and_are_frozen(self):
        finding = Finding(kind="email", value="person@example.com", confidence=0.99)
        element = Element(tag="input", attributes={"type": "email"})
        snapshot = Snapshot(url="http://localhost", elements=(element,))
        observation = SanitizedObservation(snapshot=snapshot, findings=(finding,))
        action = Action(kind="click", target="#submit")
        gate_result = GateResult(allowed=True, action=action)
        vault = Vault(entries={"email": "person@example.com"})
        rules = Rules()
        report = RunReport(actions=(action,), findings=(finding,), status="ok")
        self.assertTrue(all((finding, element, snapshot, observation, action, gate_result, vault, rules, report)))
        self.assertEqual(rules.entropy_threshold, 4.2)
        with self.assertRaises(FrozenInstanceError):
            finding.value = "changed"

    def test_finding_repr_and_public_form_never_expose_value(self):
        secret = "private-canary-value-1299"
        finding = Finding(kind="SECRET", value=secret, source="text",
                          metadata={"start": 4, "end": 29, "rule": "high_entropy_token"})
        self.assertNotIn(secret, repr(finding))
        public = finding.to_public()
        self.assertEqual(public, {"kind": "SECRET", "source": "text", "confidence": 0.0,
                                  "start": 4, "end": 29, "rule": "high_entropy_token"})
        self.assertNotIn(secret, repr(public))
        self.assertNotIn("value", public)


if __name__ == "__main__":
    unittest.main()
