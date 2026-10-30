import base64
import sys
import types
import unittest
from urllib.parse import quote
from unittest.mock import patch

from privacylens.contracts import Element, SanitizedObservation, Snapshot
from privacylens.detect.validators import luhn_generate
from privacylens.gate.canary import CanaryRegistry
from privacylens.gate.egress import send
from privacylens.gate.receipt import Receipt
from privacylens.eval.mock_llm import MockTransport
from privacylens.sanitize.vault import Vault


def observation_with(text):
    return SanitizedObservation(snapshot=Snapshot(url="file://", elements=(Element("p", text=text),)))


class EgressTests(unittest.TestCase):
    def _assert_blocked(self, observation, registry=None, vault=None):
        transport = MockTransport()
        result, response = send(observation, "review", [], transport, registry=registry, vault=vault)
        self.assertFalse(result.allowed)
        self.assertTrue(result.blocked)
        self.assertTrue(result.metadata["blocked"])
        self.assertIsNone(response)
        self.assertEqual(transport.captured, [])
        return result

    def test_blocks_raw_card_and_space_separated_card(self):
        card = luhn_generate("411111111111")
        self._assert_blocked(observation_with(card))
        registry = CanaryRegistry(); registry.register(card, "card-canary")
        self._assert_blocked(observation_with(" ".join(card[i:i+4] for i in range(0, 16, 4))), registry)

    def test_blocks_base64_key_url_encoded_email_and_zero_width_card(self):
        key = "AKIA0000000000000000"
        registry = CanaryRegistry(); registry.register(key, "key-canary")
        self._assert_blocked(observation_with(base64.b64encode(key.encode()).decode()), registry)

        email = "alice.canary@example.test"
        registry = CanaryRegistry(); registry.register(email, "email-canary")
        self._assert_blocked(observation_with(quote(email, safe="")), registry)

        card = luhn_generate("411111111111")
        registry = CanaryRegistry(); registry.register(card, "card-canary")
        obfuscated = "\u200b".join(card[i:i+4] for i in range(0, 16, 4))
        self._assert_blocked(observation_with(obfuscated), registry)

    def test_blocks_values_found_in_vault(self):
        secret = "vault-private-canary-8732"
        vault = Vault(); vault.add(secret, "SECRET", ("file://",))
        result = self._assert_blocked(observation_with(secret), vault=vault)
        self.assertNotIn(secret, repr(result))
        self.assertNotIn(secret, str(result.metadata["receipt"]))

    def test_detector_exception_blocks_and_never_calls_transport(self):
        transport = MockTransport()
        with patch("privacylens.gate.egress.scan_text", side_effect=RuntimeError("detector failure")):
            result, response = send(observation_with("clean"), "review", [], transport)
        self.assertFalse(result.allowed)
        self.assertIsNone(response)
        self.assertEqual(transport.captured, [])

    def test_ocr_timeout_blocks_and_never_calls_transport(self):
        class FakeImage:
            def __enter__(self): return self
            def __exit__(self, *_args): return False
        image_api = types.SimpleNamespace(open=lambda _stream: FakeImage())
        pil_module = types.ModuleType("PIL"); pil_module.Image = image_api
        tesseract = types.ModuleType("pytesseract")
        def timeout(_image): raise TimeoutError("OCR timed out")
        tesseract.image_to_string = timeout
        observation = SanitizedObservation(snapshot=Snapshot(url="file://", screenshot=b"not-a-real-png"),
                                           metadata={"screenshot_redacted": True})
        transport = MockTransport()
        with patch.dict(sys.modules, {"PIL": pil_module, "pytesseract": tesseract}):
            result, response = send(observation, "review", [], transport)
        self.assertTrue(result.blocked)
        self.assertIsNone(response)
        self.assertEqual(transport.captured, [])

    def test_malformed_model_json_blocks_before_transport(self):
        transport = MockTransport()
        result, response = send(observation_with("clean"), {"model_json": "{broken"}, [], transport)
        self.assertTrue(result.blocked)
        self.assertIsNone(response)
        self.assertEqual(transport.captured, [])

    def test_clean_observation_passes_and_receipt_has_no_value(self):
        secret = "private-canary-9901"
        transport = MockTransport()
        result, response = send(observation_with("Continue to order summary"), "review", [], transport)
        self.assertTrue(result.allowed)
        self.assertFalse(result.blocked)
        self.assertEqual(response, transport.response)
        self.assertEqual(len(transport.captured), 1)
        self.assertNotIn(secret, repr(result))
        self.assertNotIn(secret, Receipt().to_json())

    def test_own_shadow_tokens_are_ignored(self):
        transport = MockTransport()
        result, _ = send(observation_with("Call [REDACTED:PHONE#1|domain_class=public]"), "review", [], transport)
        self.assertTrue(result.allowed)
        self.assertEqual(len(transport.captured), 1)


if __name__ == "__main__": unittest.main()
