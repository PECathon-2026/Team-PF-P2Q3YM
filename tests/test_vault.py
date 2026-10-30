import pickle
import unittest

from privacylens.contracts import Element
from privacylens.sanitize.vault import Vault, VaultError


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.vault = Vault()
        self.secret = "4111111111111111"
        self.ref = self.vault.add(self.secret, "CARD", ("https://shop.example.test",), needs_approval=False)
        self.cc = Element("input", attributes={"id": "card", "autocomplete": "cc-number", "type": "text"})

    def test_card_only_allowed_in_cc_number_on_exact_origin(self):
        chat = Element("textarea", attributes={"name": "chat"})
        allowed, reason = self.vault.verify_injection_safety(self.ref, chat, "https://shop.example.test/pay")
        self.assertFalse(allowed)
        self.assertIn("textarea", reason)
        with self.assertRaises(VaultError): self.vault.get(self.ref, chat, "https://shop.example.test/pay")
        lookalike = "https://shop.example.test.evil.com/pay"
        self.assertFalse(self.vault.verify_injection_safety(self.ref, self.cc, lookalike)[0])
        with self.assertRaises(VaultError): self.vault.get(self.ref, self.cc, lookalike)
        self.assertEqual(self.vault.verify_injection_safety(self.ref, self.cc, "https://shop.example.test/pay"), (True, "allowed_by_local_policy"))
        self.assertEqual(self.vault.get(self.ref, self.cc, "https://shop.example.test/pay"), self.secret)

    def test_chat_search_disabled_hidden_and_approval_are_rejected(self):
        ref = self.vault.add(self.secret, "CARD", ("https://shop.example.test",))
        self.assertEqual(self.vault.verify_injection_safety(ref, self.cc, "https://shop.example.test"), (False, "approval_required"))
        self.vault.approve(ref)
        for element in (
            Element("input", attributes={"autocomplete": "cc-number", "role": "searchbox"}),
            Element("input", attributes={"autocomplete": "cc-number", "type": "search"}),
            Element("input", attributes={"autocomplete": "cc-number", "name": "chat_card"}),
            Element("input", attributes={"autocomplete": "cc-number", "disabled": ""}),
            Element("input", attributes={"autocomplete": "cc-number", "hidden": ""}),
        ):
            with self.subTest(element=element.tag, attrs=element.attributes):
                self.assertFalse(self.vault.verify_injection_safety(ref, element, "https://shop.example.test")[0])

    def test_max_uses_is_enforced(self):
        ref = self.vault.add(self.secret, "CARD", ("https://shop.example.test",), max_uses=1, needs_approval=False)
        self.assertEqual(self.vault.get(ref, self.cc, "https://shop.example.test"), self.secret)
        self.assertFalse(self.vault.verify_injection_safety(ref, self.cc, "https://shop.example.test")[0])
        with self.assertRaises(VaultError): self.vault.get(ref, self.cc, "https://shop.example.test")

    def test_repr_and_serialization_never_expose_values(self):
        self.assertTrue(self.ref.startswith("VAULT://card_"))
        self.assertNotIn(self.secret, repr(self.vault)); self.assertNotIn(self.secret, str(self.vault))
        with self.assertRaises(TypeError): pickle.dumps(self.vault)
        with self.assertRaises(TypeError): self.vault.__getstate__()


if __name__ == "__main__": unittest.main()
