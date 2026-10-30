import base64
import unittest
from urllib.parse import quote

from privacylens.gate.canary import CanaryRegistry


class CanaryTests(unittest.TestCase):
    def test_all_requested_variants_and_label_only_matches(self):
        value = "Card 4111-1111-1111-1111"
        registry = CanaryRegistry(); registry.register(value, "seed-card")
        variants = registry.variants(value)
        self.assertIn(value, variants)
        self.assertIn("card4111111111111111", variants)
        self.assertIn(quote(value, safe=""), variants)
        self.assertIn(value.encode().hex(), variants)
        standard = base64.b64encode(value.encode()).decode()
        urlsafe = base64.urlsafe_b64encode(value.encode()).decode()
        for encoded in (standard, standard.rstrip("="), urlsafe, urlsafe.rstrip("=")):
            self.assertIn(encoded, variants)
        self.assertEqual(registry.find(("payload=" + quote(value, safe="")).encode()), ["seed-card"])
        self.assertNotIn(value, repr(registry))

    def test_zero_width_and_digits_only(self):
        registry = CanaryRegistry()
        registry.register("4111111111111111", "card")
        self.assertEqual(registry.find("4111\u200b1111\u200b1111\u200b1111".encode()), ["card"])


if __name__ == "__main__": unittest.main()
