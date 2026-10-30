import pickle
import unittest

from privacylens.sanitize.rules import Rules
from privacylens.sanitize.tokens import SessionTokenizer


class SessionTokenizerTests(unittest.TestCase):
    def test_normalized_phone_values_share_per_kind_index(self):
        tokenizer = SessionTokenizer()
        first = tokenizer.tokenize("+91 987-654-3210", "PHONE")
        same = tokenizer.tokenize("9876543210", "PHONE")
        second = tokenizer.tokenize("+91 912-345-6780", "PHONE")
        self.assertEqual(first, "[REDACTED:PHONE#1]")
        self.assertEqual(same, first)
        self.assertEqual(second, "[REDACTED:PHONE#2]")
        self.assertEqual(SessionTokenizer().tokenize("9876543210", "PHONE"), "[REDACTED:PHONE#1]")

    def test_traits_are_off_by_default(self):
        tokenizer = SessionTokenizer(Rules())
        self.assertEqual(tokenizer.tokenize("4111111111111111", "CARD"), "[REDACTED:CARD#1]")
        self.assertEqual(tokenizer.tokenize("User@gmail.com", "EMAIL"), "[REDACTED:EMAIL#1]")

    def test_optional_traits_and_forbidden_traits(self):
        rules = Rules(keep_context={"CARD": "network", "EMAIL": "domain_class", "SECRET": "network", "OTP": "network"})
        tokenizer = SessionTokenizer(rules)
        self.assertEqual(tokenizer.tokenize("4111111111111111", "CARD"), "[REDACTED:CARD#1|network=VISA]")
        self.assertEqual(tokenizer.tokenize("person@gmail.com", "EMAIL"), "[REDACTED:EMAIL#1|domain_class=public]")
        self.assertEqual(tokenizer.tokenize("api-token-98765", "SECRET"), "[REDACTED:SECRET#1]")
        self.assertEqual(tokenizer.tokenize("123456", "OTP"), "[REDACTED:OTP#1]")
        for kind, raw in (("PASSWORD", "1111"), ("OTP", "123456"), ("SECRET", "AKIA0000000000000000"),
                          ("AADHAAR", "234567890123"), ("PAN", "ABCPA1234Z"), ("CVV", "321")):
            token = tokenizer.tokenize(raw, kind)
            self.assertNotIn("|", token, kind)
            self.assertNotIn(raw, token, kind)

    def test_not_picklable_and_repr_does_not_show_values(self):
        raw = "private-token-value-8877"
        tokenizer = SessionTokenizer(); tokenizer.tokenize(raw, "SECRET")
        self.assertNotIn(raw, repr(tokenizer))
        with self.assertRaises(TypeError): pickle.dumps(tokenizer)


if __name__ == "__main__": unittest.main()
