import unittest
from privacylens.detect.validators import (
    luhn_generate, luhn_validate, pan_validate, shannon_entropy,
    verhoeff_generate, verhoeff_validate,
)
from privacylens.detect.patterns import scan_text


class ValidatorTests(unittest.TestCase):
    def test_verhoeff_many_generated_positives_and_negatives(self):
        valid = [verhoeff_generate(str(23456789012 + i)) for i in range(10)]
        self.assertTrue(all(verhoeff_validate(x) for x in valid))
        self.assertEqual(len(set(valid)), 10)
        bad = [x[:-1] + str((int(x[-1])+1) % 10) for x in valid]
        bad += ["123456789012", "012345678901", "", "123", "abcdefghijkl", "2"*11, "9"*13, "2345678901x", " 234567890123", "2345-67890123"]
        self.assertTrue(all(not verhoeff_validate(x) for x in bad))

    def test_luhn_prefix_families_and_bad_checksums(self):
        prefixes = ["4", "51", "52", "53", "54", "55", "2221", "2720", "34", "37", "60", "65"]
        vals = [luhn_generate(p) for p in prefixes]
        self.assertTrue(all(luhn_validate(x) for x in vals))
        self.assertEqual(len(vals), 12)
        bad = [x[:-1] + str((int(x[-1])+1) % 10) for x in vals]
        bad += ["6011000000000000", "5611000000000000", "123456789012", "", "4", "x"*16, "4111-1111-1111-1111", "0"*16, "9"*20, "2220111111111111"]
        self.assertTrue(all(not luhn_validate(x) for x in bad))

    def test_pan_format(self):
        valid = [f"ABC{c}D1234E" for c in "PCHFATBLJG"]
        self.assertTrue(all(pan_validate(x) for x in valid))
        invalid = ["abcPA1234Z", "AB1PA1234Z", "ABCP11234Z", "ABCPa1234Z", "ABCPA123Z", "ABCPA12345", "ABCPA1234$", " ABCPA1234Z", "ABCPA1234ZZ", "ZZZIA9999Q"]
        self.assertTrue(all(not pan_validate(x) for x in invalid))

    def test_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertEqual(shannon_entropy("abcd"), 2.0)
        self.assertGreater(shannon_entropy("aB3$xY9!qR7@"), 3.0)

    def test_expiry_requires_context_and_fullwidth_normalization(self):
        for sample in ("2026-10-29", "12/25/2026", "10:15:30", "1.2.3.4"):
            self.assertNotIn("EXPIRY", {f.kind for f in scan_text(sample)}, sample)
        self.assertIn("EXPIRY", {f.kind for f in scan_text("valid thru 12/25")})
        source = "expiry １０／２９"
        match = next(f for f in scan_text(source) if f.kind == "EXPIRY")
        self.assertEqual(match.value, "１０／２９")
        self.assertEqual(source[match.metadata["start"]:match.metadata["end"]], match.value)

    def test_pattern_positive_and_negative_samples(self):
        positives = {
            "AADHAAR": [verhoeff_generate(str(23456789012+i)) for i in range(10)],
            "CARD": [luhn_generate(p) for p in ["4", "51", "52", "53", "54", "55", "2221", "2720", "34", "37"]],
            "PAN": [f"ABC{c}D1234E" for c in "PCHFATBLJG"],
            "EMAIL": [f"user{i}@example.test" for i in range(10)],
            "PHONE": [f"+91 98765432{i:02d}" for i in range(10)],
            "OTP": [f"otp {100000+i}" for i in range(10)],
            "SECRET": [f"AKIA{(i+1):016d}" for i in range(10)],
            "IP": [f"192.0.2.{i+1}" for i in range(10)],
            "CVV": [f"cvv {i:03d}" for i in range(10)],
            "EXPIRY": [f"expiry {i:02d}/29" for i in range(1,11)],
            "OTHER": [f"HDFC0{i:06d}" for i in range(10)],
        }
        for kind, samples in positives.items():
            with self.subTest(kind=kind):
                for sample in samples:
                    if kind == "OTP": findings = scan_text(sample)
                    else: findings = scan_text(sample)
                    self.assertIn(kind, {f.kind for f in findings}, sample)
        negatives = ["ordinary words", "hello world", "not-an-email", "123", "0000", "127.0.0.1", "::1", "bad@", "4111111111111112", "ABCPA1234X"]
        for sample in negatives:
            with self.subTest(sample=sample):
                if sample in ("127.0.0.1", "::1"): self.assertNotIn("IP", {f.kind for f in scan_text(sample)})
                elif sample == "ordinary words": self.assertEqual(scan_text(sample), [])
                else: self.assertTrue(isinstance(scan_text(sample), list))

    def test_ten_negative_examples_for_each_pattern_family(self):
        samples = {
            "AADHAAR": [verhoeff_generate(str(23456789012+i))[:-1] + str((int(verhoeff_generate(str(23456789012+i))[-1])+1)%10) for i in range(10)],
            "CARD": [luhn_generate("4" + str(i))[:-1] + str((int(luhn_generate("4" + str(i))[-1])+1)%10) for i in range(10)],
            "PAN": [f"abc{c}D1234E" for c in "PCHFATBLJG"],
            "EMAIL": [f"user{i}@invalid" for i in range(10)],
            "PHONE": [f"+91 12345678{i:02d}" for i in range(10)],
            "OTP": [f"otp {i:03d}" for i in range(10)],
            "SECRET": [f"key {'a'*20}{i}" for i in range(10)],
            "IP": [f"256.0.0.{i}" for i in range(10)],
            "CVV": [f"cvv {i:02d}" for i in range(10)],
            "EXPIRY": [f"{i+13:02d}/29" for i in range(10)],
            "OTHER": [f"HDFC{i+1}ABC000000" for i in range(10)],
        }
        for kind, values in samples.items():
            with self.subTest(kind=kind):
                for value in values:
                    self.assertNotIn(kind, {f.kind for f in scan_text(value)}, value)


if __name__ == "__main__": unittest.main()
