import unittest
from html.parser import HTMLParser
from privacylens.contracts import Element
from privacylens.detect.patterns import scan_text
from privacylens.detect.structural import scan_elements

class ElementParser(HTMLParser):
    def __init__(self): super().__init__(); self.items=[]
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag in ("input", "a", "img", "button", "textarea"):
            self.items.append(Element(tag=tag, attributes=attrs, selector="#"+attrs.get("id", ""), bounds=(0,0,1,1)))

class DetectionTests(unittest.TestCase):
    def test_zero_width_obfuscation_and_original_spans(self):
        source = "mail: priv\u200bacy@example.test"
        findings = scan_text(source)
        self.assertEqual(findings[0].kind, "EMAIL")
        self.assertEqual(source[findings[0].metadata["start"]:findings[0].metadata["end"]], "priv\u200bacy@example.test")
        self.assertEqual(scan_text("4111\u200b1111\u200b1111\u11111111"), [])
        self.assertEqual(scan_text("4111\u200b1111\u200b1111\u200b1111")[0].kind, "CARD")

    def test_nfkc_fullwidth_digits_keep_original_spans(self):
        source = "card：４１１１１１１１１１１１１１１１"
        finding = next(f for f in scan_text(source) if f.kind == "CARD")
        self.assertEqual(finding.value, "４１１１１１１１１１１１１１１１")
        self.assertEqual(source[finding.metadata["start"]:finding.metadata["end"]], finding.value)

    def test_expiry_requires_valid_context_and_rejects_date_time_forms(self):
        for sample in ("2026-10-29", "12/25/2026", "10:15:30", "1.2.3.4"):
            self.assertNotIn("EXPIRY", {f.kind for f in scan_text(sample)}, sample)
        self.assertIn("EXPIRY", {f.kind for f in scan_text("expiry 10/29")})
        self.assertIn("EXPIRY", {f.kind for f in scan_text("10-29", {"name": "expiry_date"})})

    def test_name_and_address_autocomplete_and_heuristics(self):
        elems = [Element("input", attributes={"id": "given", "autocomplete": "given-name"}),
                 Element("input", attributes={"name": "street-address"}),
                 Element("input", attributes={"id": "postal", "autocomplete": "postal-code"}),
                 Element("input", attributes={"label": "Full name"})]
        found = scan_elements(elems)
        self.assertGreaterEqual(sum(f.kind == "NAME" for f in found), 2)
        self.assertGreaterEqual(sum(f.kind == "ADDRESS" for f in found), 2)

    def test_ip_in_version_context_is_not_flagged(self):
        for text in ("Version 1.2.3.4 released", "ver 1.2.3.4", "v1.2.3.4", "release 1.2.3.4", "build 1.2.3.4"):
            self.assertNotIn("IP", {f.kind for f in scan_text(text)}, text)
        self.assertIn("IP", {f.kind for f in scan_text("server 1.2.3.4")})

    def test_structural_sensitive_fields_and_content(self):
        elems = [Element("input", attributes={"type":"password", "id":"pw"}),
                 Element("input", attributes={"autocomplete":"cc-number", "id":"card"}),
                 Element("input", attributes={"autocomplete":"one-time-code", "id":"otp"}),
                 Element("a", attributes={"href":"mailto:alice@example.test", "title":"contact"})]
        found=scan_elements(elems)
        self.assertTrue(any(f.kind=="SECRET" and f.metadata["element_id"]=="pw" for f in found))
        self.assertTrue(any(f.kind=="CARD" and f.metadata["element_id"]=="card" for f in found))
        self.assertTrue(any(f.kind=="OTP" and f.metadata["element_id"]=="otp" for f in found))
        self.assertTrue(any(f.kind=="EMAIL" and f.metadata["element_id"]=="element-3" for f in found))

    def test_split_card_fields_flag_all_four(self):
        elems=[Element("input", attributes={"id":f"cc{i}","name":f"card_number_{i}","maxlength":"4"}) for i in range(4)]
        flags=[f for f in scan_elements(elems) if f.kind=="CARD" and f.metadata.get("split_card")]
        self.assertEqual({f.metadata["element_id"] for f in flags}, {"cc0","cc1","cc2","cc3"})

    def test_html_parser_compatibility(self):
        parser=ElementParser(); parser.feed('<input id="x" type="email" value="a@b.test">')
        self.assertEqual(len(parser.items), 1)
        self.assertTrue(scan_elements(parser.items))

if __name__ == "__main__": unittest.main()
