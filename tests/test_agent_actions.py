import json
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from privacylens.agent.actions import parse_action, validate
from privacylens.agent.approval import AutoApprove, AutoDeny, CLIPrompt
from privacylens.contracts import Element, Snapshot
from privacylens.sanitize.rules import Rules
from privacylens.sanitize.vault import Vault


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.rules=Rules(allowed_origins=("http://localhost:8123",))
        self.button=Element(tag="button",text="Pay",attributes={"id":"pay","type":"submit","visible":"true","enabled":"true"},selector="#pay")
        self.textbox=Element(tag="input",attributes={"id":"email","type":"email","name":"email","autocomplete":"email","visible":"true","enabled":"true"},selector="#email")
        self.snapshot=Snapshot(url="http://localhost:8123/",elements=(self.button,self.textbox))
        self.vault=Vault()

    def test_strict_json_rejections(self):
        for raw in ("{", json.dumps({"action":"click","extra":"x"}), json.dumps({"action":"dance"}),
                    json.dumps({"action":"type","target":"x","text":"a"*201}),
                    json.dumps({"action":"type","target":"x","text":"hi","secret_ref":"VAULT://email_1"}),
                    json.dumps({"action":"type","target":"x","secret_ref":"plain"})):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError): parse_action(raw)

    def test_target_sensitive_text_and_navigation_rejections(self):
        cases=[('{"action":"click","target":"missing"}',"unknown_target"),
               ('{"action":"navigate","text":"https://localhost.example/"}',"navigation_origin_not_allowed"),
               ('{"action":"navigate","text":"https://evil.example/"}',"navigation_origin_not_allowed"),
               ('{"action":"type","target":"email","text":"4111111111111111"}',"typed_text_sensitive"),
               ('{"action":"type","target":"email","text":"[REDACTED:CARD#1]"}',"typed_text_contains_shadow_token")]
        for raw, reason in cases:
            ok, actual, _=validate(parse_action(raw),self.snapshot,self.vault,self.rules,self.snapshot.url)
            self.assertFalse(ok); self.assertEqual(actual,reason)

    def test_local_selector_resolves_when_html_id_is_also_present(self):
        element=Element("button",text="Continue",attributes={"id":"checkout-next"},selector="e7")
        snapshot=Snapshot(url=self.snapshot.url,elements=(element,))
        action=parse_action('{"action":"click","target":"e7"}')
        self.assertEqual(validate(action,snapshot,self.vault,self.rules,self.snapshot.url),(True,"allowed",False))

    def test_literal_canary_and_malformed_local_origins_are_rejected(self):
        self.vault.add("violet meadow amber demo", "SECRET", ("http://localhost:8123",), needs_approval=False)
        action=parse_action('{"action":"type","target":"email","text":"violet meadow amber demo"}')
        ok,reason,_=validate(action,self.snapshot,self.vault,self.rules,self.snapshot.url)
        self.assertFalse(ok); self.assertEqual(reason,"typed_text_contains_canary")
        for url in ("http://localhost:0/", "http://localhost.example:8123/"):
            action=parse_action(json.dumps({"action":"navigate","text":url}))
            ok,reason,_=validate(action,self.snapshot,self.vault,self.rules,self.snapshot.url)
            self.assertFalse(ok); self.assertEqual(reason,"navigation_origin_not_allowed")

    def test_hidden_disabled_and_secret_origin_policy(self):
        hidden=Element(tag="button",attributes={"id":"hidden","hidden":""},selector="#hidden")
        disabled=Element(tag="button",attributes={"id":"disabled","disabled":""},selector="#disabled")
        snap=Snapshot(elements=(hidden,disabled,self.textbox),url=self.snapshot.url)
        for target,reason in (("hidden","target_hidden"),("disabled","target_disabled")):
            ok,actual,_=validate(parse_action(json.dumps({"action":"click","target":target})),snap,self.vault,self.rules,snap.url)
            self.assertFalse(ok); self.assertEqual(actual,reason)
        ref=self.vault.add("person@example.test","EMAIL",("http://localhost:8123",),needs_approval=False)
        action=parse_action(json.dumps({"action":"type","target":"email","secret_ref":ref}))
        ok,_,approval=validate(action,self.snapshot,self.vault,self.rules,"http://localhost:8123/")
        self.assertTrue(ok); self.assertTrue(approval)
        ok,reason,_=validate(action,self.snapshot,self.vault,self.rules,"http://localhost:8124/")
        self.assertFalse(ok); self.assertEqual(reason,"origin_mismatch")

    def test_approval_triggers_and_default_cli_deny(self):
        for index,label in enumerate(("Pay","Submit","Place order","Buy","Confirm","Delete","Send","Rotate","Revoke","Generate token")):
            element=Element(tag="button",text=label,attributes={"id":f"trigger-{index}"},selector=f"#trigger-{index}")
            snap=Snapshot(url=self.snapshot.url,elements=(element,))
            action=parse_action(json.dumps({"action":"click","target":f"trigger-{index}"}))
            self.assertTrue(validate(action,snap,self.vault,self.rules,self.snapshot.url)[2],label)
        submit=Element(tag="button",text="Continue",attributes={"id":"submit","type":"submit"},selector="#submit")
        self.assertTrue(validate(parse_action('{"action":"click","target":"submit"}'),Snapshot(url=self.snapshot.url,elements=(submit,)),self.vault,self.rules,self.snapshot.url)[2])
        with patch("builtins.input", side_effect=EOFError): self.assertFalse(CLIPrompt().approve("click Pay"))
        self.assertTrue(AutoApprove().approve("click Pay")); self.assertFalse(AutoDeny().approve("click Pay"))


if __name__=="__main__": unittest.main()
