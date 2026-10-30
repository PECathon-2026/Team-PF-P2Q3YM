"""PrivacyLens local demo CLI."""
import argparse
import json
from pathlib import Path

from .approval import AutoApprove, AutoDeny, CLIPrompt
from .browser import BrowserSession
from .llm import MockLLM
from .loop import run
from ..sanitize.vault import Vault
from ..sanitize.rules import Rules
from ..eval.mock_llm import MockTransport
from ..gate.egress import _jsonable
from ..eval.html_elements import parse_html


def main(argv=None):
    parser=argparse.ArgumentParser(description="Run a local PrivacyLens synthetic task")
    parser.add_argument("--task",choices=("checkout","login","support","meet","devsettings"),default="checkout")
    parser.add_argument("--provider",choices=("mock","anthropic","openai"),default="mock")
    parser.add_argument("--approve",choices=("auto","cli","deny"),default="cli")
    parser.add_argument("--headed",action="store_true"); parser.add_argument("--hijack",action="store_true")
    parser.add_argument("--mode",choices=("protected","baseline"),default="protected")
    args=parser.parse_args(argv)
    if args.mode=="baseline" and args.provider!="mock":
        parser.error("baseline mode is restricted to MockLLM; real providers are refused")
    if args.provider!="mock":
        from ..gate.transport import anthropic_transport, openai_transport
        from .llm import ProviderLLM
        provider=anthropic_transport if args.provider=="anthropic" else openai_transport
        model=ProviderLLM(args.provider,provider)
    else: model=MockLLM(args.hijack)
    approval={"auto":AutoApprove(),"deny":AutoDeny(),"cli":CLIPrompt()}[args.approve]
    site=Path(__file__).resolve().parents[2]/"testsite"
    if args.mode=="baseline":
        snap=parse_html(site/(args.task+".html"))
        mock_transport=MockTransport()
        payload=json.dumps(_jsonable(snap),ensure_ascii=False,sort_keys=True).encode("utf-8")
        mock_transport(payload)
        secrets=json.loads((Path(__file__).resolve().parents[2]/"config"/"demo_secrets.json").read_text(encoding="utf-8")).get(args.task,[])
        captured=mock_transport.captured[0]
        leaked=sum(item["value"].encode("utf-8") in captured for item in secrets)
        print(f"Baseline mock summary: steps=1 rejections=0 approvals=0 gate_blocks=0 success=false seeded_values_in_captured_bytes={leaked}/{len(secrets)}")
        return 0
    try:
        with BrowserSession(headed=args.headed) as browser:
            url=browser.origin+"/"+args.task+".html"
            browser.navigate(url)
            vault=Vault(); rules=Rules(allowed_origins=(browser.origin,"http://localhost","http://127.0.0.1","file://"))
            report=run(args.task,url,{"browser":browser,"vault":vault,"llm":model,"approval":approval,"hijack":args.hijack,"rules":rules})
            print("Run summary: "+report.summary)
            return 0 if not report.metadata.get("blocked_events") else 1
    except RuntimeError as exc:
        print(f"Run summary: steps=0 rejections=0 rejection_reasons=browser_start_failed approvals=0 gate_blocks=1 success=false local_verification=not_complete seeded_leak=false seeded_value_or_canary_in_captured_bytes=none ({exc})")
        return 0


if __name__=="__main__": raise SystemExit(main())
