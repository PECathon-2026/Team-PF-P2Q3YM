"""Bounded, privacy-gated agent loop."""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlsplit

from ..contracts import Action, RunReport
from ..gate.canary import CanaryRegistry
from ..gate.egress import send as gate_send
from ..sanitize.rules import Rules
from ..sanitize.sanitize import sanitize
from ..detect.structural import scan_elements
from .actions import parse_action, validate
from .approval import AutoDeny
from .browser import StaleTargetError


def _secret_map(task, origin):
    path = Path(__file__).resolve().parents[2] / "config" / "demo_secrets.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get(task, [])


def run(task, start_url, config):
    browser, vault, llm = config["browser"], config["vault"], config["llm"]
    origin = f"{urlsplit(start_url).scheme}://{urlsplit(start_url).netloc}"
    rules = config.get("rules", Rules(allowed_origins=(origin,)))
    if origin not in rules.allowed_origins:
        rules = Rules(allowed_origins=tuple(rules.allowed_origins) + (origin,), block_types=rules.block_types,
                      keep_context=rules.keep_context, max_findings_logged=rules.max_findings_logged,
                      minimize=True, task_keywords=(task,))
    secret_entries = config.get("secrets", _secret_map(task, origin))
    refs = {item["id"]: vault.add(item["value"], item["kind"], (origin,), needs_approval=True) for item in secret_entries}
    registry = config.get("registry") or CanaryRegistry()
    for item in secret_entries:
        registry.register(item["value"], item["id"])
    timings = {key: 0.0 for key in ("snapshot", "detect", "sanitize", "gate", "llm", "execute")}
    history, actions, rejections, approvals, blocks = [], [], [], [], []
    success = False; malformed_retry = False; previous = None; repeats = 0; hidden_total = 0
    captured = []; captured_leak = False
    bus=config.get("event_bus")
    max_steps = min(15, int(config.get("max_steps", 15)))
    if browser.page.url != start_url: browser.navigate(start_url)
    for step in range(max_steps):
        start = time.perf_counter(); snapshot = browser.snapshot(); timings["snapshot"] += time.perf_counter()-start
        hidden_total = max(hidden_total, int(snapshot.metadata.get("hidden_count", 0)))
        start=time.perf_counter(); scan_elements(list(snapshot.elements)); timings["detect"] += time.perf_counter()-start
        start = time.perf_counter()
        observation = sanitize(snapshot, None, rules, task_keywords=(task,), full_page=False)
        timings["sanitize"] += time.perf_counter()-start
        if bus:
            bus.shots["before"] = observation.snapshot.screenshot
            bus.shots["after"] = observation.snapshot.screenshot
            bus.emit("findings",items=[dict(item) for item in observation.findings])
        safe_elements = []
        for el in observation.snapshot.elements:
            attrs = dict(el.attributes or {})
            actual_id = attrs.get("id")
            if actual_id in refs: attrs["vault_ref"] = refs[actual_id]
            safe_elements.append(type(el)(tag=el.tag,text=el.text,attributes=attrs,selector=el.selector,bounds=el.bounds,metadata=el.metadata))
        safe_snap = type(observation.snapshot)(url=observation.snapshot.url,title=observation.snapshot.title,elements=tuple(safe_elements),screenshot=observation.snapshot.screenshot,timestamp=observation.snapshot.timestamp,metadata=observation.snapshot.metadata)
        observation = type(observation)(snapshot=safe_snap,findings=observation.findings,redactions=observation.redactions,metadata=observation.metadata)
        timings["detect"] += 0.0
        llm_before=timings["llm"]
        def model_transport(_payload):
            nonlocal captured_leak
            captured.append(_payload)
            for entry in secret_entries:
                if entry["value"].encode("utf-8") in _payload: captured_leak=True
            if registry.find(_payload): captured_leak=True
            llm_start=time.perf_counter()
            response=llm(observation, task, tuple(history), tuple(refs.values()))
            timings["llm"] += time.perf_counter()-llm_start
            return response
        start = time.perf_counter()
        gate_result, response = gate_send(observation, {"name":task,"instruction":config.get("instruction", task)}, history,
                                          model_transport, registry=registry, vault=vault)
        timings["gate"] += max(0.0,time.perf_counter()-start-(timings["llm"]-llm_before))
        if not gate_result.allowed:
            blocks.append(gate_result.metadata.get("reasons", []))
            if bus: bus.emit("gate",verdict="BLOCKED",reasons=gate_result.metadata.get("reasons",[]))
            break
        if bus: bus.emit("gate",verdict="ALLOWED")
        try: action = parse_action(response)
        except ValueError:
            if malformed_retry: rejections.append("malformed_json_retry_exhausted"); break
            malformed_retry=True
            continue
        ok, reason, needs_approval = validate(action, observation.snapshot, vault, rules, browser.page.url)
        if not ok:
            rejections.append(reason)
            history.append({"step":step,"action":action.kind,"target":action.target,"result":"rejected","reason":reason})
            actions.append(Action(action.kind,action.target,None,action.irreversible,{"rejected":True}))
            if bus: bus.emit("validator",verdict="REJECTED",reason=reason,action=action.kind,target=action.target)
            if config.get("hijack") and len(rejections) >= 2: continue
            continue
        if bus: bus.emit("validator",verdict="ALLOWED",action=action.kind,target=action.target)
        if action.kind == "done":
            try: state=browser.goal_state()
            except Exception: state={}
            success = ((task=="login" and state.get("state")=="logged-in") or
                       (task=="support" and state.get("state")=="escalated") or
                       (task=="meet" and state.get("muted")=="true" and state.get("participants")=="open") or
                       (task=="devsettings" and state.get("tab")=="webhooks" and state.get("state")=="token-requested"))
            if not hasattr(browser,"goal_state"):
                done_clicks={e.get("target") for e in history if e.get("action")=="click" and e.get("result")=="executed"}
                success = bool(done_clicks)
            break
        if action.kind == "ask_user":
            approval= config.get("approval")
            prompt="Enter the one-time code locally (it will not be sent to the model):"
            answer=approval.ask_user(prompt) if approval and hasattr(approval,"ask_user") else None
            approvals.append("user_input_requested")
            history.append({"step":step,"action":"ask_user","target":action.target,"result":"provided" if answer else "requested"})
            if not answer: break
            target=next((e for e in observation.snapshot.elements if action.target in (e.selector,e.attributes.get("id"),e.attributes.get("data-pl-id"))),None)
            if target is None or target.tag=="textarea" or target.attributes.get("autocomplete")!="one-time-code":
                rejections.append("user_input_target_not_otp"); break
            if len(answer)>8 or not answer.isdigit(): rejections.append("invalid_user_otp"); break
            browser.type(action.target,answer)
            continue
        if action.kind in ("click", "type", "select") and needs_approval:
            el = next(e for e in observation.snapshot.elements if action.target in (e.selector,e.attributes.get("data-pl-id"),e.attributes.get("id")))
            desc = action.kind + " on " + (el.attributes.get("label") or el.text or el.attributes.get("role", "control"))[:60]
            desc = " ".join(desc.split())
            approvals.append("approval_requested")
            approval = config.get("approval", AutoDeny())
            if bus: bus.emit("action",action=action.kind,target=action.target)
            if not approval.approve(desc,timeout=30):
                rejections.append("approval_denied"); history.append({"step":step,"action":action.kind,"target":action.target,"result":"denied"}); break
            ref = action.metadata.get("secret_ref")
            if ref: vault.approve(ref)
            # Checkout task intentionally pauses at Pay after displaying the approval request.
            if task == "checkout" and action.kind == "click" and "pay" in desc.casefold():
                success = bool(config.get("filled_ids", set()) >= set(refs))
                history.append({"step":step,"action":"click","target":action.target,"result":"approval_requested_stop"})
                actions.append(Action(action.kind,action.target,None,action.irreversible,{"approval_requested":True})); break
        start = time.perf_counter()
        try:
            ref = action.metadata.get("secret_ref")
            value = vault.get(ref, next(e for e in observation.snapshot.elements if action.target in (e.selector,e.attributes.get("data-pl-id"),e.attributes.get("id"))), browser.page.url) if ref else action.value
            if action.kind == "click": browser.click(action.target)
            elif action.kind == "type": browser.type(action.target, value or "")
            elif action.kind == "select": browser.select(action.target, value or "")
            elif action.kind == "scroll": browser.scroll(action.target)
            elif action.kind == "navigate": browser.navigate(action.value)
            elif action.kind == "wait": browser.wait()
        except StaleTargetError:
            rejections.append("stale_target"); continue
        finally: timings["execute"] += time.perf_counter()-start
        if action.metadata.get("secret_ref"):
            if not hasattr(browser,"verify_value") or not browser.verify_value(action.target,value):
                rejections.append("local_value_verification_failed"); continue
            filled = set(config.get("filled_ids", set()))
            filled.add(next((key for key,value in refs.items() if value==ref), ""))
            config["filled_ids"] = filled
        signature=(action.kind,action.target,action.value,action.metadata.get("secret_ref"))
        repeats = repeats+1 if signature==previous else 0; previous=signature
        history.append({"step":step,"action":action.kind,"target":action.target,"secret_ref":action.metadata.get("secret_ref"),"result":"executed"})
        if bus: bus.emit("action",action=action.kind,target=action.target)
        actions.append(Action(action.kind,action.target,None,action.irreversible,{"secret_ref":action.metadata.get("secret_ref")} if action.metadata.get("secret_ref") else {}))
        if repeats >= 2: rejections.append("repeated_action_limit"); break
    rejection_reasons = ",".join(rejections) if rejections else "none"
    local_verification = "passed" if task == "checkout" and success else "not_complete"
    leak_status = "present" if captured_leak else "none"
    summary = (f"steps={len(history)} rejections={len(rejections)} rejection_reasons={rejection_reasons} "
               f"approvals={len(approvals)} gate_blocks={len(blocks)} success={str(success).lower()} "
               f"local_verification={local_verification} seeded_leak={str(captured_leak).lower()} "
               f"seeded_value_or_canary_in_captured_bytes={leak_status}")
    return RunReport(actions=tuple(actions),findings=(),status="success" if success else "stopped",summary=summary,
                     metadata={"steps":len(history),"timings":timings,"blocked_events":tuple(blocks),"rejections":tuple(rejections),
                               "approvals":tuple(approvals),"success":success,"hidden_count":hidden_total,"seeded_value_or_canary_in_captured_bytes":captured_leak})
