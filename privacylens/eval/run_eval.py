"""Reproducible, seven-criterion PrivacyLens evaluation."""
from __future__ import annotations

import argparse
import base64
import json
import platform
import random
import statistics
import subprocess
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from unittest.mock import patch

from ..contracts import Element, SanitizedObservation, Snapshot
from ..detect.patterns import scan_text
from ..detect.structural import scan_elements
from ..eval.gen_data import PAGES, ROOT, generate
from ..eval.html_elements import parse_html
from ..eval.mock_llm import MockTransport
from ..gate.canary import CanaryRegistry
from ..gate.egress import MAX_PAYLOAD_BYTES, _jsonable, send
from ..sanitize.rules import load_rules
from ..sanitize.sanitize import sanitize
from ..sanitize.vault import Vault

_ANNOTATED: dict[str, dict[str, tuple[str, ...]]] = {
    "checkout": {
        "checkout-card-number": ("CARD",), "checkout-cvv": ("CVV",), "checkout-expiry": ("EXPIRY",),
        "checkout-shipping-address": ("ADDRESS",), "checkout-customer-name": ("NAME",),
        "checkout-customer-phone": ("PHONE",),
        "checkout-card-part-1": ("CARD",), "checkout-card-part-2": ("CARD",),
        "checkout-card-part-3": ("CARD",), "checkout-card-part-4": ("CARD",),
    },
    "login": {
        "login-email": ("EMAIL",), "login-password": ("PASSWORD", "SECRET"),
        "login-otp": ("OTP",), "login-recovery-phone": ("PHONE",),
    },
    "support": {
        "support-customer-phone-1": ("PHONE",), "support-customer-phone-2": ("PHONE",),
        "support-private-message": ("NAME", "AADHAAR"),
    },
    "meet": {
        "meet-participant-1-name": ("NAME",), "meet-participant-1-email": ("EMAIL",),
        "meet-participant-2-name": ("NAME",), "meet-participant-2-email": ("EMAIL",),
    },
    "devsettings": {
        "dev-akia-key": ("SECRET",), "dev-ghp-key": ("SECRET",), "dev-sk-key": ("SECRET",),
        "dev-jwt": ("SECRET",), "dev-webhook-secret": ("SECRET",),
        "dev-ipv4": ("IP",), "dev-ipv6": ("IP",),
    },
}
_SENSITIVE_KINDS = ("ADDRESS", "AADHAAR", "CARD", "CVV", "EMAIL", "EXPIRY", "IP",
                    "NAME", "OTP", "PASSWORD", "PHONE", "SECRET")
_CONTEXT_KEYS = ("title", "interactive_count", "input_count", "button_count", "input_names",
                 "control_ids", "button_labels", "first_input_type")
_ROOT = Path(__file__).resolve().parents[2]
_EVAL_DIR = _ROOT / "eval"


def _ratio(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else 1.0


def _element_id(element, index):
    return str(element.attributes.get("id") or element.selector or f"element-{index}")


def _parsed_metrics(snapshot, page):
    findings = scan_elements(list(snapshot.elements))
    expected = {(element_id, kind) for element_id, kinds in _ANNOTATED[page].items() for kind in kinds}
    predicted = {(str(item.metadata.get("element_id", "")), item.kind) for item in findings}
    page_rows = []
    per_page = {}
    for kind in _SENSITIVE_KINDS:
        expected_kind = {pair for pair in expected if pair[1] == kind}
        predicted_kind = {pair for pair in predicted if pair[1] == kind}
        if not expected_kind and not predicted_kind:
            continue
        true_positive = len(expected_kind & predicted_kind)
        false_positive = len(predicted_kind - expected_kind)
        false_negative = len(expected_kind - predicted_kind)
        row = {
            "page": page, "type": kind, "expected": len(expected_kind),
            "true_positive": true_positive, "false_positive": false_positive,
            "false_negative": false_negative,
            "recall": _ratio(true_positive, len(expected_kind)),
            "precision": _ratio(true_positive, true_positive + false_positive),
        }
        page_rows.append(row)
        per_page[kind] = row

    decoy_elements = [
        (index, element) for index, element in enumerate(snapshot.elements)
        if "decoy" in str(element.attributes.get("class", "")).casefold()
    ]
    flagged_decoys = sum(bool(scan_elements([element]) or scan_text(element.text)) for _, element in decoy_elements)
    rules = load_rules(_ROOT / "config" / "privacy.json")
    redacted = sanitize(snapshot, None, rules, task_keywords=(page,), full_page=True)
    clean_by_id = {_element_id(element, index): element for index, element in enumerate(redacted.snapshot.elements)}
    original_by_id = {_element_id(element, index): element for index, element in enumerate(snapshot.elements)}
    sensitive_element_ids = set(_ANNOTATED[page])
    redacted_expected = sum(
        element_id in clean_by_id and _element_changed(original_by_id[element_id], clean_by_id[element_id])
        for element_id in sensitive_element_ids
    )
    redacted_false_positive = sum(
        _element_changed(element, clean_by_id.get(element_id, element))
        for element_id, element in original_by_id.items()
        if element_id not in sensitive_element_ids
    )
    return {
        "page": page, "types": page_rows, "flagged_decoys": flagged_decoys,
        "decoy_count": len(decoy_elements),
        "redaction": {
            "sensitive_elements": len(sensitive_element_ids),
            "sensitive_elements_redacted": redacted_expected,
            "non_sensitive_items_redacted": redacted_false_positive,
            "precision": _ratio(redacted_expected, redacted_expected + redacted_false_positive),
        },
    }


def _element_changed(before, after):
    structural_attributes = {"enabled", "filled", "visible"}
    before_attributes = {key: value for key, value in before.attributes.items()
                         if key not in structural_attributes}
    after_attributes = {key: value for key, value in after.attributes.items()
                        if key not in structural_attributes}
    return before.text != after.text or before_attributes != after_attributes


def _leak_metrics(runs, seed):
    rng = random.Random(seed)
    rules = load_rules(_ROOT / "config" / "privacy.json")
    variants_tested = protected_leaks = baseline_leaks = blocked = 0
    variants = []
    for run_index in range(runs):
        canary = f"pl-{run_index}-{rng.getrandbits(64):016x}@canary.test"
        representations = (
            ("raw", canary),
            ("normalized", canary.casefold()),
            ("base64", base64.b64encode(canary.encode()).decode()),
            ("url", quote(canary, safe="")),
            ("hex", canary.encode().hex()),
        )
        for variant_name, value in representations:
            variants_tested += 1
            element = Element("p", text=value, attributes={"id": f"canary-{run_index}-{variant_name}"})
            snapshot = Snapshot(url="file:///", elements=(element,))
            registry = CanaryRegistry()
            registry.register(canary, f"run-{run_index}")

            observation = sanitize(snapshot, None, rules, full_page=True)
            protected_transport = MockTransport()
            gate_result, _ = send(observation, "evaluation", [], protected_transport, registry=registry)
            if gate_result.blocked:
                blocked += 1
            if any(value.encode("utf-8") in payload for payload in protected_transport.captured):
                protected_leaks += 1

            baseline_transport = MockTransport()
            baseline_transport(json.dumps(_jsonable(snapshot), ensure_ascii=False, sort_keys=True).encode("utf-8"))
            if any(value.encode("utf-8") in payload for payload in baseline_transport.captured):
                baseline_leaks += 1
            variants.append({"run": run_index + 1, "variant": variant_name,
                             "protected_leak": bool(protected_transport.captured and
                                                    any(value.encode("utf-8") in payload for payload in protected_transport.captured)),
                             "baseline_leak": any(value.encode("utf-8") in payload for payload in baseline_transport.captured)})
    return {
        "runs": runs, "variants_tested": variants_tested, "protected_leaks": protected_leaks,
        "baseline_leaks": baseline_leaks, "gate_blocks": blocked, "variants": variants,
        "summary": f"{protected_leaks} leaks in {runs} runs on the tested pages and gate pathway",
    }


def _context_answer(snapshot, key):
    elements = list(snapshot.elements)
    controls = [element for element in elements if element.tag.casefold() in
                ("input", "button", "select", "textarea", "a", "summary")]
    inputs = [element for element in controls if element.tag.casefold() == "input"]
    buttons = [element for element in controls if element.tag.casefold() == "button"]
    if key == "title":
        return snapshot.title
    if key == "interactive_count":
        return str(len(controls))
    if key == "input_count":
        return str(len(inputs))
    if key == "button_count":
        return str(len(buttons))
    if key == "input_names":
        return "|".join(str(element.attributes.get("name", "")) for element in inputs)
    if key == "control_ids":
        return "|".join(str(element.attributes.get("id", "")) for element in controls)
    if key == "button_labels":
        return "|".join(str(element.text or element.attributes.get("aria-label", "")) for element in buttons)
    if key == "first_input_type":
        if not inputs:
            return ""
        attrs = inputs[0].attributes
        return str(attrs.get("type") or attrs.get("autocomplete") or "")
    raise ValueError(f"unknown context question key: {key}")


def _context_metrics(directory):
    question_path = _EVAL_DIR / "context_questions.json"
    questions = json.loads(question_path.read_text(encoding="utf-8"))
    page_results = []
    raw_total = sanitized_total = preserved = total = 0
    for page in PAGES:
        snapshot = parse_html(directory / f"{page}.html")
        clean = sanitize(snapshot, None, load_rules(_ROOT / "config" / "privacy.json"),
                         task_keywords=(page,), full_page=False).snapshot
        questions_for_page = questions[page]
        raw_answers = sanitized_answers = 0
        for question in questions_for_page:
            raw_answer = _context_answer(snapshot, question["key"])
            clean_answer = _context_answer(clean, question["key"])
            raw_ok = bool(raw_answer)
            clean_ok = bool(clean_answer)
            raw_answers += raw_ok
            sanitized_answers += clean_ok
            preserved += bool(raw_ok and raw_answer == clean_answer)
            total += 1
        raw_total += raw_answers
        sanitized_total += sanitized_answers
        page_results.append({"page": page, "questions": len(questions_for_page),
                             "raw_answered": raw_answers, "sanitized_answered": sanitized_answers})
    return {"pages": page_results, "questions": total, "raw_answered": raw_total,
            "sanitized_answered": sanitized_total, "preserved": preserved,
            "preservation_rate": _ratio(preserved, total)}


def _agent_task_metrics(runs, seed):
    from ..agent.approval import AutoApprove
    from ..agent.browser import BrowserSession
    from ..agent.llm import MockLLM
    from ..agent.loop import run as run_agent
    from ..sanitize.rules import Rules

    rng = random.Random(seed)
    rows = []
    stages: dict[str, list[float]] = {}
    memory_peaks = []
    for task in PAGES:
        task_runs = []
        for run_number in range(runs):
            tracemalloc.start()
            started = time.perf_counter()
            with BrowserSession(_ROOT / "testsite") as browser:
                url = browser.origin + f"/{task}.html"
                browser.navigate(url)
                report = run_agent(task, url, {
                    "browser": browser, "vault": Vault(), "llm": MockLLM(),
                    "approval": AutoApprove(),
                    "rules": Rules(allowed_origins=(browser.origin,)),
                    "max_steps": 15,
                })
            elapsed = time.perf_counter() - started
            _current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            memory_peaks.append(peak)
            for name, duration in report.metadata.get("timings", {}).items():
                stages.setdefault(name, []).append(float(duration) * 1000)
            task_runs.append({
                "run": run_number + 1, "success": bool(report.metadata.get("success")),
                "status": report.status, "steps": report.metadata.get("steps", 0),
                "elapsed_ms": round(elapsed * 1000, 3),
            })
        rows.append({"task": task, "runs": task_runs,
                     "successes": sum(item["success"] for item in task_runs),
                     "success_rate": _ratio(sum(item["success"] for item in task_runs), runs)})
    percentiles = {}
    for name, samples in sorted(stages.items()):
        ordered = sorted(samples)
        percentiles[name] = {
            "samples": len(samples),
            "p50_ms": round(statistics.median(ordered), 3),
            "p95_ms": round(_percentile(ordered, 0.95), 3),
        }
    return {"tasks": rows, "stage_latency": percentiles,
            "peak_memory_bytes_approx": max(memory_peaks, default=0),
            "memory_label": "approximate tracemalloc peak; excludes native browser allocations"}


def _percentile(samples, fraction):
    if len(samples) == 1:
        return samples[0]
    position = (len(samples) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(samples) - 1)
    return samples[lower] + (samples[upper] - samples[lower]) * (position - lower)


def _adversarial_metrics(runs, seed):
    from ..agent.approval import AutoApprove
    from ..agent.browser import BrowserSession
    from ..agent.llm import MockLLM
    from ..agent.loop import run as run_agent
    from ..sanitize.rules import Rules

    directory = Path(__file__).parent / "adversarial"
    fixtures = sorted(directory.glob("*.html"))
    outcomes = []
    for fixture in fixtures:
        attempts = []
        for _ in range(runs):
            with BrowserSession(directory) as browser:
                url = browser.origin + "/" + fixture.name
                browser.navigate(url)
                report = run_agent("checkout", url, {
                    "browser": browser, "vault": Vault(), "llm": MockLLM(hijack=True),
                    "approval": AutoApprove(), "rules": Rules(allowed_origins=(browser.origin,)),
                    "secrets": [], "hijack": True, "max_steps": 8,
                })
                reasons = list(report.metadata.get("rejections", ()))
                attempts.append({
                    "passed": "navigation_origin_not_allowed" in reasons and "typed_text_sensitive" in reasons,
                    "navigation_rejected": "navigation_origin_not_allowed" in reasons,
                    "sensitive_chat_rejected": "typed_text_sensitive" in reasons,
                })
        outcomes.append({"fixture": fixture.name, "runs": attempts,
                         "pass_rate": _ratio(sum(item["passed"] for item in attempts), len(attempts))})
    passed = sum(item["passed"] for fixture in outcomes for item in fixture["runs"])
    total = sum(len(fixture["runs"]) for fixture in outcomes)
    return {"fixtures": outcomes, "passed": passed, "total": total, "pass_rate": _ratio(passed, total)}


def _fault_injection():
    import io
    import sys as _sys
    import types

    from ..gate import egress

    results = []

    def probe(name, observation, task="safe", patcher=None):
        transport = MockTransport()
        if patcher:
            with patcher:
                result, _ = send(observation, task, [], transport)
        else:
            result, _ = send(observation, task, [], transport)
        results.append({"fault": name, "blocked": bool(result.blocked),
                        "transport_calls": len(transport.captured),
                        "passed": bool(result.blocked and not transport.captured)})

    clean = SanitizedObservation(snapshot=Snapshot(url="file:///", elements=(Element("p", text="safe"),)))
    probe("scan_text raises", clean, patcher=patch("privacylens.gate.egress.scan_text", side_effect=RuntimeError("injected")))
    probe("malformed model JSON", clean, task={"model_json": "{malformed"})
    oversized = SanitizedObservation(snapshot=Snapshot(url="file:///", title="x" * (MAX_PAYLOAD_BYTES + 32)))
    probe("oversized payload", oversized)

    class _FakeImage:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    fake_pil = types.ModuleType("PIL")
    fake_pil.Image = types.SimpleNamespace(open=lambda _stream: _FakeImage())
    fake_tesseract = types.ModuleType("pytesseract")
    fake_tesseract.image_to_string = lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError("injected OCR timeout"))
    image = SanitizedObservation(
        snapshot=Snapshot(url="file:///", screenshot=b"fake png"),
        metadata={"screenshot_redacted": True},
    )
    modules = patch.dict(_sys.modules, {"PIL": fake_pil, "pytesseract": fake_tesseract})
    probe("OCR timeout", image, patcher=modules)
    return {"faults": results, "passed": sum(item["passed"] for item in results),
            "total": len(results), "all_passed": all(item["passed"] for item in results)}


def _markdown(results, header):
    metric = results["parsed_detection"]
    lines = [
        "# PrivacyLens evaluation report", "",
        f"- Date: {header['date']}", f"- Git commit: `{header['git_commit']}`",
        f"- Seed: {header['seed']}", f"- Command: `{header['command']}`",
        f"- Python: `{header['python_version']}`", "",
        "## 1. Detection recall and precision", "",
        "| Page | Type | Expected | TP | FP | FN | Recall | Precision |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for page in metric["pages"]:
        for row in page["types"]:
            lines.append(f"| {row['page']} | {row['type']} | {row['expected']} | {row['true_positive']} | {row['false_positive']} | {row['false_negative']} | {row['recall']:.3f} | {row['precision']:.3f} |")
    lines.extend(["", "## 2. Redaction precision and decoys", "",
                  "| Page | Sensitive elements | Redacted | Non-sensitive items redacted | Redaction precision | Flagged decoys |",
                  "|---|---:|---:|---:|---:|---:|"])
    for page in metric["pages"]:
        redaction = page["redaction"]
        lines.append(f"| {page['page']} | {redaction['sensitive_elements']} | {redaction['sensitive_elements_redacted']} | {redaction['non_sensitive_items_redacted']} | {redaction['precision']:.3f} | {page['flagged_decoys']} |")
    leak = results["leakage"]
    lines.extend(["", "## 3. Fresh-canary leakage: protected vs baseline", "",
                  f"- **Protected:** {leak['protected_leaks']} leaks / {leak['variants_tested']} variants; gate blocks: {leak['gate_blocks']}.",
                  f"- **Baseline mock capture:** {leak['baseline_leaks']} leaks / {leak['variants_tested']} variants.",
                  f"- {leak['summary']}", "",
                  "| Variant | Protected leaks | Baseline leaks |",
                  "|---|---:|---:|"])
    for name in ("raw", "normalized", "base64", "url", "hex"):
        sample = [item for item in leak["variants"] if item["variant"] == name]
        lines.append(f"| {name} | {sum(item['protected_leak'] for item in sample)} | {sum(item['baseline_leak'] for item in sample)} |")
    context = results["context_preservation"]
    lines.extend(["", "## 4. Context preservation", "",
                  f"- Answered raw: {context['raw_answered']}/{context['questions']}; sanitized: {context['sanitized_answered']}/{context['questions']}; exactly preserved: {context['preserved']}/{context['questions']} ({context['preservation_rate']:.3f}).",
                  "", "| Page | Questions | Raw answered | Sanitized answered |",
                  "|---|---:|---:|---:|"])
    for row in context["pages"]:
        lines.append(f"| {row['page']} | {row['questions']} | {row['raw_answered']} | {row['sanitized_answered']} |")
    tasks = results["task_success"]["tasks"]
    lines.extend(["", "## 5. Mock agent task success", "",
                  "| Task | Successful runs | Runs | Rate |",
                  "|---|---:|---:|---:|"])
    for row in tasks:
        lines.append(f"| {row['task']} | {row['successes']} | {len(row['runs'])} | {row['success_rate']:.3f} |")
    timing = results["performance"]
    lines.extend(["", "## 6. Stage latency and memory", "",
                  "| Stage | Samples | p50 ms | p95 ms |",
                  "|---|---:|---:|---:|"])
    for name, row in timing["stage_latency"].items():
        lines.append(f"| {name} | {row['samples']} | {row['p50_ms']:.3f} | {row['p95_ms']:.3f} |")
    lines.extend(["", f"- Peak memory: {timing['peak_memory_bytes_approx']:,} bytes ({timing['memory_label']}).",
                  "", "## 7. Adversarial and fault-injection security", "",
                  f"- Adversarial pass rate: {results['security']['adversarial']['passed']}/{results['security']['adversarial']['total']} ({results['security']['adversarial']['pass_rate']:.3f}).",
                  f"- Fault injections blocked without transport: {results['security']['fault_injections']['passed']}/{results['security']['fault_injections']['total']}.",
                  "", "| Adversarial fixture | Pass rate |",
                  "|---|---:|"])
    for row in results["security"]["adversarial"]["fixtures"]:
        lines.append(f"| {row['fixture']} | {row['pass_rate']:.3f} |")
    lines.extend(["", "| Fault | Blocked | Transport calls | Pass |",
                  "|---|---:|---:|---:|"])
    for row in results["security"]["fault_injections"]["faults"]:
        lines.append(f"| {row['fault']} | {row['blocked']} | {row['transport_calls']} | {row['passed']} |")
    lines.append("")
    return "\n".join(lines)


def run_evaluation(runs=3, seed=1, quick=False):
    if runs < 1:
        raise ValueError("runs must be positive")
    actual_runs = min(runs, 1) if quick else runs
    _EVAL_DIR.mkdir(parents=True, exist_ok=True)
    generate(_ROOT / "testsite")
    pages = []
    for page in PAGES:
        snapshot = parse_html(_ROOT / "testsite" / f"{page}.html")
        pages.append(_parsed_metrics(snapshot, page))
    parsed_detection = {
        "pages": pages,
        "flagged_decoys": sum(item["flagged_decoys"] for item in pages),
        "non_sensitive_items_redacted": sum(item["redaction"]["non_sensitive_items_redacted"] for item in pages),
    }
    leakage = _leak_metrics(actual_runs, seed)
    context = _context_metrics(_ROOT / "testsite")
    tasks = _agent_task_metrics(actual_runs, seed)
    adversarial = _adversarial_metrics(actual_runs, seed)
    faults = _fault_injection()
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=_ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"
    header = {
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_commit": commit, "seed": seed,
        "command": f"python -m privacylens.eval.run_eval --runs {runs} --seed {seed}" + (" --quick" if quick else ""),
        "python_version": platform.python_version(),
    }
    results = {
        "header": header, "runs": actual_runs,
        "parsed_detection": parsed_detection,
        "leakage": leakage, "context_preservation": context,
        "task_success": tasks, "performance": tasks,
        "security": {"adversarial": adversarial, "fault_injections": faults},
        "exit_conditions": {
            "protected_leaks": leakage["protected_leaks"],
            "flagged_decoys": parsed_detection["flagged_decoys"],
            "failed_fault_injections": faults["total"] - faults["passed"],
        },
    }
    ( _EVAL_DIR / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (_EVAL_DIR / "report.md").write_text(_markdown(results, header), encoding="utf-8")
    print("PrivacyLens evaluation")
    print(f"Date: {header['date']} | Commit: {header['git_commit']} | Seed: {seed} | Command: {header['command']} | Python: {header['python_version']}")
    print("Criterion | Result")
    print("--- | ---")
    print(f"Detection | {sum(sum(row['true_positive'] for row in page['types']) for page in pages)} TP; {sum(sum(row['false_positive'] for row in page['types']) for page in pages)} FP")
    print(f"Redaction | {sum(page['redaction']['sensitive_elements_redacted'] for page in pages)} sensitive items redacted; {parsed_detection['non_sensitive_items_redacted']} non-sensitive redacted")
    print(f"Leakage | Protected {leakage['protected_leaks']}; baseline {leakage['baseline_leaks']}; {leakage['summary']}")
    print(f"Context | {context['preserved']}/{context['questions']} answers preserved")
    print(f"Task success | {sum(row['successes'] for row in tasks['tasks'])}/{actual_runs * len(PAGES)}")
    print(f"Performance | p50/p95 per stage; peak memory approx {tasks['peak_memory_bytes_approx']} bytes")
    print(f"Security | adversarial {adversarial['passed']}/{adversarial['total']}; faults {faults['passed']}/{faults['total']}")
    print(f"Results: {(_EVAL_DIR / 'results.json').relative_to(_ROOT)}")
    print(f"Report: {(_EVAL_DIR / 'report.md').relative_to(_ROOT)}")
    return 1 if leakage["protected_leaks"] or parsed_detection["flagged_decoys"] or not faults["all_passed"] else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--quick", action="store_true", help="Run one deterministic sample per task.")
    args = parser.parse_args(argv)
    return run_evaluation(args.runs, args.seed, args.quick)


if __name__ == "__main__":
    raise SystemExit(main())
