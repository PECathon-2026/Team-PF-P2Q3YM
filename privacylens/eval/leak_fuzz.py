"""Exercise the generated-page -> sanitizer -> egress pathway with fresh canaries."""
import argparse
import random
from pathlib import Path
from dataclasses import replace

from ..contracts import Element
from ..detect.validators import luhn_generate, verhoeff_generate
from ..gate.canary import CanaryRegistry, value_variants
from ..gate.egress import send
from ..sanitize.rules import load_rules
from ..sanitize.sanitize import sanitize
from ..sanitize.vault import Vault
from .gen_data import PAGES, generate
from .html_elements import parse_html
from .mock_llm import MockTransport


def run(runs=50, seed=1):
    if runs <= 0:
        raise ValueError("runs must be positive")
    rng = random.Random(seed)
    repo_root = Path(__file__).resolve().parents[2]
    base = repo_root / "testsite"
    generate(base)
    rules = load_rules(repo_root / "config" / "privacy.json")
    items_planted = blocked_count = leaks_found = 0
    pages = {page: parse_html(base / f"{page}.html") for page in PAGES}
    for run_number in range(runs):
        card_prefix = "4" + "".join(str(rng.randrange(10)) for _ in range(10))
        card = luhn_generate(card_prefix)
        aadhaar_prefix = str(rng.randint(2, 9)) + "".join(str(rng.randrange(10)) for _ in range(10))
        aadhaar = verhoeff_generate(aadhaar_prefix)
        email = f"canary{rng.randrange(10**14)}@example.test"
        values = (("CARD", card), ("AADHAAR", aadhaar), ("EMAIL", email))
        for page in PAGES:
            snapshot = pages[page]
            injected = tuple(
                Element("input", attributes={
                    "id": f"fuzz-{run_number}-{kind.lower()}",
                    "name": kind.lower(),
                    "autocomplete": "cc-number" if kind == "CARD" else "email" if kind == "EMAIL" else "off",
                    "value": value,
                })
                for kind, value in values
            )
            snapshot = replace(snapshot, elements=snapshot.elements + injected)
            registry = CanaryRegistry()
            vault = Vault()
            for kind, value in values:
                label = f"run-{run_number}-{page}-{kind.lower()}"
                registry.register(value, label)
                vault.add(value, kind, ("file://",))
                items_planted += 1
            probe_transport = MockTransport()
            probe, _response = send(snapshot, "Review the page safely", [], probe_transport,
                                    registry=registry, vault=vault)
            if probe.blocked:
                blocked_count += 1
            observation = sanitize(snapshot, vault, rules)
            transport = MockTransport()
            result, _response = send(observation, "Review the page safely", [], transport,
                                     registry=registry, vault=vault)
            if result.blocked:
                blocked_count += 1
            for payload in transport.captured:
                for _kind, value in values:
                    if any(variant.encode("utf-8") in payload for variant in value_variants(value)):
                        leaks_found += 1
                        break
    print("PrivacyLens leak fuzzer")
    print("Pages  Runs  Planted  Blocked  Leaks  Seed")
    print(f"{len(PAGES):>5}  {runs:>4}  {items_planted:>7}  {blocked_count:>7}  {leaks_found:>5}  {seed:>4}")
    print(f"{leaks_found} leaks in {runs} runs on the tested pages and gate pathway")
    return 1 if leaks_found else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        return run(args.runs, args.seed)
    except Exception:
        # Never echo exception text; it may contain a sensitive payload.
        print("Leak fuzzing failed closed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
