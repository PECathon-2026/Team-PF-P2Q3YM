import re, sys
from html.parser import HTMLParser
from pathlib import Path
from collections import Counter
from privacylens.detect.patterns import scan_text

class P(HTMLParser):
    def __init__(self):
        super().__init__(); self.t = []
    def handle_data(self, d):
        if d.strip(): self.t.append(d.strip())
    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k in ("value", "placeholder", "aria-label") and v: self.t.append(v)

for page in sorted(Path("testsite").glob("*.html")):
    p = P(); p.feed(page.read_text(encoding="utf-8"))
    counts, sample = Counter(), []
    for line in p.t:
        fs = scan_text(line)
        for f in fs: counts[f.kind] += 1
        if fs and len(sample) < 3:
            out = line
            for f in sorted(fs, key=lambda f: f.metadata["start"], reverse=True):
                out = out[:f.metadata["start"]] + f"[REDACTED:{f.kind}]" + out[f.metadata["end"]:]
            sample.append(out)
    print(f"\n== {page.name}: {sum(counts.values())} findings {dict(counts)}")
    for s in sample: print("   ", s)
