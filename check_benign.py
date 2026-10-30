from privacylens.detect.patterns import scan_text
benign = ["Order #4111111111111112 shipped 2026-10-29 10:15:30",
          "SKU 123456789012 qty 2", "Price Rs 12345678", "call me maybe",
          "Placed on 12/25/2026", "Total 4,999.00 INR", "Version 1.2.3.4 released",
          "ID 20261029"]
for s in benign:
    print(s, "->", [f.kind for f in scan_text(s)])
