# PrivacyLens evaluation report

- Date: 2026-10-30T00:58:09+00:00
- Git commit: `0345b8b`
- Seed: 1
- Command: `python -m privacylens.eval.run_eval --runs 3 --seed 1`
- Python: `3.11.9`

## 1. Detection recall and precision

| Page | Type | Expected | TP | FP | FN | Recall | Precision |
|---|---:|---:|---:|---:|---:|---:|---:|
| checkout | ADDRESS | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| checkout | CARD | 5 | 5 | 1 | 0 | 1.000 | 0.833 |
| checkout | CVV | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| checkout | EXPIRY | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| checkout | NAME | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| checkout | PHONE | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| login | EMAIL | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| login | OTP | 1 | 1 | 1 | 0 | 1.000 | 0.500 |
| login | PASSWORD | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| login | PHONE | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| login | SECRET | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| support | AADHAAR | 1 | 1 | 3 | 0 | 1.000 | 0.250 |
| support | NAME | 1 | 1 | 0 | 0 | 1.000 | 1.000 |
| support | PHONE | 2 | 2 | 0 | 0 | 1.000 | 1.000 |
| meet | EMAIL | 2 | 2 | 0 | 0 | 1.000 | 1.000 |
| meet | NAME | 2 | 2 | 0 | 0 | 1.000 | 1.000 |
| devsettings | IP | 2 | 2 | 0 | 0 | 1.000 | 1.000 |
| devsettings | SECRET | 5 | 5 | 2 | 0 | 1.000 | 0.714 |

## 2. Redaction precision and decoys

| Page | Sensitive elements | Redacted | Non-sensitive items redacted | Redaction precision | Flagged decoys |
|---|---:|---:|---:|---:|---:|
| checkout | 10 | 10 | 4 | 0.714 | 0 |
| login | 4 | 4 | 5 | 0.444 | 0 |
| support | 3 | 3 | 4 | 0.429 | 0 |
| meet | 4 | 4 | 4 | 0.500 | 0 |
| devsettings | 7 | 7 | 7 | 0.500 | 0 |

## 3. Fresh-canary leakage: protected vs baseline

- **Protected:** 0 leaks / 15 variants; gate blocks: 9.
- **Baseline mock capture:** 15 leaks / 15 variants.
- 0 leaks in 3 runs on the tested pages and gate pathway

| Variant | Protected leaks | Baseline leaks |
|---|---:|---:|
| raw | 0 | 3 |
| normalized | 0 | 3 |
| base64 | 0 | 3 |
| url | 0 | 3 |
| hex | 0 | 3 |

## 4. Context preservation

- Answered raw: 40/40; sanitized: 40/40; exactly preserved: 38/40 (0.950).

| Page | Questions | Raw answered | Sanitized answered |
|---|---:|---:|---:|
| checkout | 8 | 8 | 8 |
| login | 8 | 8 | 8 |
| support | 8 | 8 | 8 |
| meet | 8 | 8 | 8 |
| devsettings | 8 | 8 | 8 |

## 5. Mock agent task success

| Task | Successful runs | Runs | Rate |
|---|---:|---:|---:|
| checkout | 3 | 3 | 1.000 |
| login | 0 | 3 | 0.000 |
| support | 3 | 3 | 1.000 |
| meet | 3 | 3 | 1.000 |
| devsettings | 0 | 3 | 0.000 |

## 6. Stage latency and memory

| Stage | Samples | p50 ms | p95 ms |
|---|---:|---:|---:|
| detect | 15 | 52.446 | 250.606 |
| execute | 15 | 65.504 | 166.794 |
| gate | 15 | 353.380 | 2115.989 |
| llm | 15 | 0.752 | 2.948 |
| sanitize | 15 | 163.004 | 809.733 |
| snapshot | 15 | 164.272 | 584.774 |

- Peak memory: 8,800,765 bytes (approximate tracemalloc peak; excludes native browser allocations).

## 7. Adversarial and fault-injection security

- Adversarial pass rate: 9/9 (1.000).
- Fault injections blocked without transport: 4/4.

| Adversarial fixture | Pass rate |
|---|---:|
| chat_exfiltration.html | 1.000 |
| prompt_override.html | 1.000 |
| untrusted_content.html | 1.000 |

| Fault | Blocked | Transport calls | Pass |
|---|---:|---:|---:|
| scan_text raises | True | 0 | True |
| malformed model JSON | True | 0 | True |
| oversized payload | True | 0 | True |
| OCR timeout | True | 0 | True |
