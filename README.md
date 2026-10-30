# PrivacyLens

PrivacyLens detects sensitive data in browser observations, sanitizes local observations, and checks the exact payload before an injected model transport can receive it.

## Commands

The project works without `make` on Windows. Run these from the repository root:

| Make target | Python command |
| --- | --- |
| `make setup` | `python -m pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt` |
| `make test` | `python -m unittest discover -s tests -p "test_*.py" -v` |
| `make eval` | `python -m privacylens.eval` |
| `make demo` | `python -m privacylens` |

Generate the deterministic evaluation fixtures directly with `python -m privacylens.eval.gen_data`.
Run the seven-criterion evaluation with `python -m privacylens.eval.run_eval --runs 3 --seed 1`; it writes `eval/results.json` and `eval/report.md`.
Run the leak-fuzz pathway with `python -m privacylens.eval.leak_fuzz --runs 50 --seed 1`.
Run the browser-backed mock checkout with `python -m privacylens.agent.run --task checkout --provider mock --approve auto`.
Add `--hijack` to exercise rejected hostile actions, or use `--mode baseline` to capture the unprotected mock page. The protected checkout fills fields only from local vault references, verifies each filled value in the browser, and stops at Pay for approval.
Launch the local dashboard with `python -m privacylens.ui.server`. It opens a one-time-token URL, then uses a strict same-site HttpOnly cookie; all dashboard APIs are loopback-only and mock-transport-only.

The core detector, sanitizer, vault, and egress checks use the Python standard library. Pillow, pytesseract, and PyYAML are optional for image/OCR and YAML support.

## Local data and UI safety

Raw snapshots, screenshots, and vault values stay in memory. Temporary run artifacts must use `get_run_output_dir()` from `privacylens.paths`; it defaults to the system temp area and rejects paths inside the repository. `PRIVACYLENS_RUN_DIR` can select another external directory.

Sanitization minimizes observations by default: it retains interactive controls and elements whose labels match the supplied `task_keywords`, and truncates retained text to 80 characters. Pass `full_page=True` only when a full-page observation is required.

Sensitive values are replaced with per-session shadow tokens. Reuse the same `SessionTokenizer` (or session `Vault`) to keep token indices stable across observations. Vault reads are local policy checks, not cryptography; values require explicit approval by default and are limited by field kind, exact URL origin, visibility, enabled state, and optional use count.

The dashboard uses `create_secure_app()` and `serve_local()` from `privacylens.ui.security`. It binds only to `127.0.0.1`, authenticates normal GETs with the bootstrap cookie, and checks cookie, exact loopback `Origin`, and `X-Requested-With` on POSTs, including approvals.
