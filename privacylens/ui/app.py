"""Loopback-only dashboard API for local PrivacyLens runs."""
import json
import threading
from pathlib import Path

from .security import create_secure_app


_TASKS = {
    "checkout": {"page": "checkout.html", "goal": "Fill checkout fields from vault refs and stop at Pay for approval."},
    "login": {"page": "login.html", "goal": "Log in with vault credentials; request the one-time code from the user."},
    "support": {"page": "support.html", "goal": "Escalate the open support ticket."},
    "meet": {"page": "meet.html", "goal": "Mute the microphone and open participants."},
    "devsettings": {"page": "devsettings.html", "goal": "Open Webhooks and request a new token with approval."},
    "injection": {"page": "checkout.html", "goal": "Reject a hostile navigation and sensitive chat-field attempt."},
}


def create_app():
    from fastapi import Request
    from fastapi.responses import HTMLResponse, JSONResponse, Response

    app, token = create_secure_app()
    page = (Path(__file__).parent / "static" / "index.html").read_text(encoding="utf-8")
    app.state.run_bus = None
    app.state.approval_gate = None
    app.state.run_status = "idle"
    app.state.run_thread = None
    app.state.results = None
    app.state.eval_results_path = Path(__file__).resolve().parents[2] / "eval" / "results.json"

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return page

    @app.get("/api/status")
    async def status():
        return {"app": "PrivacyLens", "state": "ready", "session": "local",
                "providers": {"mock": True}, "image_ocr": _ocr_available()}

    @app.get("/api/tasks")
    async def tasks():
        return {"tasks": _TASKS}

    @app.post("/api/run")
    async def start_run(request: Request):
        body = await request.json()
        task = body.get("task")
        provider = body.get("provider", "mock")
        mode = body.get("mode", "protected")
        if task not in _TASKS or provider != "mock" or mode not in ("protected", "baseline"):
            return JSONResponse(status_code=400, content={"detail": "unsupported run configuration"})
        if task == "injection" and mode != "protected":
            return JSONResponse(status_code=400, content={"detail": "injection task requires protected mode"})
        if getattr(app.state, "run_thread", None) and app.state.run_thread.is_alive():
            return JSONResponse(status_code=409, content={"detail": "run already active"})

        from ..agent.events import EventBus
        bus = EventBus()
        app.state.run_bus = bus
        app.state.run_status = "running"
        app.state.results = None

        def worker():
            try:
                from ..agent.browser import BrowserSession
                from ..agent.events import WebApprovalGate
                from ..agent.llm import MockLLM
                from ..agent.loop import run
                from ..eval.html_elements import parse_html
                from ..eval.mock_llm import MockTransport
                from ..gate.egress import _jsonable
                from ..sanitize.rules import Rules
                from ..sanitize.vault import Vault

                actual_task = "checkout" if task == "injection" else task
                hijack = bool(body.get("hijack")) or task == "injection"
                if mode == "baseline":
                    site = Path(__file__).resolve().parents[2] / "testsite"
                    snapshot = parse_html(site / _TASKS[actual_task]["page"])
                    raw = json.dumps(_jsonable(snapshot), ensure_ascii=False, sort_keys=True).encode("utf-8")
                    transport = MockTransport()
                    transport(raw)
                    secrets = json.loads((site.parent / "config" / "demo_secrets.json").read_text(encoding="utf-8")).get(actual_task, [])
                    exposed = sum(item["value"].encode("utf-8") in transport.captured[0] for item in secrets)
                    bus.emit("action", action="Baseline raw-page capture", target="MockTransport only")
                    bus.emit("baseline_result", seeded_values=exposed, total=len(secrets))
                    bus.emit("run_end", status="baseline", summary=f"Mock captured {exposed}/{len(secrets)} seeded values.")
                    app.state.results = {"status": "baseline", "seeded_values_in_captured_bytes": exposed}
                else:
                    approval_gate = WebApprovalGate(bus)
                    app.state.approval_gate = approval_gate
                    with BrowserSession() as browser:
                        url = browser.origin + "/" + _TASKS[actual_task]["page"]
                        browser.navigate(url)
                        report = run(actual_task, url, {
                            "browser": browser,
                            "vault": Vault(),
                            "llm": MockLLM(hijack),
                            "approval": approval_gate,
                            "rules": Rules(allowed_origins=(browser.origin, "http://localhost", "http://127.0.0.1", "file://")),
                            "event_bus": bus,
                            "hijack": hijack,
                            "safe_preview_renderer": _safe_observation_svg,
                        })
                        app.state.results = {
                            "status": report.status,
                            "summary": report.summary,
                            "timings": report.metadata.get("timings", {}),
                        }
                        bus.emit("run_end", status=report.status, summary=report.summary)
            except Exception:
                _emit_replay(bus)
                app.state.run_status = "replay"
            finally:
                if app.state.run_status != "replay":
                    app.state.run_status = "finished"
                    bus.status = "finished"

        app.state.run_thread = threading.Thread(target=worker, daemon=True)
        app.state.run_thread.start()
        return {"started": True, "status": "running"}

    @app.get("/api/events")
    async def events(since: int = 0):
        bus = app.state.run_bus
        return {"status": bus.status if bus else app.state.run_status,
                "events": bus.since(since) if bus else []}

    @app.post("/api/approve")
    async def approve(request: Request):
        body = await request.json()
        approval_gate = app.state.approval_gate
        if not approval_gate or not approval_gate.decide(body.get("approval_id"), body.get("decision") == "approve"):
            return JSONResponse(status_code=409, content={"detail": "approval expired"})
        return {"recorded": True}

    @app.get("/api/shot")
    async def shot(which: str = "after"):
        bus = app.state.run_bus
        image = bus.shots.get(which) if bus and which in ("before", "after") else None
        media_type = "image/svg+xml" if image and image.lstrip().startswith(b"<svg") else "image/png"
        return Response(image or b"", media_type=media_type, status_code=200 if image else 404)

    @app.get("/api/results")
    async def results():
        result = app.state.eval_results_path
        return json.loads(result.read_text(encoding="utf-8")) if result.exists() else {"results": []}

    @app.post("/api/simulate-leak")
    async def simulate_leak():
        from ..contracts import Element, SanitizedObservation, Snapshot
        from ..eval.mock_llm import MockTransport
        from ..gate.egress import send

        transport = MockTransport()
        observation = SanitizedObservation(snapshot=Snapshot(
            url="file://", elements=(Element(tag="p", text="4111111111111111"),)))
        result, _response = send(observation, "demo", [], transport)
        return {"verdict": "BLOCKED" if result.blocked else "ALLOWED",
                "reasons": [{"type": item["type"], "count": item["count"]}
                            for item in result.metadata.get("reasons", [])]}

    @app.post("/api/image-scan")
    async def image_scan(request: Request):
        from ..sanitize.image import redact_png

        payload = await request.body()
        if len(payload) > 12_000_000:
            return JSONResponse(status_code=413, content={"detail": "image too large"})
        safe = redact_png(payload, ())
        if safe is None:
            return JSONResponse(status_code=422, content={"detail": "Image could not be safely OCR-scanned; install Tesseract and Pillow."})
        return Response(content=safe, media_type="image/png")

    app.state.privacylens_session_token = token
    return app


def _emit_replay(bus):
    sample = Path(__file__).parent / "sample_events.json"
    for item in json.loads(sample.read_text(encoding="utf-8")):
        bus.emit(item["type"], **item.get("data", {}))
    bus.status = "Demo replay"
    bus.emit("demo_replay", message="Demo replay: agent or browser could not start.")


def _safe_observation_svg(snapshot):
    from xml.sax.saxutils import escape

    width = 1000
    rows = []
    for element in snapshot.elements:
        attrs = dict(element.attributes or {})
        label = attrs.get("label") or attrs.get("aria-label") or attrs.get("name") or element.tag
        value = attrs.get("value", "")
        detail = element.text or value
        rows.append((str(element.tag), str(label), str(detail)))
    height = max(300, 112 + 42 * len(rows))
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#0B1220"/>',
        '<text x="32" y="42" fill="#34D6B4" font-family="system-ui,sans-serif" font-size="18" font-weight="700">SANITIZED MODEL OBSERVATION</text>',
        '<text x="32" y="70" fill="#9AAEC1" font-family="monospace" font-size="12">Safe, minimized text view · generated in memory</text>',
    ]
    for index, (tag, label, detail) in enumerate(rows):
        y = 110 + index * 42
        lines.append(f'<text x="32" y="{y}" fill="#9AAEC1" font-family="monospace" font-size="12">{escape(tag.upper())}</text>')
        lines.append(f'<text x="164" y="{y}" fill="#EEF6FA" font-family="system-ui,sans-serif" font-size="14">{escape(label[:100])}</text>')
        lines.append(f'<text x="164" y="{y + 18}" fill="#34D6B4" font-family="monospace" font-size="12">{escape(detail[:140])}</text>')
    lines.append("</svg>")
    return "".join(lines).encode("utf-8")


def _ocr_available():
    try:
        import PIL  # noqa: F401
        import pytesseract  # noqa: F401
        return True
    except ImportError:
        return False
