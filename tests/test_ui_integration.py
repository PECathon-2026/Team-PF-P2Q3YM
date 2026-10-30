import time
import unittest
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

_HAS_FASTAPI=bool(importlib.util.find_spec("fastapi"))


def _leaf_values(value):
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _leaf_values(item)]
    if isinstance(value, list):
        return [leaf for item in value for leaf in _leaf_values(item)]
    return [str(value)]


class UIIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(_HAS_FASTAPI,"FastAPI is optional")
    def test_bootstrap_requires_token_then_sets_cookie_and_serves_page(self):
        from fastapi.testclient import TestClient
        from privacylens.ui.app import create_app
        app=create_app(); token=app.state.privacylens_session_token
        with TestClient(app,base_url="http://127.0.0.1:8765") as client:
            self.assertEqual(client.get("/").status_code,403)
            response=client.get("/?token="+token,follow_redirects=False)
            self.assertEqual(response.status_code,303)
            cookie=response.headers.get("set-cookie","").casefold()
            self.assertIn("privacylens_session",cookie)
            self.assertIn("httponly",cookie)
            self.assertIn("samesite=strict",cookie)
            self.assertEqual(response.headers.get("cache-control"),"no-store")
            page=client.get("/")
            self.assertEqual(page.status_code,200)
            self.assertEqual(page.headers.get("cache-control"),"no-store")
            self.assertIn("X-Requested-With",page.text)
            with TestClient(app,base_url="http://127.0.0.1:8765") as other:
                self.assertEqual(other.get("/?token="+token).status_code,403)

    @unittest.skipUnless(_HAS_FASTAPI,"FastAPI is optional")
    def test_post_requires_cookie_origin_and_requested_with_marker(self):
        from fastapi.testclient import TestClient
        from privacylens.ui.app import create_app
        app=create_app()
        with TestClient(app,base_url="http://127.0.0.1:8765") as client:
            client.get("/?token="+app.state.privacylens_session_token)
            endpoint="/api/simulate-leak"
            self.assertEqual(client.post(endpoint).status_code,403)
            marker={"X-Requested-With":"privacylens"}
            self.assertEqual(client.post(endpoint,headers=marker).status_code,403)
            origin={"Origin":"http://127.0.0.1:8765"}
            self.assertEqual(client.post(endpoint,headers=origin).status_code,403)
            headers={**origin,**marker}
            response=client.post(endpoint,headers=headers)
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json()["verdict"],"BLOCKED")
            self.assertEqual(response.headers.get("cache-control"),"no-store")

    @unittest.skipUnless(_HAS_FASTAPI,"FastAPI is optional")
    def test_run_lifecycle_approval_and_events_never_include_seed_values(self):
        from fastapi.testclient import TestClient
        from privacylens.ui.app import create_app
        root=Path(__file__).resolve().parents[1]
        seeded=json.loads((root/"config"/"demo_secrets.json").read_text(encoding="utf-8"))
        raw_values=[item["value"] for task,entries in seeded.items() if task!="origins" for item in entries]
        app=create_app(); token=app.state.privacylens_session_token
        with TestClient(app,base_url="http://127.0.0.1:8765") as client:
            client.get("/?token="+token)
            headers={"Origin":"http://127.0.0.1:8765","X-Requested-With":"privacylens"}
            response=client.post("/api/run",json={"task":"checkout","provider":"mock","mode":"protected"},headers=headers)
            self.assertEqual(response.status_code,200)
            safe_responses=[response.json()]
            events=[]; approvals=set()
            for _ in range(300):
                event_response=client.get("/api/events?since=0")
                safe_responses.append(event_response.json())
                events=event_response.json()["events"]
                for request in (event for event in events if event["type"]=="approval_request"):
                    if request["approval_id"] in approvals: continue
                    decision=client.post("/api/approve",json={"approval_id":request["approval_id"],"decision":"approve"},headers=headers)
                    self.assertEqual(decision.status_code,200); safe_responses.append(decision.json()); approvals.add(request["approval_id"])
                if any(event["type"]=="run_end" for event in events):break
                time.sleep(.1)
            self.assertTrue(any(e["type"]=="run_end" for e in events))
            self.assertGreater(len(approvals),1)
            serialized=json.dumps({"events":events,"responses":safe_responses},ensure_ascii=False)
            leaves=_leaf_values({"events":events,"responses":safe_responses})
            for value in raw_values:
                if len(value)>=6: self.assertNotIn(value,serialized)
                self.assertNotIn(value,leaves)
            self.assertNotIn("canary@",serialized.casefold())
            preview=client.get("/api/shot?which=after")
            self.assertEqual(preview.status_code,200)
            self.assertEqual(preview.headers.get("content-type","").split(";")[0],"image/svg+xml")
            self.assertEqual(preview.headers.get("cache-control"),"no-store")
            preview_text=preview.content.decode("utf-8")
            for value in raw_values:
                if len(value)>=6: self.assertNotIn(value,preview_text)

    @unittest.skipUnless(_HAS_FASTAPI,"FastAPI is optional")
    def test_baseline_captures_seeded_values_only_in_local_mock_transport(self):
        from fastapi.testclient import TestClient
        from privacylens.ui.app import create_app
        root=Path(__file__).resolve().parents[1]
        secrets=json.loads((root/"config"/"demo_secrets.json").read_text(encoding="utf-8"))["checkout"]
        raw_values=[item["value"] for item in secrets]
        app=create_app()
        with TestClient(app,base_url="http://127.0.0.1:8765") as client:
            client.get("/?token="+app.state.privacylens_session_token)
            headers={"Origin":"http://127.0.0.1:8765","X-Requested-With":"privacylens"}
            started=client.post("/api/run",json={"task":"checkout","provider":"mock","mode":"baseline"},headers=headers)
            self.assertEqual(started.status_code,200)
            for _ in range(50):
                events=client.get("/api/events?since=0").json()["events"]
                if any(event["type"]=="run_end" for event in events): break
                time.sleep(.02)
            result=next(event for event in events if event["type"]=="baseline_result")
            self.assertGreater(result["seeded_values"],0)
            self.assertFalse(any("value" in event for event in events))
            serialized=json.dumps({"start":started.json(),"events":events},ensure_ascii=False)
            leaves=_leaf_values({"start":started.json(),"events":events})
            for value in raw_values:
                if len(value)>=6: self.assertNotIn(value,serialized)
                self.assertNotIn(value,leaves)
            self.assertNotIn("canary@",serialized.casefold())

    @unittest.skipUnless(_HAS_FASTAPI,"FastAPI is optional")
    def test_ui_lists_injection_task_and_results_empty_state(self):
        from fastapi.testclient import TestClient
        from privacylens.ui.app import create_app
        app=create_app()
        app.state.eval_results_path=Path(__file__).with_name("missing-eval-results.json")
        with TestClient(app,base_url="http://127.0.0.1:8765") as client:
            client.get("/?token="+app.state.privacylens_session_token)
            tasks=client.get("/api/tasks").json()["tasks"]
            self.assertEqual(set(tasks),{"checkout","login","support","meet","devsettings","injection"})
            self.assertIn("injection",client.get("/").text)
            self.assertEqual(client.get("/api/results").json(),{"results":[]})

    def test_approval_timeout_defaults_to_deny(self):
        from privacylens.agent.events import EventBus, WebApprovalGate
        gate=WebApprovalGate(EventBus())
        self.assertFalse(gate.approve("test approval",timeout=.01))

    @unittest.skipUnless(_HAS_FASTAPI,"FastAPI is optional")
    def test_browser_start_failure_enters_visible_replay(self):
        from fastapi.testclient import TestClient
        from privacylens.agent.browser import BrowserSession
        from privacylens.ui.app import create_app
        app=create_app()
        with TestClient(app,base_url="http://127.0.0.1:8765") as client:
            client.get("/?token="+app.state.privacylens_session_token)
            headers={"Origin":"http://127.0.0.1:8765","X-Requested-With":"privacylens"}
            with patch.object(BrowserSession,"__enter__",side_effect=RuntimeError("browser unavailable")):
                response=client.post("/api/run",json={"task":"checkout","provider":"mock","mode":"protected"},headers=headers)
                self.assertEqual(response.status_code,200)
                for _ in range(50):
                    events=client.get("/api/events?since=0").json()["events"]
                    if any(event["type"]=="demo_replay" for event in events): break
                    time.sleep(.02)
            self.assertTrue(any(event["type"]=="demo_replay" for event in events))
            self.assertTrue(any(event["type"]=="run_end" for event in events))


if __name__=="__main__": unittest.main()
