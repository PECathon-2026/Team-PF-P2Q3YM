"""Ephemeral loopback test browser backed by optional Playwright Chromium."""
from __future__ import annotations

import functools
import http.server
import secrets
import threading
from pathlib import Path

from ..contracts import Element, Snapshot


class StaleTargetError(RuntimeError): pass


class BrowserSession:
    def __init__(self, site_dir=None, headed=False):
        self.site_dir = Path(site_dir or Path(__file__).resolve().parents[2] / "testsite").resolve()
        self.headed = headed
        self._server = self._thread = self._playwright = self._browser = self._context = self.page = None
        self._frames = {}

    def __enter__(self):
        from functools import partial
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is optional. Install it with `python -m pip install playwright` and run `python -m playwright install chromium`.") from exc
        self._session_token = secrets.token_urlsafe(32)
        owner = self
        class GuardedStaticHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *_args): pass
            def _authorized(self):
                return (self.headers.get("X-PrivacyLens-Session") == owner._session_token and
                        self.headers.get("Origin") == owner.origin)
            def do_GET(self):
                if not self._authorized(): self.send_error(403); return
                super().do_GET()
            def do_HEAD(self):
                if not self._authorized(): self.send_error(403); return
                super().do_HEAD()
            def do_POST(self):
                if not self._authorized(): self.send_error(403); return
                self.send_error(405)
        handler = functools.partial(GuardedStaticHandler, directory=str(self.site_dir))
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True); self._thread.start()
        self.origin = f"http://127.0.0.1:{self._server.server_address[1]}"
        try:
            self._playwright = sync_playwright().start()
            if not Path(self._playwright.chromium.executable_path).is_file():
                raise RuntimeError("Chromium is not installed. Run `python -m playwright install chromium` after installing Playwright.")
            self._browser = self._playwright.chromium.launch(headless=not self.headed)
            self._context = self._browser.new_context(extra_http_headers={
                "Origin":self.origin,"X-PrivacyLens-Session":self._session_token})  # fresh, non-persistent context
            self.page = self._context.new_page()
        except RuntimeError:
            self.close()
            raise
        except Exception as exc:
            self.close()
            raise RuntimeError("Could not start Chromium. Install it with `python -m playwright install chromium`.") from exc
        return self

    def close(self):
        for item in (self._context, self._browser):
            try:
                if item: item.close()
            except Exception: pass
        try:
            if self._playwright: self._playwright.stop()
        except Exception: pass
        if self._server:
            self._server.shutdown(); self._server.server_close()
        if self._thread: self._thread.join(timeout=2)

    def __exit__(self, *_): self.close()

    def navigate(self, url): self.page.goto(url, wait_until="domcontentloaded")
    def wait(self, milliseconds=300): self.page.wait_for_timeout(max(0, min(int(milliseconds), 5000)))
    def scroll(self, target=""):
        if target: self._locator(target).scroll_into_view_if_needed()
        else: self.page.evaluate("window.scrollBy(0, Math.max(200, window.innerHeight * .75))")

    def _locator(self, local_id):
        for frame in self.page.frames:
            locator = frame.locator('[data-pl-id="' + str(local_id).replace('"', '') + '"]')
            try:
                if locator.count(): return locator.first
            except Exception: continue
        raise StaleTargetError("target is no longer present")

    def click(self, local_id):
        loc = self._locator(local_id)
        if not loc.count(): raise StaleTargetError("target is no longer present")
        loc.click()

    def type(self, local_id, text):
        loc = self._locator(local_id)
        if not loc.count(): raise StaleTargetError("target is no longer present")
        loc.fill(text)

    def select(self, local_id, value):
        loc = self._locator(local_id)
        if not loc.count(): raise StaleTargetError("target is no longer present")
        loc.select_option(value)

    def verify_value(self, local_id, expected):
        loc=self._locator(local_id)
        try: return loc.input_value()==expected
        except Exception: return False

    def goal_state(self):
        return self.page.evaluate("() => ({state:document.body.dataset.state||'',muted:document.body.dataset.muted||'',participants:document.body.dataset.participants||'',tab:document.body.dataset.tab||''})")

    def snapshot(self):
        payload = self.page.evaluate("""() => {
          let n=0, out=[], hidden=0;
          const interact=new Set(['INPUT','BUTTON','SELECT','TEXTAREA','A','SUMMARY']);
          const blocks=new Set(['P','DIV','ARTICLE','LI','H1','H2','H3','LABEL']);
          function visit(root) {
            for (const el of root.querySelectorAll('*')) {
              if (el.tagName==='IFRAME') { try { if(el.contentDocument) visit(el.contentDocument); } catch(_) {} }
              const style=getComputedStyle(el), r=el.getBoundingClientRect();
              const hiddenNow=style.display==='none'||style.visibility==='hidden'||r.width===0||r.height===0||style.opacity==='0'||style.color===style.backgroundColor;
              if (el.shadowRoot) visit(el.shadowRoot);
              const text=(el.innerText||el.textContent||'').trim();
              if (!(interact.has(el.tagName)||(blocks.has(el.tagName)&&text))) continue;
              if(hiddenNow){hidden++; continue;}
              const id='e'+(++n); el.setAttribute('data-pl-id',id);
              const labels=[];
              if(el.labels) for(const l of el.labels) labels.push((l.innerText||'').trim());
              const attrs={}; for(const k of ['type','autocomplete','name','id','href','title','alt','role','placeholder','aria-label','data-pl-id']) if(el.hasAttribute(k)) attrs[k]=el.getAttribute(k);
              for(const a of el.attributes) if(a.name.startsWith('data-')) attrs[a.name]=a.value;
              attrs.label=[el.getAttribute('aria-label'),...labels,el.getAttribute('placeholder')].filter(Boolean).join(' ');
              attrs.value=('value' in el)?el.value:'';
              attrs.visible='true'; attrs.enabled=String(!el.disabled);
              out.push({tag:el.tagName.toLowerCase(),text:text.slice(0,1000),attrs,bbox:[r.x,r.y,r.width,r.height],frame:el.ownerDocument.defaultView.frameElement?el.ownerDocument.defaultView.frameElement.src:'main'});
            }
          }
          visit(document); return {out,hidden};
        }""")
        elems=[]; self._frames={}
        for item in payload["out"]:
            attrs=item["attrs"]; local_id=attrs["data-pl-id"]
            self._frames[local_id]=item["frame"]
            elems.append(Element(tag=item["tag"], text=item["text"], attributes=attrs, selector=local_id,
                                 bounds=tuple(item["bbox"]), metadata={"visible":True,"enabled":attrs["enabled"]=="true","hidden":False,"role":attrs.get("role","")}))
        screenshot=self.page.screenshot(type="png", full_page=False)
        return Snapshot(url=self.page.url,title=self.page.title(),elements=tuple(elems),screenshot=screenshot,
                        metadata={"hidden_count":payload["hidden"]})
