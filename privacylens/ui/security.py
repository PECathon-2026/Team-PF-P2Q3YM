"""Security primitives for any optional local PrivacyLens HTTP UI."""
import hmac
import secrets

LOCAL_BIND_HOST = "127.0.0.1"
SESSION_HEADER = "x-privacylens-session"


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def validate_local_request(host: str, origin: str, supplied_token: str, expected_token: str, port: int) -> bool:
    expected_host = f"{LOCAL_BIND_HOST}:{int(port)}"
    expected_origin = f"http://{expected_host}"
    if host.casefold() != expected_host.casefold():
        raise PermissionError("request host is not the bound loopback host")
    if origin != expected_origin:
        raise PermissionError("request origin check failed")
    if not hmac.compare_digest(str(supplied_token), str(expected_token)):
        raise PermissionError("session token check failed")
    return True


def create_secure_app():
    """Create a loopback app with a one-use browser bootstrap and cookie auth."""
    try:
        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
    except ImportError as exc:
        raise RuntimeError("FastAPI is required to create the local UI app") from exc
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    token = new_session_token()
    bootstrapped = False

    @app.middleware("http")
    async def require_session_and_origin(request: Request, call_next):
        nonlocal bootstrapped
        port = request.url.port
        from fastapi.responses import RedirectResponse, JSONResponse
        expected_host=f"{LOCAL_BIND_HOST}:{int(port)}"
        if request.headers.get("host","").casefold()!=expected_host.casefold():
            response=JSONResponse(status_code=403,content={"detail":"request rejected"})
            response.headers["Cache-Control"]="no-store"
            response.headers["Content-Security-Policy"]="default-src 'self'; connect-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'"
            return response
        token_query=request.query_params.get("token","")
        if request.method=="GET" and request.url.path=="/" and not bootstrapped and hmac.compare_digest(token_query,token):
            bootstrapped=True
            response=RedirectResponse("/",status_code=303,headers={"Cache-Control":"no-store"})
            response.set_cookie("privacylens_session",token,httponly=True,samesite="strict",secure=False,path="/")
            response.headers["Content-Security-Policy"]="default-src 'self'; connect-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'"
            return response
        try:
            supplied=request.cookies.get("privacylens_session","")
            if not hmac.compare_digest(str(supplied),token): raise PermissionError("session token check failed")
            if request.method=="POST":
                validate_local_request(request.headers.get("host",""),request.headers.get("origin",""),supplied,token,port)
                if request.headers.get("x-requested-with")!="privacylens": raise PermissionError("request marker check failed")
        except Exception:
            response=JSONResponse(status_code=403, content={"detail": "request rejected"})
        else:
            response=await call_next(request)
        response.headers["Cache-Control"]="no-store"
        response.headers["Content-Security-Policy"]="default-src 'self'; connect-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'"
        return response

    app.state.privacylens_session_token = token
    return app, token


def serve_local(app, port: int):
    """Run a supplied ASGI app on loopback only; never accept a host override."""
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("uvicorn is required to serve the local UI") from exc
    uvicorn.run(app, host=LOCAL_BIND_HOST, port=int(port), access_log=False)
