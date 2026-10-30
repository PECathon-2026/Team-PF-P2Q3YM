"""Launch the authenticated local dashboard."""
import threading, time, webbrowser
import uvicorn
from .app import create_app
from .security import LOCAL_BIND_HOST

def main():
    app=create_app()
    port=8765
    config=uvicorn.Config(app,host=LOCAL_BIND_HOST,port=port,log_level="error",access_log=False)
    server=uvicorn.Server(config)
    thread=threading.Thread(target=server.run,daemon=True);thread.start()
    while not server.started: time.sleep(.05)
    url=f"http://{LOCAL_BIND_HOST}:{port}/?token={app.state.privacylens_session_token}"
    print(url,flush=True);webbrowser.open(url)
    try: thread.join()
    except KeyboardInterrupt: server.should_exit=True

if __name__=="__main__": main()
