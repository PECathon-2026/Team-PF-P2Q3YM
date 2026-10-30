"""In-memory run events and fail-closed web approval handoff."""
import threading
import time

class EventBus:
    def __init__(self): self._events=[]; self._lock=threading.Lock(); self._condition=threading.Condition(self._lock); self.shots={};self.status="running"
    def emit(self, kind, **data):
        with self._condition:
            item={"id":len(self._events)+1,"type":kind,"time":time.time(),**data}; self._events.append(item); self._condition.notify_all(); return item
    def since(self, sequence=0):
        with self._lock: return self._events[int(sequence):]

class WebApprovalGate:
    def __init__(self,bus): self.bus=bus; self._pending={}; self._lock=threading.Lock()
    def approve(self,description,timeout=30):
        self.bus.status="waiting for approval"
        key=str(time.time_ns())
        decision=threading.Event(); record={"event":None,"event_obj":decision,"answer":False}
        with self._lock:self._pending[key]=record
        event=self.bus.emit("approval_request",approval_id=key,description=description,deadline=time.time()+30)
        record["event"]=event
        decision.wait(min(30,timeout or 30))
        self.bus.status="running"
        with self._lock:self._pending.pop(key,None)
        self.bus.emit("approval_result",decision="approve" if record["answer"] else "deny")
        return record["answer"]
    def decide(self,key,answer):
        with self._lock: record=self._pending.get(str(key))
        if not record:return False
        record["answer"]=bool(answer);record["event_obj"].set();return True
