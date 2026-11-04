from pathlib import Path
from threading import RLock
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .database import add_event,add_alert,baselines,save_baseline
from .integrity import sha256_file
from .policy import sensitive,allowed
_lock=RLock(); _obs=None
class Handler(FileSystemEventHandler):
    def __init__(self,policy=None):self.policy=policy or {}
    def record(self,kind,src,dst=""):
        target=dst or src; digest=""
        try:
            if Path(target).is_file():digest=sha256_file(target)
        except OSError:pass
        is_s=sensitive(src,self.policy.get("extensions"),self.policy.get("keywords")) or (bool(dst) and sensitive(dst,self.policy.get("extensions"),self.policy.get("keywords")))
        ok=allowed(dst,self.policy.get("allowed")) if dst else True
        bad=is_s and not ok; risk="HIGH" if bad else ("MEDIUM" if is_s else "LOW")
        detail="Sensitive file moved outside configured allowed destinations" if bad else ""
        add_event(kind,src,dst,digest,risk,"Suspicious" if bad else "Normal",detail)
        if bad:add_alert("HIGH","Sensitive file moved to unapproved destination",target,detail)
        if digest and kind in ("CREATED","MOVED"):save_baseline(str(Path(target).resolve()),digest)
        if digest and kind=="MODIFIED":
            old=baselines().get(str(Path(src).resolve()))
            if old and old!=digest:add_event("INTEGRITY_FAILURE",src,dst,digest,"HIGH","Suspicious","SHA-256 mismatch");add_alert("HIGH","Integrity mismatch",src,"Hash differs from baseline")
    def on_created(self,e):
        if not e.is_directory:self.record("CREATED",e.src_path)
    def on_modified(self,e):
        if not e.is_directory:self.record("MODIFIED",e.src_path)
    def on_deleted(self,e):
        if not e.is_directory:
            s=sensitive(e.src_path,self.policy.get("extensions"),self.policy.get("keywords"));add_event("DELETED",e.src_path,risk="MEDIUM" if s else "LOW",status="Suspicious" if s else "Normal",details="Deleted; hash unavailable")
            if s:add_alert("MEDIUM","Sensitive file deleted",e.src_path,"Review deletion")
    def on_moved(self,e):
        if not e.is_directory:self.record("MOVED",e.src_path,e.dest_path)
def start_monitoring(folder,recursive=True,policy=None):
    global _obs
    p=Path(folder).resolve()
    if not p.is_dir():raise ValueError("Folder does not exist")
    with _lock:
        if _obs and _obs.is_alive():_obs.stop();_obs.join(timeout=3)
        o=Observer();o.schedule(Handler(policy),str(p),recursive=recursive);o.start();_obs=o
def stop_monitoring():
    global _obs
    with _lock:
        if _obs:_obs.stop();_obs.join(timeout=3);_obs=None
def running():return bool(_obs and _obs.is_alive())
