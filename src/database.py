import sqlite3
from pathlib import Path
from datetime import datetime,timezone
DB=Path(__file__).resolve().parent.parent/"data"/"monitor.db"
def con():
    DB.parent.mkdir(parents=True,exist_ok=True); c=sqlite3.connect(DB,timeout=10); c.row_factory=sqlite3.Row; return c
def init_db():
    with con() as c:
        c.execute("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,timestamp TEXT,event_type TEXT,source_path TEXT,destination_path TEXT,sha256 TEXT,risk_level TEXT,status TEXT,details TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,timestamp TEXT,severity TEXT,title TEXT,file_path TEXT,details TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS baselines(file_path TEXT PRIMARY KEY,sha256 TEXT,updated_at TEXT)")
def add_event(kind,src,dst="",digest="",risk="LOW",status="Normal",details=""):
    with con() as c:c.execute("INSERT INTO events(timestamp,event_type,source_path,destination_path,sha256,risk_level,status,details) VALUES(?,?,?,?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),kind,src,dst,digest,risk,status,details))
def add_alert(sev,title,path,details):
    with con() as c:c.execute("INSERT INTO alerts(timestamp,severity,title,file_path,details) VALUES(?,?,?,?,?)",(datetime.now(timezone.utc).isoformat(),sev,title,path,details))
def events():
    with con() as c:return [dict(x) for x in c.execute("SELECT * FROM events ORDER BY id")]
def alerts():
    with con() as c:return [dict(x) for x in c.execute("SELECT * FROM alerts ORDER BY id")]
def baselines():
    with con() as c:return {x["file_path"]:x["sha256"] for x in c.execute("SELECT * FROM baselines")}
def save_baseline(path,digest):
    with con() as c:c.execute("INSERT INTO baselines VALUES(?,?,?) ON CONFLICT(file_path) DO UPDATE SET sha256=excluded.sha256,updated_at=excluded.updated_at",(path,digest,datetime.now(timezone.utc).isoformat()))
