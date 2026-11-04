from pathlib import Path
def sensitive(path,extensions=None,keywords=None):
    p=Path(path); ex=set(extensions or [".pem",".key",".env",".sql",".db",".xlsx"]); words=set(keywords or ["password","secret","confidential","customer"])
    return p.suffix.lower() in ex or any(w.lower() in p.name.lower() for w in words)
def allowed(destination,paths=None):
    if not destination or paths is None:return True
    d=Path(destination).resolve()
    for item in paths:
        try:
            base=Path(item).expanduser().resolve()
            if d==base or base in d.parents:return True
        except (OSError,RuntimeError):pass
    return False
