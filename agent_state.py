import json, os, platform, subprocess, sys, time

files = ["C:/Users/PC MARKET CI/hermes-first-task/probe.py", "C:/Users/PC MARKET CI/hermes-first-task/DADEREZO.html"]
for f in files:
    files_status = os.path.exists(f)
    if files_status:
        try:
            size = os.path.getsize(f)
        except OSError:
            size = "err"
    else:
        size = "absent"

info = {
    "now_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "platform": {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "node": platform.node(),
    },
    "files": {
        "probe.py": files_status,
        "DADEREZO.html": files_status,
        "probe_size": size if files_status else None,
    },
    "env": {
        "model_provider_hint": os.environ.get("HERMES_MODEL", "not set"),
        "local_appdata": os.environ.get("LOCALAPPDATA", "not set"),
        "tmp": os.environ.get("TMPDIR", "not set"),
    },
    "note": "Agent as of now: local prototype dashboard and read-only local probe only. No data is being collected from the community network yet.",
}

print(json.dumps(info, indent=2, ensure_ascii=False))
