#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Diagnostic d'état de l'environnement local de l'agent DADEREZO."""
import json
import os
import platform
import time

HERE = os.path.dirname(os.path.abspath(__file__))

TRACKED_FILES = [
    "collector.py",
    "agent_client.py",
    "orchestrator.py",
    "api.py",
    "probe.py",
    "devices.json",
    "DADEREZO.html",
]


def main() -> None:
    files_report = {}
    for fname in TRACKED_FILES:
        fpath = os.path.join(HERE, fname)
        exists = os.path.exists(fpath)
        files_report[fname] = {
            "exists": exists,
            "size": os.path.getsize(fpath) if exists else None,
        }

    db_path = os.path.join(HERE, "daderezo.db")
    info = {
        "now_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "node": platform.node(),
        },
        "files": files_report,
        "local_db_present": os.path.exists(db_path),
        "env": {
            "api_url": os.environ.get("DADEREZO_API_URL", "not set"),
            "agent_id": os.environ.get("DADEREZO_AGENT_ID", "not set"),
            "api_key_configured": bool(os.environ.get("DADEREZO_API_KEY")),
        },
        "mode": "read_only",
    }
    print(json.dumps(info, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
