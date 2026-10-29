#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exécute probe.py de manière portable (sans chemin Windows codé en dur)."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> None:
    probe_script = os.path.join(HERE, "probe.py")
    out = subprocess.run([sys.executable, probe_script], cwd=HERE, capture_output=True, text=True, timeout=20)
    print(
        json.dumps(
            {
                "returncode": out.returncode,
                "stdout": out.stdout,
                "stderr": out.stderr,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
