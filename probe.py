#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sonde rapide multi-plateforme (Windows / Linux / macOS) en lecture seule."""
import getpass
import json
import platform
import sys

from collector import local_info


def main() -> None:
    net = local_info()
    res = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "node": platform.node(),
        "user": getpass.getuser(),
        "python": sys.version.split()[0],
        "python_exe": sys.executable,
        "ip_local": net.get("ip"),
        "subnet_mask": net.get("mask"),
        "default_gateway": net.get("gw"),
        "mac": net.get("mac"),
        "dns": net.get("dns"),
    }
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
