import json, platform, subprocess, sys

res = {
    "platform": platform.system(),
    "platform_release": platform.release(),
    "machine": platform.machine(),
    "node": platform.node(),
    "user": "USERENV",
    "python": sys.version.split()[0],
    "python_exe": sys.executable,
}
out = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, encoding="cp1252", errors="replace").stdout
lines = out.splitlines()
dhcp = next((l for l in lines if "dhcp enabled" in l.lower()), "DHCP non lu")
gw = None
for l in lines:
    if "default gateway" in l.lower():
        parts = l.split(":")
        gw = parts[1].strip() if len(parts) > 1 else None
res["dhcp"] = dhcp.strip()
res["default_gateway"] = gw
print(json.dumps(res, ensure_ascii=False))
