import json, subprocess, sys

def run(cmd, cwd):
    r = subprocess.run([sys.executable, cmd], cwd=cwd, capture_output=True, text=True)
    return r

out = run("C:/Users/PC MARKET CI/hermes-first-task/probe.py", "C:/Users/PC MARKET CI/hermes-first-task")
print(json.dumps({
    "returncode": out.returncode,
    "stdout": out.stdout,
    "stderr": out.stderr,
}, ensure_ascii=False))
