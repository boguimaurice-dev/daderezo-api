#!/usr/bin/env python3
# Agent client — envoie les donnees du collecteur vers l'API SaaS
# Usage: python agent_client.py --api https://votre-api.onrender.com --agent mon-site
import argparse, json, os, subprocess, time, urllib.request

def run_collector():
    r = subprocess.run(["python", "collector.py"], capture_output=True,
                       text=True, timeout=120, encoding="cp1252", errors="replace")
    if r.returncode != 0:
        print("Erreur collecteur:", r.stderr[:200])
        return None
    # Read logs.json
    with open("logs.json", "r", encoding="utf-8") as f:
        return json.load(f)

def send_data(api_url, agent_id, data):
    # Convert alerts to list of dicts
    alerts_raw = data.get("alerts", [])
    alerts = []
    for a in alerts_raw:
        if isinstance(a, (list, tuple)):
            alerts.append({"severity": a[0], "message": a[1]})
        elif isinstance(a, dict):
            alerts.append(a)
        else:
            alerts.append({"severity": "info", "message": str(a)})
    payload = {
        "agent_id": agent_id,
        "nom": f"Agent {agent_id}",
        "ip_local": data.get("ip_local"),
        "mask": data.get("mask"),
        "gw": data.get("gw"),
        "mac_local": data.get("mac_local"),
        "probes": data.get("probes", []),
        "alerts": alerts,
    }
    req = urllib.request.Request(
        f"{api_url}/data",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as rep:
        return json.loads(rep.read())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", required=True, help="URL de l'API SaaS")
    parser.add_argument("--agent", default="default", help="ID de l'agent/site")
    parser.add_argument("--interval", type=int, default=300, help="Intervalle en secondes")
    args = parser.parse_args()

    print(f"Agent {args.agent} -> {args.api} (intervalle: {args.interval}s)")

    # Register
    try:
        req = urllib.request.Request(
            f"{args.api}/register",
            data=json.dumps({"agent_id": args.agent, "nom": f"Agent {args.agent}"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as rep:
            print("Enregistre:", json.loads(rep.read()))
    except Exception as e:
        print("Erreur enregistrement:", e)

    while True:
        data = run_collector()
        if data:
            try:
                result = send_data(args.api, args.agent, data)
                print(f"Envoye: {result.get('received', 0)} sondes")
            except Exception as e:
                print(f"Erreur envoi: {e}")
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
