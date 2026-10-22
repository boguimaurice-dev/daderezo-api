#!/usr/bin/env python3
# DADEREZO - orchestrateur local
# Coordonne les collecteurs, distribue les taches de diagnostic, gere les alertes.
# Lecture seule. Aucune modification de configuration sans validation humaine.
import sqlite3, json, os, time, subprocess
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "daderezo.db")
LOG = os.path.join(HERE, "orchestrator.log")
TASKS = os.path.join(HERE, "tasks.json")

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def log(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(now() + " | " + msg + "\n")
    print(now() + " | " + msg)

def load_tasks():
    if os.path.exists(TASKS):
        with open(TASKS, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

def save_tasks(tasks):
    with open(TASKS, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)

def run_collector():
    log("Lancement du collecteur")
    r = subprocess.run(["python", os.path.join(HERE, "collector.py")],
                      capture_output=True, text=True, timeout=120,
                      encoding="cp1252", errors="replace")
    if r.returncode != 0:
        log("ERREUR collecteur: " + r.stderr[:200])
    else:
        log("Collecteur termine avec succes")
    return r.returncode == 0

def check_alerts():
    conn = sqlite3.connect(DB)
    alerts = conn.execute("SELECT severity, message FROM alerts ORDER BY id DESC LIMIT 5").fetchall()
    conn.close()
    for sev, msg in alerts:
        log(f"ALERTE [{sev}] {msg}")
    return alerts

def dispatch_tasks():
    tasks = load_tasks()
    pending = [t for t in tasks if t.get("status") == "pending"]
    for t in pending:
        log(f"Tache {t['id']}: {t['demande']}")
        # Le collecteur execute les diagnostics en lecture seule
        if "scan" in t["demande"].lower() or "diagnostic" in t["demande"].lower():
            run_collector()
            t["status"] = "done"
            t["resultat"] = "Scan termine. Resultats dans daderezo.db et logs.json"
        elif "rapport" in t["demande"].lower():
            run_collector()
            t["status"] = "done"
            t["resultat"] = "Rapport genere. Voir dashboard.html"
        else:
            t["status"] = "done"
            t["resultat"] = "Tache non reconnue, collecteur lance par defaut"
            run_collector()
    save_tasks(tasks)

def main():
    log("Orchestrateur DADEREZO demarre")
    cycle = 0
    while True:
        cycle += 1
        log(f"--- Cycle {cycle} ---")
        run_collector()
        alerts = check_alerts()
        dispatch_tasks()
        log(f"Cycle {cycle} termine. Prochain dans 300s.")
        time.sleep(300)

if __name__ == "__main__":
    main()
