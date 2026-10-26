#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DADEREZO — Orchestrateur local autonome (100 % lecture seule).
Coordonne le collecteur, régénère le tableau de bord local et traite tasks.json.
Aucune modification de configuration réseau n'est effectuée.
"""
import argparse
from datetime import datetime, timezone
import json
import os
import sqlite3
import time

from collector import DB, collect
import make_dashboard

HERE = os.path.dirname(os.path.abspath(__file__))
LOG = os.path.join(HERE, "orchestrator.log")
TASKS = os.path.join(HERE, "tasks.json")


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    line = f"{now()} | {msg}"
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)


def load_tasks() -> list:
    if os.path.exists(TASKS):
        try:
            with open(TASKS, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            log(f"Avertissement lecture tasks.json : {e}")
    return []


def save_tasks(tasks: list) -> None:
    with open(TASKS, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)


def check_new_alerts(last_alert_id: int) -> int:
    if not os.path.exists(DB):
        return last_alert_id
    conn = sqlite3.connect(DB)
    try:
        rows = conn.execute(
            "SELECT id, severity, message FROM alerts WHERE id > ? ORDER BY id ASC",
            (last_alert_id,),
        ).fetchall()
    finally:
        conn.close()

    for alert_id, sev, msg in rows:
        log(f"ALERTE [{sev}] {msg}")
        last_alert_id = max(last_alert_id, int(alert_id))
    return last_alert_id


def dispatch_tasks() -> None:
    tasks = load_tasks()
    pending = [t for t in tasks if isinstance(t, dict) and t.get("status") == "pending"]
    if not pending:
        return

    for t in pending:
        demande = str(t.get("demande", "")).lower()
        t_id = t.get("id", "?")
        log(f"Tâche #{t_id} : {t.get('demande', '')}")
        if "sweep" in demande or "complet" in demande:
            collect(do_sweep=True)
            make_dashboard.build()
            t["status"] = "done"
            t["completed_at"] = now()
            t["resultat"] = "Balayage sous-réseau terminé. Résultats dans daderezo.db et dashboard.html"
        elif "scan" in demande or "diagnostic" in demande:
            collect(do_sweep=False)
            make_dashboard.build()
            t["status"] = "done"
            t["completed_at"] = now()
            t["resultat"] = "Scan terminé. Résultats dans daderezo.db et logs.json"
        elif "rapport" in demande:
            make_dashboard.build()
            t["status"] = "done"
            t["completed_at"] = now()
            t["resultat"] = "Rapport régénéré dans dashboard.html"
        else:
            collect(do_sweep=False)
            make_dashboard.build()
            t["status"] = "done"
            t["completed_at"] = now()
            t["resultat"] = "Tâche exécutée en lecture seule (collecte standard)"
    save_tasks(tasks)


def run_single_cycle(cycle: int, last_alert_id: int, do_sweep: bool = False) -> int:
    log(f"--- Cycle {cycle} ---")
    try:
        res = collect(do_sweep=do_sweep)
        log(
            f"Collecte OK : {len(res.get('probes', []))} équipements | "
            f"passerelle={res.get('gw_status')} | internet={res.get('internet_status')}"
        )
    except Exception as e:
        log(f"ERREUR collecteur : {e}")
    last_alert_id = check_new_alerts(last_alert_id)
    dispatch_tasks()
    try:
        make_dashboard.build(quiet=True)
    except Exception as e:
        log(f"Avertissement génération dashboard.html : {e}")
    return last_alert_id


def main() -> None:
    parser = argparse.ArgumentParser(description="DADEREZO — Orchestrateur local")
    parser.add_argument("--interval", type=int, default=300, help="Intervalle entre cycles (secondes)")
    parser.add_argument("--sweep", action="store_true", help="Activer le balayage ping du sous-réseau")
    parser.add_argument("--once", action="store_true", help="Exécuter un seul cycle puis quitter")
    args = parser.parse_args()

    log("Orchestrateur DADEREZO démarré (mode lecture seule)")
    last_alert_id = 0
    if os.path.exists(DB):
        conn = sqlite3.connect(DB)
        try:
            row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM alerts").fetchone()
            last_alert_id = int(row[0] or 0)
        except Exception:
            last_alert_id = 0
        finally:
            conn.close()

    if args.once:
        run_single_cycle(1, last_alert_id, do_sweep=args.sweep)
        return

    cycle = 0
    while True:
        cycle += 1
        last_alert_id = run_single_cycle(cycle, last_alert_id, do_sweep=args.sweep)
        log(f"Cycle {cycle} terminé. Prochain dans {args.interval}s.")
        time.sleep(max(10, args.interval))


if __name__ == "__main__":
    main()
