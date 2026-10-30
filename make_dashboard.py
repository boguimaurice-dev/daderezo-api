#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Construit dashboard.html (vue locale hors-ligne) à partir de daderezo.db."""
import datetime
from html import escape
import os
import sqlite3

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "daderezo.db")
OUT = os.path.join(HERE, "dashboard.html")


def build(db_path: str = DB, out_path: str = OUT, quiet: bool = False) -> str:
    state = {}
    devices = []
    alerts = []

    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            state = {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM state").fetchall()}
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if "known_devices" in tables:
                rows = conn.execute(
                    "SELECT ip, mac, name, zone, last_status AS status, type FROM known_devices ORDER BY ip ASC"
                ).fetchall()
                devices = [dict(r) for r in rows]
            if not devices and "probes" in tables:
                rows = conn.execute(
                    "SELECT ip, mac, status, type FROM probes ORDER BY id DESC LIMIT 25"
                ).fetchall()
                dedup = {}
                for r in rows:
                    d = dict(r)
                    if d["ip"] not in dedup:
                        dedup[d["ip"]] = d
                devices = list(dedup.values())
            if "alerts" in tables:
                alerts = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT ts, severity, message FROM alerts ORDER BY id DESC LIMIT 20"
                    ).fetchall()
                ]
        finally:
            conn.close()

    ip_local = escape(state.get("ip_local") or "—")
    gw = escape(state.get("gw") or "—")
    mac_local = escape(state.get("mac_local") or "—")
    internet = escape(state.get("internet_status") or "inconnu")
    site_name = escape(state.get("site_name") or "Communauté Sainte Marie de Bouaké")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    rows = "\n".join(
        f"<tr>"
        f"<td>{escape(str(p.get('name') or '—'))}</td>"
        f"<td>{escape(str(p.get('ip') or '—'))}</td>"
        f"<td>{escape(str(p.get('mac') or '—'))}</td>"
        f"<td class='{'ok' if p.get('status') == 'up' else 'down'}'>{escape(str(p.get('status') or '—'))}</td>"
        f"<td>{escape(str(p.get('type') or '—'))}</td>"
        f"</tr>"
        for p in devices
    ) or "<tr><td colspan='5'>Aucun équipement relevé pour le moment.</td></tr>"

    alert_html = "\n".join(
        f"<li><b>[{escape(str(a.get('severity') or 'info'))}]</b> "
        f"<small>{escape(str(a.get('ts') or ''))}</small> — {escape(str(a.get('message') or ''))}</li>"
        for a in alerts
    ) or "<li>Aucune alerte enregistrée.</li>"

    html = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DADEREZO · Supervision locale</title>
<meta name="theme-color" content="#031238">
<link rel="icon" type="image/svg+xml" href="/favicon.svg?v=4.3">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png?v=4.3">
<link rel="icon" type="image/png" sizes="64x64" href="/favicon.png?v=4.3">
<style>
:root {{ color-scheme: light; }}
body {{ font-family: "Segoe UI", system-ui, sans-serif; margin: 0; background: #f4f8ff; color: #031645; }}
header {{ background: linear-gradient(135deg, #031238, #0066eb); color: #f1f6ff; padding: 14px 18px; border-bottom: 2px solid #00c8ff; }}
header h1 {{ margin: 0; font-size: 20px; }}
header p {{ margin: 4px 0 0; font-size: 13px; color: #cbdcff; }}
main {{ padding: 18px; max-width: 1200px; margin: 0 auto; }}
.card {{ background: #ffffff; border: 1px solid #cbdcff; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }}
.stat {{ background: #eaf2ff; border: 1px solid #cbdcff; border-radius: 10px; padding: 12px; }}
.stat b {{ display: block; font-size: 20px; color: #0066eb; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ border: 1px solid #cbdcff; padding: 10px; text-align: left; }}
th {{ background: #eaf2ff; }}
.ok {{ color: #059669; font-weight: bold; }}
.down {{ color: #dc2626; font-weight: bold; }}
.alerts li {{ margin-bottom: 8px; }}
.foot {{ margin-top: 16px; font-size: 12px; color: #4b638c; }}
</style>
</head>
<body>
<header>
  <h1>DADEREZO — Surveillance réseau</h1>
  <p>{site_name} — {now_str} — lecture seule</p>
</header>
<main>
  <div class="card">
    <h2>Vue d’ensemble</h2>
    <div class="grid">
      <div class="stat"><b>{ip_local}</b><span>Adresse IP locale</span></div>
      <div class="stat"><b>{gw}</b><span>Passerelle</span></div>
      <div class="stat"><b>{mac_local}</b><span>MAC locale</span></div>
      <div class="stat"><b>{internet}</b><span>Accès Internet</span></div>
      <div class="stat"><b>{len(devices)}</b><span>Équipements suivis</span></div>
    </div>
  </div>
  <div class="card">
    <h2>Équipements réseaux</h2>
    <table>
      <thead><tr><th>Nom</th><th>Adresse IP</th><th>MAC</th><th>État</th><th>Type</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div class="card">
    <h2>Alertes</h2>
    <ul class="alerts">{alert_html}</ul>
  </div>
  <div class="foot">Collecteur local – lecture seule – base : daderezo.db – log : collector.log</div>
</main>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    if not quiet:
        print("dashboard.html written")
    return out_path


if __name__ == "__main__":
    build()
