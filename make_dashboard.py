#!/usr/bin/env python3
# Construit dashboard.html avec les données locales.
import json, os, sqlite3, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "daderezo.db")
OUT = os.path.join(HERE, "dashboard.html")

def build():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    ip_local = conn.execute("SELECT value FROM state WHERE key='ip_local'").fetchone()
    gw = conn.execute("SELECT value FROM state WHERE key='gw'").fetchone()
    mac_local = conn.execute("SELECT value FROM state WHERE key='mac_local'").fetchone()
    probes = conn.execute("SELECT ip, mac, status, type FROM probes ORDER BY id DESC LIMIT 10").fetchall()
    alerts = conn.execute("SELECT severity, message FROM alerts ORDER BY id DESC LIMIT 20").fetchall()
    conn.close()
    probes = [dict(r) for r in probes]
    alerts = [dict(r) for r in alerts]
    ip_local = ip_local[0] if ip_local else "—"
    gw = gw[0] if gw else "—"
    mac_local = mac_local[0] if mac_local else "—"
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    rows = "\n".join(
        f"<tr><td>{p['ip']}</td><td>{p['mac'] or '—'}</td>"
        f"<td class='{ 'ok' if p['status'] == 'up' else 'down' }'>{p['status']}</td>"
        f"<td>{p['type'] or '—'}</td></tr>" for p in probes
    )
    alert_html = "\n".join(
        f"<li><b>{a['severity']}</b> {a['message']}</li>" for a in alerts
    ) or "<li>Aucune alerte.</li>"
    html = f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DADEREZO · Supervision</title>
<style>
:root {{ color-scheme: light; }}
body {{ font-family: "Segoe UI", system-ui, sans-serif; margin: 0; background: #f5f7f5; color: #1d2b26; }}
header {{ background: #1e3a33; color: #d9e6df; padding: 14px 18px; }}
header h1 {{ margin: 0; font-size: 20px; }}
header p {{ margin: 4px 0 0; font-size: 13px; }}
main {{ padding: 18px; max-width: 1200px; margin: 0 auto; }}
.card {{ background: #ffffff; border: 1px solid #cdd9d2; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }}
.stat {{ background: #eef4f0; border: 1px solid #d3e0d8; border-radius: 10px; padding: 12px; }}
.stat b {{ display: block; font-size: 22px; color: #1e6b57; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ border: 1px solid #d3e0d8; padding: 10px; text-align: left; }}
th {{ background: #eef4f0; }}
.ok {{ color: #1e6b57; font-weight: bold; }}
.down {{ color: #a34a3d; font-weight: bold; }}
.alerts li {{ margin-bottom: 8px; }}
.foot {{ margin-top: 16px; font-size: 12px; color: #6b7d75; }}
</style>
</head>
<body>
<header>
  <h1>DADEREZO — Surveillance réseau</h1>
  <p>Communauté Sainte Marie de Bouaké — {now} — lecture seule</p>
</header>
<main>
  <div class="card">
    <h2>Vue d’ensemble</h2>
    <div class="grid">
      <div class="stat"><b>{ip_local}</b><span>Adresse IP locale</span></div>
      <div class="stat"><b>{gw}</b><span>Passerelle</span></div>
      <div class="stat"><b>{mac_local}</b><span>MAC locale</span></div>
      <div class="stat"><b>{len(probes)}</b><span>Postes détectés</span></div>
    </div>
  </div>
  <div class="card">
    <h2>Équipements réseaux</h2>
    <table>
      <thead><tr><th>Adresse</th><th>MAC</th><th>État</th><th>Type</th></tr></thead>
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
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(html)
    print("dashboard.html written")

if __name__ == "__main__":
    build()
