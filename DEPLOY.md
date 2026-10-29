# Guide de déploiement DADEREZO SaaS v3.0

## Architecture Globale

```text
[PC / Mini-PC / Raspberry Pi local]
  └── agent_client.py (--task-poll 5s)
         │ HTTPS 443 sortant
         ▼
[API FastAPI v3.0 (Vercel / Render / Docker)]
  ├── landing.html       (Vitrine SaaS, Démo Live & Onboarding Client sur /)
  ├── DADEREZO.html      (Poste Superviseur Général Vocal & Écrit sur /ui et /app)
  ├── agent_engine.py    (4 Agents IA : SENTINEL-SEC · TOPO-SCAN · DIAG-NET · OPS-DISPATCH)
  └── storage.py         (Supabase PostgreSQL 17 HTTPS · PostgreSQL direct · SQLite)
```

---

## Étape 1 : Tester localement

```bash
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

Dans un second terminal, lancez un cycle de collecte local :

```bash
python agent_client.py --api http://localhost:8000 --agent sainte-marie-bouake --nom "Communauté Sainte Marie de Bouaké" --once
```

Pages disponibles :
- `http://localhost:8000/` : Page d'accueil SaaS, Démo Live interactive & Générateur de sonde (Mode Clair & Sombre)
- `http://localhost:8000/ui` : Poste complet du Superviseur Général Multi-Agents
- `http://localhost:8000/docs` : Documentation interactive OpenAPI / Swagger

---

## Étape 2 : Déployer en Production sur Vercel + Supabase PostgreSQL 17 (Recommandé)

1. Créez un projet **Supabase** (PostgreSQL 17) et exécutez le schéma des tables (`agents`, `probes`, `devices`, `alerts`, `state`, `tasks`, `agent_sessions`, `agent_audit_logs`, `human_approvals`).
2. Sur **Vercel**, importez le dépôt GitHub `daderezo-api` (`vercel.json` inclus) et configurez les variables d'environnement :
   - `SUPABASE_URL` = `https://<votre-ref>.supabase.co`
   - `SUPABASE_SERVICE_ROLE_KEY` = `<clé service_role Supabase>`
   - `DADEREZO_API_KEY` = `<clé secrète optionnelle pour protéger les écritures>`
   - `GROQ_API_KEY` ou `OPENAI_API_KEY` = `<optionnel : synthèse LLM générative ancrée>`
3. Déployez : l'API communique avec Supabase en HTTPS pur (port 443), sans problème de pooler TCP IPv4/IPv6 serverless.

> Alternative PostgreSQL direct (Render / Railway / Docker) : définissez `DATABASE_URL=postgresql://...`. Sans variable externe, l'API bascule automatiquement sur SQLite.

---

## Étape 3 : Connecter une vraie sonde sur le terrain (Windows, Linux, Raspberry Pi)

Sur un poste allumé connecté au réseau local supervisé (aucune librairie Python externe requise sur le poste sonde) :

```bash
python agent_client.py \
  --api https://daderezo-api-nine.vercel.app \
  --agent sainte-marie-bouake \
  --nom "Communauté Sainte Marie de Bouaké" \
  --task-poll 5
```

---

## Principaux Endpoints API v3.0

- `GET /` — Vitrine SaaS & Démo Live (`text/html`) ou statut JSON (`application/json`)
- `GET /ui` et `GET /app` — Poste du Superviseur Général (`DADEREZO.html`)
- `GET /simple` — Vue légère (`frontend.html`)
- `GET /health` — Statut JSON, version, pipeline d'agents et moteur DB actif (`supabase` / `postgresql` / `sqlite`)
- `GET /download/{filename}` — Téléchargement sécurisé par liste blanche (`agent_client.py`, `collector.py`, `devices.json`, `make_dashboard.py`)
- `POST /register` & `POST /data` — Enregistrement idempotent et ingestion télémétrique WAN/LAN
- `GET /agents`, `GET /devices/{agent_id}`, `GET /dashboard/{agent_id}` — État temps réel et matrice LAN vs Internet par poste
- `GET /supervisor/overview` — Vue consolidée multi-sites
- `POST /supervisor/ask` — Mission écrite/vocale exécutée par les 4 agents (`SENTINEL-SEC`, `TOPO-SCAN`, `DIAG-NET`, `OPS-DISPATCH`)
- `GET /supervisor/audit` & `GET /supervisor/session/{session_id}` — Traces d'outils IA et mémoire de session
- `POST /supervisor/approve/{approval_id}` — Validation humaine (*Human-in-the-Loop*) avant balayage 254 IP
