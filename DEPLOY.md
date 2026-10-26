# Guide de déploiement DADEREZO SaaS

## Architecture

```text
[PC / Mini-PC / Raspberry Pi local] --> agent_client.py --> [API FastAPI (Render / Docker)] --> [DADEREZO.html / Frontend]
```

## Étape 1 : Tester l'API et la sonde localement

```bash
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

Dans un second terminal, lancez un cycle de collecte local :

```bash
python agent_client.py --api http://localhost:8000 --agent sainte-marie-bouake --once
```

Ouvrez ensuite :
- `http://localhost:8000/ui` : tableau de bord complet DADEREZO
- `http://localhost:8000/docs` : documentation interactive Swagger

## Étape 2 : Créer une base PostgreSQL persistante (optionnel, gratuit sur Render)

1. Sur Render, cliquez **+ New** → **PostgreSQL**
2. Nommez-la `daderezo-db` (plan Free)
3. Copiez l'**Internal Database URL**
4. Ajoutez dans les variables d'environnement du service Web :
   - `DATABASE_URL` = `<URL PostgreSQL copiée>` (les URLs `postgres://` et `postgresql://` sont toutes deux acceptées)
   - `DADEREZO_API_KEY` = `<votre-cle-secrete>` *(recommandé en production)*

Sans `DATABASE_URL`, l'API utilise automatiquement SQLite (`daderezo_saas.db`).

## Étape 3 : Déployer sur Render

1. Connectez ce dépôt GitHub (`daderezo-api`) sur https://render.com
2. Créez un **Web Service** :
   - **Build command** : `pip install -r requirements.txt`
   - **Start command** : `uvicorn api:app --host 0.0.0.0 --port $PORT`
3. Votre service est accessible sur `https://daderezo-api.onrender.com` (interface directe sur `/ui`).

## Étape 4 : Connecter la sonde du site supervisé

Sur un ordinateur ou mini-PC toujours allumé dans le réseau local (Windows ou Linux / Raspberry Pi) :

```bash
python agent_client.py \
  --api https://daderezo-api.onrender.com \
  --agent sainte-marie-bouake \
  --nom "Sainte Marie de Bouaké" \
  --api-key "<votre-cle-secrete>"
```

## Endpoints disponibles

- `GET /` — interface web (navigateur) ou statut JSON (clients API)
- `GET /health` — statut JSON du service
- `GET /ui` — interface complète de supervision (`DADEREZO.html`)
- `GET /simple` — vue légère (`frontend.html`)
- `POST /register` — enregistrer / mettre à jour une sonde (idempotent)
- `POST /data` — recevoir l'instantané des équipements, l'état WAN/LAN et les alertes
- `GET /agents` — liste des sondes avec état dynamique (`online` / `offline`)
- `GET /devices/{agent_id}` — inventaire courant dédupliqué d'un site
- `GET /probes/{agent_id}?limit=20` — historique des sondes
- `GET /alerts/{agent_id}?limit=20` — journal des alertes
- `GET /state/{agent_id}` — paramètres réseau du site
- `GET /dashboard/{agent_id}` — agrégat complet pour le tableau de bord
- `POST /tasks/{agent_id}` — programmer un diagnostic en lecture seule (`scan`, `sweep`, `diagnostic`, `rapport`)
