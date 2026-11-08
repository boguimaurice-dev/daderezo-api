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

### Connexion Google, candidatures et activation

1. Sauvegarder la base, puis exécuter dans l'ordre `migrations/001_private_audit_sessions.sql` et `migrations/002_platform_applications.sql` sur Supabase **avant** de déployer le code. Les anciennes traces sans organisation ne sont pas accessibles : aucun rattachement automatique ne doit être fait.
2. Configurer côté serveur `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` et `DADEREZO_SUPERADMIN_EMAIL` (l'adresse Google du super administrateur). Ne jamais exposer la clé service au navigateur. Ne pas activer `DADEREZO_LEGACY_AUTH` en production.
3. Configurer Google dans Supabase et ajouter `https://daderezo-api-nine.vercel.app/ui?google_callback=1` aux URL de redirection Supabase. L'URL de retour Google Cloud demeure `/auth/v1/callback` sur le domaine Supabase.
4. Le candidat se connecte avec Google, indique le site et atteste son autorisation. Le super administrateur examine la candidature puis choisit `approved` et `paid` (avec date de fin UTC incluse) ou `pilot`. La clé sonde n'est fournie qu'au compte actif. Une suspension ou l'expiration interdit les requêtes suivantes ; une commande déjà reçue par une sonde ne peut pas être rappelée.
5. L'ancien compte e-mail/mot de passe et les anciennes clés sondes sont bloqués par défaut. Pour rattacher l'ancien site, l'utilisateur doit utiliser le même navigateur contenant son ancien jeton DADEREZO encore valide, se connecter avec Google sur la même adresse, déposer sa candidature puis cliquer sur « Rattacher mon ancien site » **avant toute décision**. Le serveur vérifie le jeton signé, l'e-mail et l'organisation ; l'administrateur approuve ensuite la candidature et le paiement ou pilote. La sonde devra être reconfigurée avec sa nouvelle clé. Les anciennes lignes de journaux sans organisation vérifiable restent conservées mais non visibles ; aucune attribution n'est devinée. En cas de jeton absent ou expiré, une procédure de vérification manuelle reste à prévoir : ne pas raccorder sur la seule base de l'e-mail.

Il s'agit d'une confirmation manuelle des paiements, sans prestataire, facture, renouvellement automatique ni délai de grâce. L'accès Google nécessite une nouvelle connexion à l'expiration du jeton. Exiger la double authentification Google pour le compte administrateur. Avant mise en production, tester les redirections Google de bout en bout, les RLS et droits Supabase, les sauvegardes et le déploiement. La fonctionnalité reste dépendante des contrôles d'isolation des autres composants ; les simulations ne prouvent pas une sécurité exhaustive.
