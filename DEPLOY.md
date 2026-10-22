# Guide de deploiement DADEREZO SaaS

## Architecture

```
[PC client] --> agent_client.py --> [API FastAPI sur Render] --> [Lovable frontend]
```

## Etape 1 : Tester l'API localement

```bash
cd hermes-first-task
pip install -r requirements.txt
uvicorn api:app --reload
```

Ouvrir http://localhost:8000/docs pour voir la documentation Swagger.

## Etape 2 : Deployer sur Render (gratuit)

1. Creez un compte sur https://render.com
2. Connectez votre repo GitHub (ou uploadez les fichiers)
3. Creez un "Web Service" avec:
   - Build command: pip install -r requirements.txt
   - Start command: uvicorn api:app --host 0.0.0.0 --port $PORT
4. Render vous donne une URL: https://daderezo-api.onrender.com

## Etape 3 : Connecter l'agent local

Sur le PC du client:
```bash
python agent_client.py --api https://daderezo-api.onrender.com --agent mon-site
```

## Etape 4 : Connecter le frontend Lovable

Dans Lovable, configurez les appels API vers:
- GET https://daderezo-api.onrender.com/dashboard/{agent_id}
- GET https://daderezo-api.onrender.com/agents

## Endpoints disponibles

- GET / — statut du service
- POST /register — enregistrer un agent
- POST /data — envoyer les donnees collectees
- GET /agents — liste des agents
- GET /probes/{agent_id} — sondes d'un agent
- GET /alerts/{agent_id} — alertes d'un agent
- GET /state/{agent_id} — etat d'un agent
- GET /dashboard/{agent_id} — tableau de bord complet

## Etape 0 : Creer une base PostgreSQL (GRATUIT sur Render)

1. Sur Render, cliquez "+ New" -> "PostgreSQL"
2. Nommez-la "daderezo-db"
3. Selectionnez le plan "Free"
4. Cliquez "Create Database"
5. Copiez l'URL de connexion (Internal Database URL)
6. Dans les variables d'environnement du Web Service, ajoutez:
   DATABASE_URL = <l'URL copiee>

L'API detectera automatiquement PostgreSQL et utilisera le stockage persistant.
