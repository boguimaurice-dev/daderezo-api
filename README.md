# DADEREZO v3.0 — Système Multi-Agents de Supervision Réseau (100 % Lecture Seule)

**DADEREZO** est un système autonome multi-agents de supervision réseau conçu pour la **Communauté Sainte Marie de Bouaké** (ainsi que pour les écoles, associations et structures multi-sites).

Il orchestre **4 agents spécialisés** (`SENTINEL-SEC`, `TOPO-SCAN`, `DIAG-NET`, `OPS-DISPATCH`) connectés à une persistance permanente **Supabase PostgreSQL 17** (ou PostgreSQL / SQLite), pilote une console **vocale & écrite** pour l'Administrateur Superviseur Général, et opère **strictement en lecture seule** avec anti-injection de prompt et validation humaine (*Human-in-the-Loop*).

---

## Architecture Multi-Agents

```text
[Réseau local / PC Bouaké]                             [Cloud Vercel + Supabase PostgreSQL 17]
  devices.json + collector.py
        │
        └──► agent_client.py (--task-poll 5s) ──► api.py ──► storage.py (Supabase / PG / SQLite)
                                                    │
                                                    └──► agent_engine.py (4 Agents + Audit + HITL)
                                                            ├── 01 SENTINEL-SEC (Anti-injection & Lecture seule)
                                                            ├── 02 TOPO-SCAN    (Matrice LAN vs Internet & Latence)
                                                            ├── 03 DIAG-NET     (Corrélation FAI & Ticket Opérateur)
                                                            └── 04 OPS-DISPATCH (Ordres sonde & Validation humaine)
```

---

## Fonctionnalités clés

- **100 % multi-plateforme** : fonctionne sous **Windows**, **Linux / Raspberry Pi** et **macOS**.
- **Diagnostic intelligent LAN vs FAI** : distingue une coupure du routeur local (`gw_status`) d'une coupure Internet fournisseur (`internet_status` par ping ICMP + repli HTTPS/DNS).
- **Sondage parallèle rapide** : vérification simultanée de la disponibilité et de la latence (`ms`) de tous les équipements détectés.
- **Inventaire persistant & zéro fausse alerte en boucle** :
  - Chaque nouvelle adresse MAC n'est signalée **qu'une seule fois** à sa première apparition.
  - Les pannes sont signalées après dépassement du seuil d'échecs (`fail_threshold`) avec notification automatique de **rétablissement**.
  - En cas de coupure Internet, les alertes restent tamponnées dans `daderezo.db` et sont transmises dès le retour de la connexion.
- **Sécurité API (`DADEREZO_API_KEY`)** : protection optionnelle des écritures par en-tête `X-API-Key`, requêtes SQL intégralement paramétrées, et file de tâches de diagnostic limitée aux actions en lecture seule (`scan`, `sweep`, `diagnostic`, `rapport`).

---

## Démarrage rapide

### 1. Lancer l'API et le tableau de bord web

```bash
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

- **Tableau de bord interactif** : `http://localhost:8000/ui` (ou directement `http://localhost:8000/` dans un navigateur)
- **État JSON du service** : `http://localhost:8000/health`
- **Documentation Swagger** : `http://localhost:8000/docs`

### 2. Lancer la sonde sur un poste du réseau local

**Vers l'API (local ou Render) :**
```bash
python agent_client.py --api http://localhost:8000 --agent sainte-marie-bouake --nom "Sainte Marie de Bouaké"
```

Options utiles :
- `--once` : exécute une seule collecte + envoi puis quitte (idéal pour tester ou via tâche planifiée / `cron`)
- `--sweep` : effectue un balayage ping court du sous-réseau local avant lecture ARP pour découvrir les équipements silencieux
- `--interval 300` : intervalle en secondes entre deux collectes (défaut : `300` s = 5 min)
- `--api-key <CLE>` : clé d'authentification si `DADEREZO_API_KEY` est activée sur le serveur

**En mode 100 % hors-ligne (sans serveur API) :**
```bash
python orchestrator.py
```
Génère et met à jour automatiquement le fichier `dashboard.html` local.

---

## Personnaliser l'inventaire (`devices.json`)

Déclarez vos équipements connus et adresses MAC autorisées dans `devices.json` pour nommer vos routeurs/relais et éviter qu'ils ne soient signalés comme appareils inconnus :

```json
{
  "site_name": "Communauté Sainte Marie de Bouaké",
  "internet_targets": ["1.1.1.1", "8.8.8.8"],
  "fail_threshold": 2,
  "devices": {
    "192.168.8.1": {
      "name": "Box FAI principale",
      "type": "fai_box",
      "zone": "Accès FAI",
      "critical": true
    },
    "192.168.8.57": {
      "name": "Passerelle / Routeur principal",
      "type": "gateway",
      "zone": "Cœur réseau",
      "critical": true
    }
  },
  "authorized_macs": {
    "cc:d8:43:32:45:c8": { "name": "Routeur principal", "zone": "Cœur réseau" }
  }
}
```

---

## Tests automatisés

```bash
python -m unittest discover -s tests -v
```
