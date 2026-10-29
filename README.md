# DADEREZO v4.0 — Plateforme SaaS Multi-Agents de Supervision, Pilotage Actif Réseau, Optimisation Multi-Box & Partage Multimédia

**DADEREZO** est une plateforme SaaS multi-agents conçue pour superviser, optimiser et piloter les réseaux locaux (**écoles, communautés, centres de santé, PME multi-sites**).

La version **v4.0** réunit **5 agents spécialisés** (`SENTINEL-SEC`, `TOPO-SCAN`, `DIAG-NET`, `NET-CONTROL`, `MEDIA-HUB`) connectés à **Supabase PostgreSQL 17 + Supabase Storage** (ou PostgreSQL / SQLite), avec :
1. **Contrôle granulaire Internet ON / OFF à 3 niveaux** :
   - **Niveau 1 — Box Principale (`global`)** : couper ou rétablir l'accès Internet WAN de tout le site tout en conservant le réseau local (LAN, imprimantes, partage interne) 100 % actif.
   - **Niveau 2 — Sous-réseau CIDR ou Zone (`subnet` / `zone`)** : isoler ou ouvrir Internet pour une zone entière (`Visiteurs`, `Communauté`, `Administration`, `Accueil`) ou un sous-réseau (`192.168.8.0/24`).
   - **Niveau 3 — Appareil précis (`device`)** : interrupteur ON/OFF en 1 clic ou par commande vocale/écrite sur n'importe quel poste (IP ou MAC).
2. **Configuration & Optimisation Automatique Multi-Box** :
   - Planification coordonnée des canaux Wi-Fi sans interférence (`1 / 6 / 11` en 2.4 GHz, `36 / 44 / 149` en 5 GHz), DNS rapides (`1.1.1.1` / `9.9.9.9`), QoS Anti-Bufferbloat et MTU optimal (`1492` Fibre / `1420` 4G-5G LTE).
   - Génération de commandes multi-pilotes (`Huawei HiLink`, `MikroTik RouterOS`, `OpenWrt UCI`, `Linux nftables/iptables`, `Windows Firewall`).
3. **Partage de Fichiers & Données Multimédias (Cloud + LAN Local)** :
   - Dépôt, prévisualisation intégrée (`<img>`, `<audio>`, `<video>`) et téléchargement de documents, images, sons et vidéos par zone.
   - Serveur HTTP Multimédia LAN intégré (`--media-port 8090`) accessible sur le Wi-Fi/Ethernet local **même lorsque Internet est coupé**.
4. **Isolation SaaS Multi-Tenant Privée (`🔐 Espace Privé`)** :
   - Les visiteurs publics n'accèdent qu'au banc de simulation isolé (`simulation-bouake`).
   - Chaque organisation crée son espace privé (`/auth/signup`) et reçoit une clé sonde dédiée (`dzk_...`) garantissant que ses équipements, ses box et ses fichiers restent strictement privés.

---

## Architecture Multi-Agents v4.0

```text
[Réseau local Client + Box]                           [Cloud Vercel + Supabase PG17 + Storage]
  devices.json + collector.py + net_controller.py
        │
        └──► agent_client.py (--task-poll 5 --media-port 8090)
                    │
                    └──► api.py ──► storage.py (Supabase PG17 / Storage / SQLite)
                           │
                           └──► agent_engine.py (5 Agents + Audit + HITL)
                                   ├── 01 SENTINEL-SEC (Anti-injection & Isolation SaaS privée)
                                   ├── 02 TOPO-SCAN    (Matrice LAN vs Internet & Latence)
                                   ├── 03 DIAG-NET     (Corrélation FAI & Ticket Opérateur)
                                   ├── 04 NET-CONTROL  (Switches Internet 3 niveaux & Optimisation Box)
                                   └── 05 MEDIA-HUB    (Partage Docs/Images/Audios/Vidéos & HITL)
```

---

## Démarrage rapide

### 1. Lancer l'API et le Poste Superviseur

```bash
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

- **Accueil SaaS & Démo Live** : `http://localhost:8000/` (Mode Clair & Mode Sombre)
- **Poste du Superviseur Général** : `http://localhost:8000/ui` (ou `/ui?auth=1` pour créer un Espace Privé)
- **État JSON du service** : `http://localhost:8000/health`
- **Documentation OpenAPI** : `http://localhost:8000/docs`

### 2. Lancer la sonde privée sur un poste du réseau local

```bash
python agent_client.py --api https://daderezo-api-nine.vercel.app --agent mon-site-principal --nom "Mon Réseau Privé" --api-key dzk_VOTRE_CLE_PRIVEE --task-poll 5 --media-port 8090
```

- `--api-key dzk_...` : rattache la sonde exclusivement à votre espace privé (invisible du public).
- `--media-port 8090` : démarre le Hub Multimédia LAN local (`http://<IP_LOCALE>:8090`) pour partager les fichiers même hors Internet.
- `DADEREZO_ACTIVE_CONTROL=1` (variable d'environnement optionnelle sur passerelle Linux/Windows) : active l'application matérielle directe des règles pare-feu locales en plus du journal de commandes routeur.

---

## Tests automatisés

```bash
python -m unittest discover -s tests -v
```
