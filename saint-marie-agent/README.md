# Agent Sœur Marie — Hôtellerie Monastique Sainte-Marie de Bouaké

Agent d'accueil et d'hôtellerie monastique dans l'esprit de saint Benoît. 
Capable de recevoir les hôtes en ligne, de collecter les informations de demade,
et de les relayer aux frères hôteliers du monastère.

---

## 🚀 Lancement

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer le serveur API
python saint_marie_app.py
```

- **API**: http://localhost:8000
- **Chat Hôte**: http://localhost:8000/
- **Tableau de bord Monks**: http://localhost:8000/dashboard

---

## 📁 Structure du projet

```
saint-marie-agent/
├── saint_marie_agent.py      # Moteur de dialogue et outils d'action
├── saint_marie_db.py         # Côté base de données (SQLite)
├── saint_marie_app.py        # Serveur FastAPI + API REST
├── knowledge.py              # Base de connaissances du monastère
└── static/
    ├── chat.html             # Interface chat pour les hôtes
    └── dashboard.html        # Tableau de bord pour les moines hôteliers
```

---

## 🎯 Fonctionnalités

### Pour les hôtes (chat en ligne)
- **Accueil chaleureux** dans l'esprit de saint Benoît
- **Renseignements pratiques** : horaires de prière, comment s'y rendre, régimes
- **Prise de contact** : collecte des informations (nom, provenance, dates, besoins)
- **Relais automatique** : transmission de la fiche de demande au groupe WhatsApp des frères

### Outils d'action de l'agent
- `verifier_disponibilite(dates, nb_personnes)` — Vérification des places
- `enregistrer_demandes(hote, dates, motif, besoins)` — Enregistrement de la demande
- `notifier_hoteliers(demande_id)` — Notification aux frères
- `repondre_hote(demande_id, message)` — Réponse à l'hôte

### Pour les moines hôteliers (tableau de bord)
- Vue des demandes entrantes (état, dates, personnes)
- Notifications reçues des frères
- Journal des actions
- Marquage des demandes comme lues

---

## 🔧 Configuration

### Base de données
La base SQLite est créée automatiquement au premier lancement :
- `saint_marie.db` — Stocke les conversations, demandes, notifications

### Sources de connaissances
Les informations du monastère proviennent de :
- Site officiel : https://benedictinsbouake.com
- Fichiers de conception : « Hôtellerie & Accueil monastique »
- Spécifications de l'utilisateur

---

## 📱 Intégration WhatsApp

Pour brancher l'agent sur le numéro WhatsApp Business `+225 97 00 80 52` :

1. Configurer un **WhatsApp Business** (Meta) avec le numéro du monastère
2. Activer **WhatsApp Cloud API**
3. Relier l'API Cloud à l'application Saint-Marie
4. Configurer le **webhook** pointant vers `/api/chat`
5. Activer les **notifications** vers le groupe WhatsApp des frères

---

## 🌿 Éthique monastique

L'agent Sœur Marie incarne l'esprit de saint Benoît :
- Accueil chaleureux et fraternel
- Calme et écoute
- Clairvoyance dans le relais vers les frères
- Respect de la clôture monastique et des horaires

> *« Tous les hôtes qui se présentent seront reçus comme le Christ. »*
> — Règle de saint Benoît, Chapitre 64

---

## ✝️ Contact

**Monastère Bénédictin Sainte-Marie de Bouaké**
- 🌐 Site : https://benedictinsbouake.com
- 📞 Accueil : 07 47 52 05 57
- 📞 Hôtellerie : 07 97 00 80 52
- 📍 Bouaké, Côte d'Ivoire
