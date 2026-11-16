# Journalisation DADEREZO

## Déploiement obligatoire

1. Sauvegarder la base. Sur Supabase/PostgreSQL, exécuter
   `migrations/20261115_audit_tenants.sql` **avant** le nouveau code.
   Sur SQLite, les colonnes/index sont ajoutés automatiquement par `init_db()`.
2. Sur Supabase, activer RLS et révoquer les droits des rôles clients comme indiqué
   à la fin du SQL. Ne jamais exposer la clé service_role dans le navigateur.
3. Déployer l'API et le watchdog ensemble. Vérifier inscription, connexion,
   déconnexion, erreur 401 et journal dans deux organisations distinctes.
4. Planifier la maintenance quotidienne avec les mêmes variables de base que l'API :
   `python audit_maintenance.py --days 90`.
   Exemple cron dans un environnement où ces variables sont déjà chargées :
   `15 2 * * * cd /opt/daderezo && .venv/bin/python audit_maintenance.py --days 90`.
   Superviser le code de sortie du job. Le script refuse une durée inférieure à 90 jours.

Aucune migration distante ni tâche planifiée n'est créée automatiquement par le code.
Ne pas annoncer la rétention opérationnelle avant ces étapes et une vérification des sauvegardes.
La purge vise le journal d'audit uniquement, pas les conversations, mesures ou sauvegardes.

## Données et accès

`agent_audit_logs` : horodatage UTC, tenant_id, acteur, request_id, session,
agent, action, outil, statut, durée, détails limités à 1000 caractères.
L'API renvoie `X-Request-ID` pour rapprocher requêtes, erreurs et outils d'une mission.
La requête SQL/REST filtre **avant** LIMIT, avec égalité stricte du tenant.
La démo n'a accès qu'au tenant public-demo, jamais aux lignes système ou privées.
Les anciens logs sans tenant fiable restent uniquement consultables par l'administrateur
via la base : aucun rattachement automatique par recherche dans du texte.
Les anciennes conversations non préfixées ne sont plus exposées par l'API ;
les conserver pour un éventuel rattachement manuel vérifié.

Les nouvelles sessions IA sont préfixées par l'organisation côté serveur, y compris
lorsque deux clients utilisent le même identifiant de conversation.
Le watchdog rattache ses incidents au tenant de la sonde ; sans tenant, ils restent système.

## Événements

- Inscription, connexion locale/Google, vérification 2FA et déconnexion : route,
  statut HTTP, durée, peer_ip, indicateur session_issued. Une réponse 200 avec
  session_issued=false peut être une étape 2FA, **pas une connexion finalisée**.
- Échecs 4xx/5xx (dont 401/403/429) : route paramétrée, pas URL brute ni query string.
- Échecs d'authentification sans identité validée : tenant **system**, acteur anonymous.
  Ils ne sont pas montrés dans la démo ; consultation administrateur en base.
  On ne rattache pas un échec à un compte sur la seule foi d'un e-mail fourni.
- Actions des agents, sécurité, politiques Internet, box, médias, validations humaines :
  journal métier existant enrichi du tenant, de l'acteur et de la corrélation.
- Acquittements de tâches : PROBE / task_ack / REPORTED, numéro de tâche et retour sonde.
  QUEUED signifie mise en file. REPORTED signifie déclaration de la sonde,
  **pas preuve indépendante** d'une exécution réussie ou d'un accès WAN réellement coupé.
  Certains anciens statuts métier (APPLIED/OPTIMIZED/ON/OFF) représentent l'état logique
  enregistré ; consulter télémétrie et résultat de tâche avant de conclure à un effet physique.

peer_ip vient de la connexion ASGI, sans faire confiance à X-Forwarded-For arbitraire.
Derrière proxy, configurer les proxies de confiance du serveur pour obtenir l'IP réelle.
La déconnexion efface le cookie : elle n'ajoute pas de liste de révocation des JWT.

## Erreurs et confidentialité

Les erreurs HTTP vont au journal central. Les exceptions non gérées et les échecs
 d'écriture d'audit sont aussi signalés sur stderr via Python logging (type d'exception,
 identifiant de requête, sans message d'exception susceptible de contenir un secret).
Les écritures du middleware passent par le pool de threads, pas par l'event loop.
Une panne de stockage ne doit pas casser une réponse déjà produite : elle est signalée
sur stderr, mais il n'y a pas encore de file durable de secours pour ces traces perdues.

Ne sont pas collectés par ce middleware : corps de requête/réponse, mots de passe,
headers Authorization/Cookie, jetons et query strings. Un masquage défensif s'applique
également aux détails métier ; éviter malgré tout d'y injecter des secrets ou du texte libre sensible.
Les IP, e-mails, noms et titres de fichiers peuvent constituer des données personnelles :
restreindre l'accès, documenter les finalités et appliquer les règles locales de conservation.

La console est à consulter dans les runtime logs de l'hébergeur ou avec :
`docker compose -f docker-compose.contabo.yml logs --tail=100 daderezo-api daderezo-watchdog`.
Configurer la rétention/rotation côté hébergeur ou Docker pour stdout/stderr.
Le journal local `orchestrator.log` utilise désormais 5 rotations de 5 Mio.
Les sondes conservent leurs mesures/alertes dans `daderezo.db` ; les alertes non synchronisées
restent en attente d'envoi. Cette base locale a son propre cycle de vie.

## Limites connues

Le journal n'est pas un stockage WORM ni signé cryptographiquement. Les administrateurs
base peuvent le modifier. La disponibilité, le volume, les sauvegardes et l'exécution
de la purge restent à superviser. Les appels directs internes sans contexte HTTP
sont classés system sauf tenant explicitement fourni par le watchdog.

## Tests

`DADEREZO_AUTH_SECRET=test-only .venv/bin/python -m pytest -q`

Tests additionnels : isolation stricte, absence de fuite vers la démo, masquage,
connexion/déconnexion et corrélation, 500 sans fuite de secret, rétention,
filtre Supabase et absence de verrouillage Redis à la première tentative.

## Vérification complémentaire du 15 novembre 2026

- Migration additive `audit_tenant_identity_and_indexes` appliquée via le connecteur
  sur `daderezo-supervision` (`cgcygjznrvojpodzlxys`). Lecture de contrôle : les trois
  colonnes et les deux index sont présents. RLS était déjà activée ; les rôles
  `anon` et `authenticated` n'ont pas le droit SELECT sur la table. Aucun ancien log
  n'a été effacé ou automatiquement réattribué.
- Production Vercel observée sur le commit `02c198d` (ancienne version).
  Ces modifications ne sont donc pas actives tant qu'un nouveau déploiement n'est pas terminé.
- Docker et Vercel incluent explicitement les deux nouveaux modules importés.
- CI utilise désormais pytest et un secret de test isolé, pour exécuter aussi les
  nouveaux tests de sécurité (la découverte unittest seule les aurait ignorés).
- Une tâche absente ou appartenant à une autre sonde n'est plus acquittée avec succès.
- Les réponses 500 du middleware sont génériques avec request_id. Pas de propagation
  du message d'exception vers l'utilisateur ou du traceback brut vers Uvicorn.
- Identifiants de session externes bornés à 128 caractères ; le préfixe interne du
  tenant n'est pas renvoyé au client (évite l'accumulation du préfixe à chaque tour).

La planification de purge n'a pas été activée à distance : vérifier les sauvegardes
et valider la conservation des anciennes traces avant toute suppression automatique.
Pour installer les dépendances de test :
`python -m pip install -r requirements.txt -r requirements-dev.txt`.
