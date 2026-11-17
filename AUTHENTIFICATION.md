# Google, QR 2FA et retour accueil

## Corrections

- Suppression du faux parcours Google : plus de saisie d'e-mail traitée comme une preuve.
  Google Identity Services affiche son bouton officiel, puis le serveur utilise google-auth
  pour vérifier signature, expiration, audience et émetteur du jeton. Le nonce doit correspondre
  au cookie HttpOnly de courte durée posé par `/auth/google/config`.
- Si GOOGLE_CLIENT_ID manque, Google est explicitement indisponible. Aucun identifiant
  factice, ni fallback user_info, n'est accepté.
- Google respecte le 2FA DADEREZO : pas de session finale avant vérification du code.
- Jetons internes signés/vérifiés avec PyJWT, HS256 imposé et audiences distinctes
  pour session et 2FA, émetteur fixé, expiration/version obligatoires.
- QR SVG généré localement avec qrcode, transporté en data URI ; aucune clé envoyée à un
  service QR externe. Secret manuel conservé comme alternative. L'activation doit utiliser
  le secret et le jeton d'enrôlement signé, liés au compte pendant 10 minutes.
- Un 2FA déjà actif ne peut pas être écrasé avec un nouveau secret.
  Désactivation : session + mot de passe + TOTP pour un compte local ; session Google
  + TOTP pour un compte Google sans mot de passe local. Limitation des tentatives.
- QR, secret et champ du code effacés du DOM à l'annulation/fermeture/changement de compte.
- Liens « Accueil DADEREZO » (menu) et « ← Accueil » (barre supérieure), disponibles
  aussi en mode Travail sans basculer la simulation.
- Suppression du cache partagé de télémétrie privée du service worker (les cookies HttpOnly
  ne permettent pas au worker de distinguer les comptes). En mode hors connexion, ces appels
  renvoient 503 plutôt que les dernières mesures d'un autre utilisateur. Le shell HTML reste
  disponible hors ligne. La version du cache est incrémentée pour éliminer les anciens caches.

## Sécurité : sessions antérieures

Le mécanisme Google précédent acceptait des profils non vérifiés et pouvait émettre une session
pour un e-mail arbitraire. Ce constat est une vulnérabilité du code, pas une preuve d'exploitation.
Les nouveaux jetons portent `auth_version=2`. Les anciens jetons SaaS et challenges sans version
sont refusés après déploiement : **tous les utilisateurs doivent se reconnecter une fois**.
Les clés des sondes ne sont pas automatiquement renouvelées, pour ne pas arrêter les installations.
En cas de suspicion d'accès frauduleux, faire analyser les comptes/données et renouveler les clés
sondes concernées via une procédure administrateur contrôlée. Le journal ancien n'est pas exhaustif.
Mettre à jour Vercel ET Contabo, s'il sert aussi l'API : une ancienne instance conserverait la faille.

## Ce qui manque pour rendre Google utilisable en production

Vérification des variables du projet Vercel daderezo-api : **GOOGLE_CLIENT_ID absent**.
L'agent n'a pas d'accès à Google Cloud Console et ne peut pas inventer un client OAuth.
Aucun client_secret n'est nécessaire pour le parcours GIS ID token utilisé ici.

1. Dans Google Cloud Console, sélectionner/créer le projet voulu.
2. Ouvrir Google Auth Platform (ou API et services > Écran de consentement OAuth).
   Configurer nom de l'application, audience et contacts requis.
   Si l'application reste en test, ajouter les comptes autorisés comme utilisateurs de test.
3. Dans Clients / Identifiants, créer un client OAuth **Application Web**.
4. Ajouter l'origine JavaScript autorisée exacte :
   `https://daderezo-api-nine.vercel.app`
   Ajouter séparément votre domaine personnalisé, si utilisé, ainsi qu'une URL de preview
   stable si vous souhaitez tester là-bas. Pas de chemin `/ui`, pas de wildcard.
5. Copier l'ID client public terminé par `.apps.googleusercontent.com`.
6. Vercel > daderezo-api > Settings > Environment Variables : créer `GOOGLE_CLIENT_ID`
   avec cet ID pour Production (et Preview si voulu), puis redéployer.
   Ne pas ajouter un client_secret au navigateur ni au dépôt.
7. Si Contabo sert l'API, renseigner également GOOGLE_CLIENT_ID dans son `.env`, puis
   recréer le conteneur API ; docker-compose transmet désormais cette variable.
8. Vérifier `/auth/google/config` : `enabled: true`, puis ouvrir Espace Privé et utiliser
   le vrai bouton Google. Après activation du 2FA, une nouvelle connexion Google doit demander
   le code avant de donner accès au réseau privé.

Ne pas confondre ces paramètres avec Supabase Auth : DADEREZO utilise ici ses propres sessions
et le flux Google Identity Services. Activer seulement le fournisseur Google dans Supabase
ne configure pas ce parcours.

## Utilisation du QR

1. Se connecter avec e-mail/mot de passe (ou Google une fois configuré).
2. Ouvrir Espace Privé > Configurer 2FA.
3. Dans Authenticator, choisir Ajouter > Scanner un QR code ; scanner le QR affiché.
4. Saisir dans DADEREZO le code à 6 chiffres affiché, puis Activer 2FA.
5. Se déconnecter et se reconnecter pour vérifier le challenge.

Garder la clé d'enrôlement dans un coffre sûr avant fermeture si une sauvegarde est nécessaire.
Ni le QR ni cette clé ne doivent être envoyés dans le chat. Aucun code de récupération
à usage unique n'est encore fourni : la perte du téléphone ET de la clé nécessite une
récupération administrateur vérifiée, pas un contournement public du 2FA.

## Vérifications effectuées

- Tests Python : rejet des profils clients, signatures/claims/nonce invalides, Google non
  configuré, Google + TOTP, QR SVG local, secret lié au compte, expiration, remplacement interdit,
  limitation des tentatives, vecteur RFC 6238 et invalidation des anciennes sessions.
- `tests/auth_ui.cjs` (jsdom, simulation DOM) : SDK Google et callback, challenge 2FA,
  affichage/nettoyage du QR et liens accueil en mode travail. Cela ne remplace pas une vraie
  connexion au compte Google dans un navigateur avec le client OAuth de production.
- Dépendances de test : requirements-dev.txt + jsdom@26.1.0 (installation dans .cache/auth-ui).
  `NODE_PATH=.cache/auth-ui/node_modules node tests/auth_ui.cjs`.

## Incident : « Erreur interne » après le bouton Google

La base Supabase distante utilisait encore la table saas_users historique à huit colonnes.
Les cinq colonnes du profil Google et du facteur TOTP étaient absentes : un PATCH avatar_url
ou un INSERT de compte Google pouvait échouer avant l'apparition du challenge 2FA.

Migration distante `saas_users_google_totp_columns` appliquée et relue : auth_provider,
is_email_verified, avatar_url, totp_secret et totp_enabled présents, avec les types utilisés
par storage.py (indicateurs entiers 0/1). Cache PostgREST notifié pour rechargement.
Aucun compte, mot de passe, clé de sonde ou facteur existant n'a été modifié.
Les anciens comptes dont le statut d'e-mail est inconnu ne sont pas déclarés vérifiés
par défaut. Les rôles Supabase anon/authenticated ne peuvent plus lire saas_users ;
la session DADEREZO passe par l'API avec sa clé service_role, dont les droits restent présents.

Le correctif de base est utilisable immédiatement par l'API déjà déployée. La migration
versionnée est dans migrations/20261116_saas_users_google_totp.sql pour les autres installations.
storage.init_db() met également à niveau les anciennes tables PostgreSQL directes, comme SQLite.
CI inclut désormais PostgreSQL 17 et deux tests d'intégration dans des schémas temporaires :
upgrade automatique et SQL de production exécuté deux fois, avec préservation du facteur existant.
Localement, ces deux tests sont ignorés si DADEREZO_TEST_POSTGRES_URL n'est pas renseigné.
La connexion réelle de l'utilisateur reste à retester ; aucun code Authenticator ni secret
ne doit être partagé pour ce diagnostic.
