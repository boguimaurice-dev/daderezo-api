# Terminer la mise en production des logs

## État vérifié

- Code poussé sur `arena/a2f22b58-daderezo-api` ; PR :
  https://github.com/boguimaurice-dev/daderezo-api/pull/17
- 52 tests locaux passent. Les avertissements existants concernent les identifiants
  OpenAPI GET/HEAD en double et une dépréciation de TestClient ; aucun test ne les masque.
- Prévisualisation Vercel du commit `da9fe13` : READY.
  https://daderezo-fcdpe0vlj-bogui-maurices-projects.vercel.app
  READY confirme la construction, pas le fonctionnement de tous les parcours réels.
- Migration additive Supabase appliquée sur `daderezo-supervision`, puis vérifiée :
  tenant_id / actor / request_id, index tenant et horodatage présents.
  RLS activée ; aucun SELECT accordé à anon/authenticated. Aucun log supprimé.
- Pas de fusion dans main, pas de déploiement de production des corrections,
  pas de purge ni tâche planifiée créée.

## 1. Vérifier la prévisualisation dans le navigateur

1. Ouvrir le lien de prévisualisation et s'authentifier auprès de Vercel si demandé.
2. Utiliser un compte de test DADEREZO ; ne pas faire d'essai de coupure réseau réelle.
3. Se connecter, ouvrir « Preuves d'Audit IA & Journal d'Incidents » et actualiser :
   une entrée AUTH /auth/login doit apparaître dans cet espace.
4. Poser deux questions de suite au superviseur : vérifier la continuité de conversation
   et que l'identifiant de session ne s'allonge pas à chaque tour.
5. Se déconnecter, se reconnecter : vérifier l'entrée /auth/logout.
6. Avec un autre espace privé dans un autre profil navigateur, vérifier que les
   premières traces/conversations n'apparaissent pas. La démo ne doit pas les montrer.
7. Les échecs anonymes sont classés system : ils ne sont volontairement pas visibles
   dans la démo. Consultation administrateur en base uniquement.

Attention : la prévisualisation peut utiliser la même base que la production.
Ne pas tester la suppression de données ni des commandes réseau sur des sites réels.

## 2. Contrôler GitHub puis fusionner

1. Ouvrir la PR #17, onglet Checks. Attendre la fin des analyses de sécurité.
2. Si le job « Tests Unitaires & Intégration » n'apparaît pas, ne pas déduire qu'il
   a réussi : vérifier Actions > DADEREZO CI & Contabo Auto-Deploy, les autorisations
   et une éventuelle demande d'approbation. La suite locale a bien exécuté 52 tests.
3. En cas de contrôle rouge, ne pas fusionner : transmettre le nom du contrôle et
   son erreur (sans secrets). Les anciens logs Actions ne sont pas récupérables
   depuis ce sandbox lorsque GitHub redirige vers son domaine de stockage non autorisé.
4. Quand les contrôles disponibles et la recette sont satisfaisants, fusionner la PR.
5. Dans Vercel > daderezo-api > Deployments, vérifier que le nouveau déploiement
   est Production / Ready et correspond au commit de fusion de la PR #17.
   Si aucun déploiement ne se lance, redéployer explicitement main depuis Vercel.
6. Refaire connexion + affichage d'audit sur https://daderezo-api-nine.vercel.app.

## 3. Vérifier Contabo (si ce VPS est utilisé)

Depuis votre terminal SSH, sans coller de clé ou mot de passe dans le chat :

```sh
cd /opt/daderezo
# Vérifier la synchronisation GitOps et le démarrage des services :
git log -1 --oneline
docker compose -f docker-compose.contabo.yml ps
docker compose -f docker-compose.contabo.yml logs --tail=100 daderezo-api daderezo-watchdog
# Vérifier la destination de stockage, sans afficher de secret :
docker compose -f docker-compose.contabo.yml exec -T daderezo-api python -c 'import storage; print(storage.get_backend_mode())'
```

Le backend attendu est `supabase` si c'est votre architecture prévue. Si vous voyez
`sqlite` par surprise, ne lancez pas la maintenance : corrigez la configuration
SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY dans votre gestionnaire de secrets,
puis recréez les services. Ne recopiez pas leurs valeurs dans le chat.

## 4. Sauvegarder et valider la rétention avant toute purge

1. Vérifier qu'une sauvegarde restaurable de la base existe, selon le plan Supabase.
   Une migration de schéma réussie n'est pas une sauvegarde.
2. En tant qu'administrateur, prévisualiser le volume candidat dans SQL Editor :

```sql
SELECT count(*) AS candidats_a_purger
FROM public.agent_audit_logs
WHERE ts < (to_char((now() AT TIME ZONE 'UTC') - interval '90 days',
                    'YYYY-MM-DD"T"HH24:MI:SS.US') || '+00:00');
```

Les horodatages sont stockés en texte. Les nouvelles entrées sont en UTC ISO 8601 ;
contrôler le format des anciennes entrées avant d'appliquer une purge globale.
3. Confirmer la durée désirée (minimum 90 jours) et le sort des traces historiques.
4. Seulement après cette validation, tester manuellement sur le VPS :

```sh
cd /opt/daderezo
docker compose -f docker-compose.contabo.yml run --rm --no-deps daderezo-api python audit_maintenance.py --days 90
```

Cette commande **supprime définitivement** les traces plus anciennes que la durée.
5. Si le test est concluant, installer via `crontab -e` une tâche quotidienne,
   en adaptant le chemin réel du dépôt :

```cron
15 2 * * * cd /opt/daderezo && /usr/bin/docker compose -f docker-compose.contabo.yml run --rm --no-deps daderezo-api python audit_maintenance.py --days 90 >> /var/log/daderezo-audit-maintenance.log 2>&1
```

Vérifier le chemin de docker avec `command -v docker`, les droits de l'utilisateur,
la rotation de ce fichier de sortie et la remontée d'alerte en cas d'échec du cron.
Si vous n'utilisez pas Contabo, ne copiez pas ce cron : choisir un ordonnanceur
adapté à votre hébergement. Aucun accès SSH au VPS n'était disponible ici.

## Limites à ne pas oublier

- REPORTED = résultat déclaré par la sonde, pas vérification physique indépendante.
- Panne de base = perte possible de certaines traces ; les erreurs d'écriture sont
  signalées sur stderr, sans file durable de secours.
- Le journal n'est pas inaltérable (pas de WORM/signature cryptographique).
- Les conversations, métriques, alertes et sauvegardes ont des rétentions distinctes.

Documentation technique complète : `JOURNALISATION.md`.
