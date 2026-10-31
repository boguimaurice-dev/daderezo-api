#!/usr/bin/env bash
# =============================================================================
# DADEREZO v4.3 — Liaison Automatique GitOps pour VPS Contabo (Ubuntu / Debian)
# =============================================================================
# Exécutez UNE SEULE FOIS sur votre VPS Contabo :
#   curl -fsSL https://daderezo-api-nine.vercel.app/download/contabo_bootstrap.sh | sudo bash
#
# Ce script :
#   1. Installe Docker + Docker Compose + Git si absents.
#   2. Clone boguimaurice-dev/daderezo-api dans /opt/daderezo.
#   3. Configure localement votre fichier /opt/daderezo/.env (DeepSeek, Supabase, Telegram)
#      SANS exposer vos clés dans aucun chat externe.
#   4. Démarre l'API, la Sentinelle 24/7 (contabo_watchdog.py), Ollama et Caddy HTTPS.
#   5. Active le démon systemd `daderezo-gitops.timer` (vérifie GitHub `main` toutes les 2 min
#      et redéploie automatiquement chaque nouvelle version poussée depuis Arena / GitHub !).
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/daderezo"
REPO_URL="https://github.com/boguimaurice-dev/daderezo-api.git"

echo "================================================================="
echo "  DADEREZO v4.3 — Installation & Liaison Automatique VPS Contabo "
echo "================================================================="

if [[ $EUID -ne 0 ]]; then
  echo "Veuillez lancer ce script avec sudo (ex: sudo bash contabo_bootstrap.sh)."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl ca-certificates openssl >/dev/null

if ! command -v docker >/dev/null 2>&1; then
  echo "[1/5] Installation de Docker Engine & Docker Compose..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
else
  echo "[1/5] Docker déjà installé ($(docker --version))."
fi

echo "[2/5] Synchronisation du dépôt GitHub dans ${INSTALL_DIR}..."
if [[ -d "${INSTALL_DIR}/.git" ]]; then
  git -C "${INSTALL_DIR}" fetch origin main
  git -C "${INSTALL_DIR}" reset --hard origin/main
else
  rm -rf "${INSTALL_DIR}"
  git clone --branch main "${REPO_URL}" "${INSTALL_DIR}"
fi

ENV_FILE="${INSTALL_DIR}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[3/5] Configuration sécurisée locale (${ENV_FILE})..."
  RAND_KEY="$(openssl rand -hex 12)"
  RAND_SEC="$(openssl rand -hex 32)"

  if [[ -t 0 ]]; then
    read -r -p "Domaine HTTPS (laissez vide pour utiliser directement l'IP Contabo sur :80) : " IN_DOMAIN || true
    read -r -p "URL Supabase [https://cgcygjznrvojpodzlxys.supabase.co] : " IN_SB_URL || true
    read -r -s -p "Clé SUPABASE_SERVICE_ROLE_KEY (masquée, Entrée pour SQLite local) : " IN_SB_KEY || true
    echo ""
    read -r -s -p "Clé DEEPSEEK_API_KEY (sk-..., masquée, Entrée pour utiliser Ollama local) : " IN_DS_KEY || true
    echo ""
    read -r -p "Token Bot Telegram optionnel (DADEREZO_TELEGRAM_BOT_TOKEN) : " IN_TG_TOK || true
    read -r -p "Chat ID Telegram optionnel (DADEREZO_TELEGRAM_CHAT_ID) : " IN_TG_CHAT || true
  else
    IN_DOMAIN=""
    IN_SB_URL="https://cgcygjznrvojpodzlxys.supabase.co"
    IN_SB_KEY=""
    IN_DS_KEY=""
    IN_TG_TOK=""
    IN_TG_CHAT=""
  fi

  cat > "${ENV_FILE}" <<EOF
DADEREZO_DOMAIN=${IN_DOMAIN:-:80}
SUPABASE_URL=${IN_SB_URL:-https://cgcygjznrvojpodzlxys.supabase.co}
SUPABASE_SERVICE_ROLE_KEY=${IN_SB_KEY:-}
DADEREZO_API_KEY=${RAND_KEY}
DADEREZO_AUTH_SECRET=${RAND_SEC}
DEEPSEEK_API_KEY=${IN_DS_KEY:-}
DADEREZO_LLM_PROVIDER=${IN_DS_KEY:+deepseek}
DADEREZO_LLM_MODEL=${IN_DS_KEY:+deepseek-chat}
DADEREZO_WATCHDOG_INTERVAL=60
DADEREZO_TELEGRAM_BOT_TOKEN=${IN_TG_TOK:-}
DADEREZO_TELEGRAM_CHAT_ID=${IN_TG_CHAT:-}
DADEREZO_ALERT_WEBHOOK_URL=
EOF
  chmod 600 "${ENV_FILE}"
  echo "  -> Fichier ${ENV_FILE} créé (permissions 600). Vous pourrez l'éditer via: sudo nano ${ENV_FILE}"
else
  echo "[3/5] Fichier ${ENV_FILE} existant conservé."
fi

echo "[4/5] Démarrage des conteneurs DADEREZO 24/7..."
cd "${INSTALL_DIR}"
docker compose -f docker-compose.contabo.yml up -d --build

echo "[5/5] Activation de la liaison GitOps automatique (sync GitHub main toutes les 2 min)..."
cat > /usr/local/bin/daderezo-gitops-sync <<'SYNC_EOF'
#!/usr/bin/env bash
set -euo pipefail
cd /opt/daderezo
git fetch origin main --quiet
LOCAL_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git rev-parse origin/main)"
if [[ "${LOCAL_SHA}" != "${REMOTE_SHA}" ]]; then
  echo "[DADEREZO-GITOPS] Nouveau commit détecté (${LOCAL_SHA:0:7} -> ${REMOTE_SHA:0:7}), mise à jour..."
  git reset --hard origin/main
  docker compose -f docker-compose.contabo.yml up -d --build --remove-orphans
  echo "[DADEREZO-GITOPS] Mise à jour terminée avec succès."
fi
SYNC_EOF
chmod +x /usr/local/bin/daderezo-gitops-sync

cat > /etc/systemd/system/daderezo-gitops.service <<'SVC_EOF'
[Unit]
Description=DADEREZO Contabo GitOps Auto-Sync from GitHub main
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/daderezo-gitops-sync
SVC_EOF

cat > /etc/systemd/system/daderezo-gitops.timer <<'TMR_EOF'
[Unit]
Description=Vérifie les mises à jour GitHub DADEREZO toutes les 2 minutes

[Timer]
OnBootSec=60s
OnUnitActiveSec=120s
Persistent=true

[Install]
WantedBy=timers.target
TMR_EOF

systemctl daemon-reload
systemctl enable --now daderezo-gitops.timer

PUBLIC_IP="$(curl -4 -fsSL https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')"
echo "================================================================="
echo "✅ DADEREZO v4.3 est actif et lié automatiquement sur votre Contabo !"
echo "   • URL directe VPS    : http://${PUBLIC_IP}"
echo "   • Santé API & IA     : http://${PUBLIC_IP}/health"
echo "   • Config & Clés (.env): sudo nano /opt/daderezo/.env && cd /opt/daderezo && sudo docker compose -f docker-compose.contabo.yml up -d"
echo "   • Sync auto GitHub   : active (toutes les 2 min sur la branche main)"
echo "================================================================="
