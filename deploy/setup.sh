#!/usr/bin/env bash
# SIGNAL — Hetzner CX32 setup script (Ubuntu 22.04 LTS)
# Run as root on a fresh server:
#   bash <(curl -fsSL https://raw.githubusercontent.com/Dweeler87/signal/main/deploy/setup.sh)
# Or after git clone:
#   sudo bash deploy/setup.sh

set -euo pipefail

SIGNAL_USER="signal"
SIGNAL_DIR="/opt/signal"
SIGNAL_REPO="https://github.com/Dweeler87/signal.git"
LOG_DIR="/var/log/signal"
PYTHON_VERSION="3.12"

echo "==> Updating apt..."
apt-get update -qq

echo "==> Installing system packages..."
apt-get install -y -qq \
  python${PYTHON_VERSION} \
  python${PYTHON_VERSION}-venv \
  python3-pip \
  redis-server \
  supervisor \
  nginx \
  git \
  curl \
  htop \
  ufw

echo "==> Configuring Redis (bind localhost only)..."
sed -i 's/^bind .*/bind 127.0.0.1/' /etc/redis/redis.conf
sed -i 's/^# maxmemory .*/maxmemory 512mb/' /etc/redis/redis.conf
sed -i 's/^# maxmemory-policy .*/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
systemctl enable redis-server
systemctl restart redis-server

echo "==> Creating signal user..."
id -u ${SIGNAL_USER} &>/dev/null || useradd -r -m -d /home/${SIGNAL_USER} -s /bin/bash ${SIGNAL_USER}

echo "==> Cloning or updating repo..."
if [ -d "${SIGNAL_DIR}/.git" ]; then
  git -C "${SIGNAL_DIR}" pull --ff-only
else
  git clone "${SIGNAL_REPO}" "${SIGNAL_DIR}"
fi
chown -R ${SIGNAL_USER}:${SIGNAL_USER} "${SIGNAL_DIR}"

echo "==> Creating Python venv and installing deps..."
sudo -u ${SIGNAL_USER} python${PYTHON_VERSION} -m venv "${SIGNAL_DIR}/.venv"
sudo -u ${SIGNAL_USER} "${SIGNAL_DIR}/.venv/bin/pip" install --quiet --upgrade pip
sudo -u ${SIGNAL_USER} "${SIGNAL_DIR}/.venv/bin/pip" install --quiet -e "${SIGNAL_DIR}[prod]"

# Patch supervisord config to use venv Python
sed -i "s|command=python|command=${SIGNAL_DIR}/.venv/bin/python|g" "${SIGNAL_DIR}/deploy/supervisord.conf"
sed -i "s|command=uvicorn|command=${SIGNAL_DIR}/.venv/bin/uvicorn|g" "${SIGNAL_DIR}/deploy/supervisord.conf"

echo "==> Creating log directory..."
mkdir -p "${LOG_DIR}"
chown -R ${SIGNAL_USER}:${SIGNAL_USER} "${LOG_DIR}"

echo "==> Installing supervisord config..."
cp "${SIGNAL_DIR}/deploy/supervisord.conf" /etc/supervisor/conf.d/signal.conf
systemctl enable supervisor
systemctl restart supervisor

echo "==> Configuring nginx reverse proxy..."
cat > /etc/nginx/sites-available/signal <<'NGINX'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 30s;
    }
}
NGINX
ln -sf /etc/nginx/sites-available/signal /etc/nginx/sites-enabled/signal
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

echo "==> Configuring firewall..."
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP (API via nginx)
ufw allow 443/tcp  # HTTPS (for future TLS)
ufw --force enable

echo ""
echo "==> Setup complete!"
echo ""
echo "NEXT STEPS:"
echo "  1. Copy your .env to ${SIGNAL_DIR}/.env"
echo "     (make sure API_ADMIN_SECRET, CLICKHOUSE_*, REDIS_URL are set)"
echo ""
echo "  2. Restart workers:"
echo "     supervisorctl restart all"
echo ""
echo "  3. Check status:"
echo "     supervisorctl status"
echo "     tail -f /var/log/signal/log_follower.log"
echo ""
echo "  4. Enable additional CT logs in ingestion/log_follower.py"
echo "     (start with oak2026, xenon2026h1 once confirmed working)"
echo ""
echo "  5. Provision your first API key:"
echo "     curl -s -X POST http://localhost:8000/v1/keys \\"
echo "       -H 'X-Admin-Secret: <your_API_ADMIN_SECRET>' \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"tier\": \"pro\", \"label\": \"founder-key\"}'"
