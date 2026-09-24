#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="Hysteria Control"
HY2_VERSION="${HY2_VERSION:-v2.12.3}"
PANEL_PORT="${PANEL_PORT:-8443}"
INSTALL_DIR="/opt/hysteria-control"
CONFIG_DIR="/etc/hysteria-control"
APP_SOURCE="${HC_APP_SOURCE:-https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/app.py}"
ASSET_BASE="https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/assets/fonts"

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
need_tty() { [[ -r /dev/tty && -w /dev/tty ]] || die 'Run this installer from an interactive terminal.'; }

[[ "${EUID}" -eq 0 ]] || die 'Run as root, for example: curl ... | sudo bash.'
[[ -r /etc/os-release ]] || die 'Cannot identify this Linux distribution.'
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die 'Supported distributions: Ubuntu 22.04+ and Debian 11+.' ;;
esac
command -v systemctl >/dev/null || die 'systemd is required.'

need_tty
DOMAIN="${HC_DOMAIN:-}"
EMAIL="${HC_EMAIL:-}"
PANEL_USER="${HC_PANEL_USER:-admin}"
if [[ -z "$DOMAIN" ]]; then read -r -p 'Domain pointed to this server: ' DOMAIN </dev/tty; fi
if [[ -z "$EMAIL" ]]; then read -r -p "Let's Encrypt email: " EMAIL </dev/tty; fi
if [[ -z "${HC_PANEL_USER:-}" ]]; then
  read -r -p "Panel login [${PANEL_USER}]: " entered_user </dev/tty || true
  PANEL_USER="${entered_user:-$PANEL_USER}"
fi
DOMAIN="${DOMAIN,,}"

[[ "${#DOMAIN}" -le 253 && "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$DOMAIN" != *..* ]] || die 'Enter a valid DNS hostname (not an IP address).'
[[ "$DOMAIN" == *.* ]] || die 'The domain must be a fully qualified hostname.'
[[ "$EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die 'Enter a valid email address.'
[[ "$PANEL_USER" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die 'Panel login may contain letters, numbers, _ and - (up to 32 characters).'
[[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] || die 'Panel port must be a number.'
PANEL_PORT=$((10#$PANEL_PORT))
(( PANEL_PORT >= 1024 && PANEL_PORT <= 65535 && PANEL_PORT != 80 && PANEL_PORT != 443 )) || die 'Panel port must be between 1024 and 65535, except 80 and 443.'

HY2_EXISTING=0
if systemctl list-unit-files hysteria-server.service --no-legend 2>/dev/null | grep -q '^hysteria-server.service'; then
  HY2_EXISTING=1
  printf 'Existing Hysteria installation detected; it will be reconfigured for Hysteria Control. A timestamped backup will be kept.\n'
fi
[[ ! -e "$INSTALL_DIR" ]] || die "$INSTALL_DIR already exists; move or back it up before installing."
[[ ! -e "$CONFIG_DIR" ]] || die "$CONFIG_DIR already exists; inspect it before installing."

printf '\nInstalling %s on %s. Hysteria will use UDP/443; the HTTPS panel will use TCP/%s.\n' "$PROJECT_NAME" "$DOMAIN" "$PANEL_PORT"
printf 'The domain must already resolve to this server and TCP/80 must be reachable for certificate issuance.\n\n'

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl openssl python3 python3-flask qrencode certbot iproute2 sudo

# The installer may be launched as `curl ... | sudo bash`, so app.py is not
# present in the current directory. Fetch the matching panel code itself.
APP_TMP="$(mktemp /tmp/hysteria-control-app.XXXXXX)"
trap 'rm -f "$APP_TMP"' EXIT
curl -fsSL "$APP_SOURCE" -o "$APP_TMP"

if ss -H -ltn | awk '{print $4}' | grep -Eq ":(80|${PANEL_PORT})$"; then
  die 'A required TCP port (80 or the chosen panel port) is already in use.'
fi
if (( HY2_EXISTING == 0 )) && ss -H -lun | awk '{print $4}' | grep -Eq ':443$'; then
  die 'UDP/443 is already in use by another service.'
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow 80/tcp
  ufw allow 443/udp
  ufw allow "${PANEL_PORT}/tcp"
fi

certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" --domain "$DOMAIN"

if (( HY2_EXISTING == 0 )); then
  curl -fsSL https://get.hy2.sh/ -o /tmp/hysteria-control-hy2-install.sh
  HYSTERIA_USER=root bash /tmp/hysteria-control-hy2-install.sh --version "$HY2_VERSION"
  rm -f /tmp/hysteria-control-hy2-install.sh
fi

getent group hysteria-control >/dev/null || groupadd --system hysteria-control
id hysteria-control >/dev/null 2>&1 || useradd --system --gid hysteria-control --home-dir /var/lib/hysteria-control --shell /usr/sbin/nologin --no-create-home hysteria-control
if (( HY2_EXISTING == 1 )); then
  HYSTERIA_SERVICE_USER="$(systemctl show hysteria-server.service --property=User --value)"
  if [[ -n "$HYSTERIA_SERVICE_USER" && "$HYSTERIA_SERVICE_USER" != root ]]; then
    id "$HYSTERIA_SERVICE_USER" >/dev/null 2>&1 || die "The existing Hysteria service user ${HYSTERIA_SERVICE_USER} does not exist."
    usermod -a -G hysteria-control "$HYSTERIA_SERVICE_USER"
  fi
fi
install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -d -o root -g root -m 0755 "$INSTALL_DIR/assets" "$INSTALL_DIR/assets/fonts"
install -d -o root -g hysteria-control -m 0750 "$CONFIG_DIR" "$CONFIG_DIR/tls"
install -d -o hysteria-control -g hysteria-control -m 0750 /var/lib/hysteria-control
install -d -o root -g root -m 0755 /etc/hysteria
install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
if (( HY2_EXISTING == 1 )) && [[ -e /etc/hysteria/config.yaml ]]; then
  cp -p /etc/hysteria/config.yaml "/etc/hysteria/config.yaml.backup.$(date +%Y%m%d%H%M%S)"
fi
install -o root -g hysteria-control -m 0640 /dev/null /etc/hysteria/api-secret
API_SECRET="$(openssl rand -hex 32)"
printf '%s\n' "$API_SECRET" > /etc/hysteria/api-secret
install -o root -g hysteria-control -m 0644 "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$CONFIG_DIR/tls/fullchain.pem"
install -o root -g hysteria-control -m 0640 "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$CONFIG_DIR/tls/privkey.pem"

PANEL_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
PANEL_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
PRIMARY_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
PANEL_PRIMARY_PASS="$PRIMARY_PASS" python3 - <<'PY'
import os
import sqlite3

db = '/var/lib/hysteria-control/panel.db'
connection = sqlite3.connect(db)
connection.execute('create table if not exists users(username text primary key,password text not null,enabled integer not null default 1)')
connection.execute('insert or ignore into users(username,password,enabled) values(?,?,1)', ('primary', os.environ['PANEL_PRIMARY_PASS']))
connection.commit()
connection.close()
PY
chown hysteria-control:hysteria-control /var/lib/hysteria-control/panel.db
chmod 0600 /var/lib/hysteria-control/panel.db
cat > "$CONFIG_DIR/panel.env" <<EOF
PANEL_USER=${PANEL_USER}
PANEL_PASS=${PANEL_PASS}
PANEL_SECRET=${PANEL_SECRET}
PANEL_DOMAIN=${DOMAIN}
PANEL_PORT=${PANEL_PORT}
HY_CONTROL_DIR=${INSTALL_DIR}
PANEL_DB=/var/lib/hysteria-control/panel.db
HYSTERIA_API=http://127.0.0.1:9999
HYSTERIA_API_SECRET_FILE=/etc/hysteria/api-secret
HYSTERIA_CONFIG=/etc/hysteria/config.yaml
PANEL_CERT=${CONFIG_DIR}/tls/fullchain.pem
PANEL_KEY=${CONFIG_DIR}/tls/privkey.pem
EOF
chown root:hysteria-control "$CONFIG_DIR/panel.env"
chmod 0640 "$CONFIG_DIR/panel.env"

cat > /etc/hysteria/config.yaml <<EOF
listen: :443
tls:
  cert: ${CONFIG_DIR}/tls/fullchain.pem
  key: ${CONFIG_DIR}/tls/privkey.pem
auth:
  type: userpass
  userpass:
    primary: ${PRIMARY_PASS}
trafficStats:
  listen: 127.0.0.1:9999
  secret: ${API_SECRET}
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
    rewriteHost: true
EOF
chown root:hysteria-control /etc/hysteria/config.yaml
chmod 0640 /etc/hysteria/config.yaml

install -o root -g root -m 0644 "$APP_TMP" "$INSTALL_DIR/app.py"
rm -f "$APP_TMP"
curl -fsSL 'https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/VERSION' -o "$INSTALL_DIR/VERSION"
chmod 0644 "$INSTALL_DIR/VERSION"
for font in ibm-plex-sans-cyrillic.woff2 ibm-plex-sans-latin.woff2 ibm-plex-mono-cyrillic.woff2 ibm-plex-mono-latin.woff2 OFL.txt; do
  curl -fsSL "$ASSET_BASE/$font" -o "$INSTALL_DIR/assets/fonts/$font"
  chmod 0644 "$INSTALL_DIR/assets/fonts/$font"
done

cat > /usr/local/sbin/hysteria-control-sync <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
set -a
. /etc/hysteria-control/panel.env
set +a
exec /usr/bin/python3 /opt/hysteria-control/app.py --sync-root
EOF
chown root:hysteria-control /usr/local/sbin/hysteria-control-sync
chmod 0750 /usr/local/sbin/hysteria-control-sync

cat > /etc/sudoers.d/hysteria-control <<'EOF'
hysteria-control ALL=(root) NOPASSWD: /usr/local/sbin/hysteria-control-sync
EOF
chmod 0440 /etc/sudoers.d/hysteria-control
visudo -cf /etc/sudoers.d/hysteria-control

cat > /etc/systemd/system/hysteria-control.service <<'EOF'
[Unit]
Description=Hysteria Control web panel
After=network-online.target hysteria-server.service
Wants=network-online.target

[Service]
Type=simple
User=hysteria-control
Group=hysteria-control
UMask=0077
EnvironmentFile=/etc/hysteria-control/panel.env
WorkingDirectory=/opt/hysteria-control
ExecStart=/usr/bin/python3 /opt/hysteria-control/app.py
PrivateTmp=true
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/letsencrypt/renewal-hooks/deploy/hysteria-control <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${RENEWED_LINEAGE:-}" == "/etc/letsencrypt/live/${DOMAIN}" ]]; then
  install -o root -g hysteria-control -m 0644 "\$RENEWED_LINEAGE/fullchain.pem" "${CONFIG_DIR}/tls/fullchain.pem"
  install -o root -g hysteria-control -m 0640 "\$RENEWED_LINEAGE/privkey.pem" "${CONFIG_DIR}/tls/privkey.pem"
  systemctl try-restart hysteria-control.service
  systemctl try-restart hysteria-server.service
fi
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/hysteria-control

python3 -m py_compile "$INSTALL_DIR/app.py"
systemctl daemon-reload
systemctl enable --now hysteria-server.service
systemctl restart hysteria-server.service
systemctl enable --now hysteria-control.service
systemctl enable --now certbot.timer
systemctl is-active --quiet hysteria-server.service || die 'Hysteria did not start. Check journalctl -u hysteria-server.service.'
systemctl is-active --quiet hysteria-control.service || die 'The panel did not start. Check journalctl -u hysteria-control.service.'
PANEL_OK=0
API_OK=0
for attempt in 1 2 3 4 5; do
  if curl -fs --max-time 3 --resolve "${DOMAIN}:${PANEL_PORT}:127.0.0.1" "https://${DOMAIN}:${PANEL_PORT}/" -o /dev/null; then PANEL_OK=1; fi
  if curl -fs --max-time 3 -H "Authorization: ${API_SECRET}" http://127.0.0.1:9999/online -o /dev/null; then API_OK=1; fi
  if (( PANEL_OK == 1 && API_OK == 1 )); then break; fi
  sleep 1
done
(( PANEL_OK == 1 )) || die 'The panel did not answer over HTTPS. Check journalctl -u hysteria-control.service.'
(( API_OK == 1 )) || die 'The Hysteria statistics API did not answer. Check journalctl -u hysteria-server.service.'

printf '\n%s installed successfully.\n' "$PROJECT_NAME"
printf 'Panel: https://%s:%s\nLogin: %s\nPassword: %s\n' "$DOMAIN" "$PANEL_PORT" "$PANEL_USER" "$PANEL_PASS"
printf 'Initial VPN user: primary\nConnection: hysteria2://primary:%s@%s:443/?sni=%s&insecure=0#primary\n' "$PRIMARY_PASS" "$DOMAIN" "$DOMAIN"
printf 'Save the password now. It is also stored in the protected file %s/panel.env.\n' "$CONFIG_DIR"
if ! command -v ufw >/dev/null 2>&1 || ! ufw status 2>/dev/null | grep -q '^Status: active'; then
  printf 'If your provider has a firewall, allow TCP/80, TCP/%s and UDP/443 there.\n' "$PANEL_PORT"
fi
