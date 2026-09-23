#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="Hysteria Control"
HY2_VERSION="${HY2_VERSION:-v2.12.3}"
PANEL_PORT="${PANEL_PORT:-8443}"
INSTALL_DIR="/opt/hysteria-control"
CONFIG_DIR="/etc/hysteria-control"
APP_SOURCE="${HC_APP_SOURCE:-https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/app.py}"

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
if systemctl is-active --quiet hysteria-server.service || command -v hysteria >/dev/null 2>&1 || [[ -e /etc/hysteria/config.yaml ]]; then
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
install -d -o root -g root -m 0755 "$INSTALL_DIR"
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
  userpass: {}
trafficStats:
  listen: 127.0.0.1:9999
  secret: ${API_SECRET}
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
    rewriteHost: true
EOF
chmod 0600 /etc/hysteria/config.yaml

install -o root -g root -m 0644 "$APP_TMP" "$INSTALL_DIR/app.py"
rm -f "$APP_TMP"

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
fi
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/hysteria-control

python3 -m py_compile "$INSTALL_DIR/app.py"
systemctl daemon-reload
systemctl enable --now hysteria-server.service
systemctl restart hysteria-server.service
systemctl enable --now hysteria-control.service
systemctl enable --now certbot.timer

printf '\n%s installed successfully.\n' "$PROJECT_NAME"
printf 'Panel: https://%s:%s\nLogin: %s\nPassword: %s\n' "$DOMAIN" "$PANEL_PORT" "$PANEL_USER" "$PANEL_PASS"
printf 'Save the password now. It is also stored in the protected file %s/panel.env.\n' "$CONFIG_DIR"
if ! command -v ufw >/dev/null 2>&1 || ! ufw status 2>/dev/null | grep -q '^Status: active'; then
  printf 'If your provider has a firewall, allow TCP/80, TCP/%s and UDP/443 there.\n' "$PANEL_PORT"
fi
