#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR=/opt/hysteria-control
CONFIG=/etc/hysteria-control/panel.env
BASE=https://raw.githubusercontent.com/ilya-sid/hysteria-control/main

[[ $EUID -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
[[ -f "$INSTALL_DIR/app.py" && -f "$CONFIG" ]] || { printf 'Hysteria Control is not installed.\n' >&2; exit 1; }
command -v curl >/dev/null && command -v python3 >/dev/null && command -v systemctl >/dev/null || { printf 'curl, Python 3 and systemd are required.\n' >&2; exit 1; }
exec 9>/run/hysteria-control-update.lock
flock -n 9 || { printf 'Another update is running.\n' >&2; exit 1; }
set -a
. "$CONFIG"
set +a

WORK_DIR=$(mktemp -d /tmp/hysteria-control-update.XXXXXX)
APPLIED=0
MIGRATED=0
finish() {
  result=$?
  if (( result != 0 && APPLIED == 1 )); then
    cp -p "$WORK_DIR/app.py.previous" "$INSTALL_DIR/app.py"
    if [[ -f "$WORK_DIR/VERSION.previous" ]]; then cp -p "$WORK_DIR/VERSION.previous" "$INSTALL_DIR/VERSION"; fi
    if [[ -d "$WORK_DIR/fonts.previous" ]]; then
      mkdir -p "$INSTALL_DIR/assets/fonts"
      cp -a "$WORK_DIR/fonts.previous/." "$INSTALL_DIR/assets/fonts/"
    fi
    if (( MIGRATED == 1 )); then
      [[ -f "$WORK_DIR/config.yaml.previous" ]] && cp -p "$WORK_DIR/config.yaml.previous" /etc/hysteria/config.yaml || true
      [[ -f "$WORK_DIR/panel.env.previous" ]] && cp -p "$WORK_DIR/panel.env.previous" "$CONFIG" || true
    fi
    systemctl restart hysteria-control.service || true
    if (( MIGRATED == 1 )); then systemctl restart hysteria-server.service || true; fi
    printf 'Update failed; previous panel files were restored.\n' >&2
  fi
  rm -r "$WORK_DIR"
  exit "$result"
}
trap finish EXIT

mkdir -p "$WORK_DIR/fonts"
download() { curl -fsSL --connect-timeout 10 --max-time 45 --retry 2 "$1" -o "$2"; }
download "$BASE/app.py" "$WORK_DIR/app.py"
download "$BASE/maintenance.py" "$WORK_DIR/maintenance.py"
for font in ibm-plex-sans-cyrillic.woff2 ibm-plex-sans-latin.woff2 ibm-plex-mono-cyrillic.woff2 ibm-plex-mono-latin.woff2 OFL.txt; do
  download "$BASE/assets/fonts/$font" "$WORK_DIR/fonts/$font"
done
download "$BASE/VERSION" "$WORK_DIR/VERSION"
python3 -m py_compile "$WORK_DIR/app.py"
python3 "$WORK_DIR/maintenance.py" "$WORK_DIR/config.yaml.next"

cp -p "$INSTALL_DIR/app.py" "$WORK_DIR/app.py.previous"
if [[ -f "$INSTALL_DIR/VERSION" ]]; then cp -p "$INSTALL_DIR/VERSION" "$WORK_DIR/VERSION.previous"; fi
if [[ -d "$INSTALL_DIR/assets/fonts" ]]; then cp -a "$INSTALL_DIR/assets/fonts" "$WORK_DIR/fonts.previous"; fi
APPLIED=1
cp -p /etc/hysteria/config.yaml "$WORK_DIR/config.yaml.previous"
cp -p "$CONFIG" "$WORK_DIR/panel.env.previous"
if ! cmp -s "$WORK_DIR/config.yaml.next" /etc/hysteria/config.yaml || ! grep -q '^HYSTERIA_DYNAMIC_AUTH=1$' "$CONFIG"; then
  MIGRATED=1
  install -o root -g hysteria-control -m 0640 "$WORK_DIR/config.yaml.next" /etc/hysteria/config.yaml
  if ! grep -q '^HYSTERIA_DYNAMIC_AUTH=1$' "$CONFIG"; then
    printf '\nHYSTERIA_DYNAMIC_AUTH=1\nHYSTERIA_AUTH_PORT=%s\n' "${HYSTERIA_AUTH_PORT:-9998}" >> "$CONFIG"
  fi
fi
install -d -o root -g root -m 0755 "$INSTALL_DIR/assets" "$INSTALL_DIR/assets/fonts"
install -o root -g root -m 0644 "$WORK_DIR/app.py" "$INSTALL_DIR/app.py"
install -o root -g root -m 0644 "$WORK_DIR/VERSION" "$INSTALL_DIR/VERSION"
for font in ibm-plex-sans-cyrillic.woff2 ibm-plex-sans-latin.woff2 ibm-plex-mono-cyrillic.woff2 ibm-plex-mono-latin.woff2 OFL.txt; do
  install -o root -g root -m 0644 "$WORK_DIR/fonts/$font" "$INSTALL_DIR/assets/fonts/$font"
done

systemctl restart hysteria-control.service
systemctl is-active --quiet hysteria-control.service
# Do not restart VPN until its dynamic auth backend accepts requests.
auth_ready=0
for _ in $(seq 1 20); do
  if curl -fs --noproxy '*' --max-time 2 -H 'Content-Type: application/json' \
    -d '{"auth":"invalid-update-probe"}' "http://127.0.0.1:${HYSTERIA_AUTH_PORT:-9998}/auth" | grep -q '"ok": false'; then
    auth_ready=1; break
  fi
  sleep 1
done
(( auth_ready == 1 )) || { printf 'VPN auth backend did not become ready.\n' >&2; exit 1; }
if (( MIGRATED == 1 )); then
  systemctl restart hysteria-server.service
  systemctl is-active --quiet hysteria-server.service
fi
set -a
. "$CONFIG"
set +a
# The listener can accept TCP while its TLS handshake is stuck. Check an
# actual HTTPS response through loopback, bypassing DNS and proxy settings.
ready=0
for _ in $(seq 1 20); do
  if curl -fs --noproxy '*' --connect-timeout 1 --max-time 3 \
    --resolve "${PANEL_DOMAIN}:${PANEL_PORT}:127.0.0.1" \
    "https://${PANEL_DOMAIN}:${PANEL_PORT}/" -o /dev/null; then
    ready=1
    break
  fi
  sleep 1
done
(( ready == 1 )) || { printf 'Panel did not respond over HTTPS on 127.0.0.1:%s.\n' "$PANEL_PORT" >&2; exit 1; }
python3 - <<'PY'
import os, urllib.request
with open(os.environ.get('HYSTERIA_API_SECRET_FILE','/etc/hysteria/api-secret')) as f:
    secret=f.read().strip()
request=urllib.request.Request(os.environ.get('HYSTERIA_API','http://127.0.0.1:9999')+'/online',headers={'Authorization':secret})
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request,timeout=3) as response:
    if response.status!=200: raise SystemExit('VPN statistics check failed')
PY
APPLIED=0
printf 'Hysteria Control updated to %s. Users and server configuration were kept.\n' "$(tr -d '\n' < "$INSTALL_DIR/VERSION")"
