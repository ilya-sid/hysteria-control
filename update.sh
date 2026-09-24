#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR=/opt/hysteria-control
CONFIG=/etc/hysteria-control/panel.env
BASE=https://raw.githubusercontent.com/ilya-sid/hysteria-control/main

[[ $EUID -eq 0 ]] || { printf 'Run as root.\n' >&2; exit 1; }
[[ -f "$INSTALL_DIR/app.py" && -f "$CONFIG" ]] || { printf 'Hysteria Control is not installed.\n' >&2; exit 1; }
command -v curl >/dev/null && command -v python3 >/dev/null && command -v systemctl >/dev/null || { printf 'curl, Python 3 and systemd are required.\n' >&2; exit 1; }

WORK_DIR=$(mktemp -d /tmp/hysteria-control-update.XXXXXX)
APPLIED=0
finish() {
  result=$?
  if (( result != 0 && APPLIED == 1 )); then
    cp -p "$WORK_DIR/app.py.previous" "$INSTALL_DIR/app.py"
    if [[ -f "$WORK_DIR/VERSION.previous" ]]; then cp -p "$WORK_DIR/VERSION.previous" "$INSTALL_DIR/VERSION"; fi
    if [[ -d "$WORK_DIR/fonts.previous" ]]; then
      mkdir -p "$INSTALL_DIR/assets/fonts"
      cp -a "$WORK_DIR/fonts.previous/." "$INSTALL_DIR/assets/fonts/"
    fi
    systemctl restart hysteria-control.service || true
    printf 'Update failed; previous panel files were restored.\n' >&2
  fi
  rm -r "$WORK_DIR"
  exit "$result"
}
trap finish EXIT

mkdir -p "$WORK_DIR/fonts"
curl -fsSL "$BASE/app.py" -o "$WORK_DIR/app.py"
for font in ibm-plex-sans-cyrillic.woff2 ibm-plex-sans-latin.woff2 ibm-plex-mono-cyrillic.woff2 ibm-plex-mono-latin.woff2 OFL.txt; do
  curl -fsSL "$BASE/assets/fonts/$font" -o "$WORK_DIR/fonts/$font"
done
curl -fsSL "$BASE/VERSION" -o "$WORK_DIR/VERSION"
python3 -m py_compile "$WORK_DIR/app.py"

cp -p "$INSTALL_DIR/app.py" "$WORK_DIR/app.py.previous"
if [[ -f "$INSTALL_DIR/VERSION" ]]; then cp -p "$INSTALL_DIR/VERSION" "$WORK_DIR/VERSION.previous"; fi
if [[ -d "$INSTALL_DIR/assets/fonts" ]]; then cp -a "$INSTALL_DIR/assets/fonts" "$WORK_DIR/fonts.previous"; fi
APPLIED=1
install -d -o root -g root -m 0755 "$INSTALL_DIR/assets" "$INSTALL_DIR/assets/fonts"
install -o root -g root -m 0644 "$WORK_DIR/app.py" "$INSTALL_DIR/app.py"
install -o root -g root -m 0644 "$WORK_DIR/VERSION" "$INSTALL_DIR/VERSION"
for font in ibm-plex-sans-cyrillic.woff2 ibm-plex-sans-latin.woff2 ibm-plex-mono-cyrillic.woff2 ibm-plex-mono-latin.woff2 OFL.txt; do
  install -o root -g root -m 0644 "$WORK_DIR/fonts/$font" "$INSTALL_DIR/assets/fonts/$font"
done

systemctl restart hysteria-control.service
systemctl is-active --quiet hysteria-control.service
set -a
. "$CONFIG"
set +a
# Ждём открытия порта после перезапуска: systemd может пометить сервис
# активным за несколько секунд до готовности listener. Проверка TCP не
# зависит от DNS, прокси, сертификата и HTTP-редиректов панели.
ready=0
for _ in $(seq 1 20); do
  if ss -H -lnt "sport = :${PANEL_PORT}" 2>/dev/null | grep -q "LISTEN"; then
    ready=1
    break
  fi
  sleep 1
done
(( ready == 1 )) || { printf 'Panel did not become ready on 127.0.0.1:%s.\n' "$PANEL_PORT" >&2; exit 1; }
APPLIED=0
printf 'Hysteria Control updated to %s. Users and server configuration were kept.\n' "$(tr -d '\n' < "$INSTALL_DIR/VERSION")"
