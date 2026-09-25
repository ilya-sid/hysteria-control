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
    systemctl restart hysteria-control.service || true
    if (( MIGRATED == 1 )); then
      [[ -f "$WORK_DIR/config.yaml.previous" ]] && cp -p "$WORK_DIR/config.yaml.previous" /etc/hysteria/config.yaml || true
      [[ -f "$WORK_DIR/panel.env.previous" ]] && cp -p "$WORK_DIR/panel.env.previous" "$CONFIG" || true
      systemctl restart hysteria-server.service || true
    fi
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
if ! grep -q '^HYSTERIA_DYNAMIC_AUTH=1$' "$CONFIG"; then
  [[ -f /etc/hysteria/config.yaml ]] || { printf 'Hysteria config is missing; migration aborted.\n' >&2; exit 1; }
  cp -p /etc/hysteria/config.yaml "$WORK_DIR/config.yaml.previous"
  cp -p "$CONFIG" "$WORK_DIR/panel.env.previous"
  python3 - "$CONFIG" <<'PY'
import os, re, sqlite3, sys, tempfile
env_path=sys.argv[1]; cfg='/etc/hysteria/config.yaml'; db='/var/lib/hysteria-control/panel.db'
text=open(cfg,encoding='utf-8').read().splitlines()
try: auth=text.index('auth:'); userpass=text.index('  userpass:',auth)
except ValueError: raise SystemExit('Auth userpass section not found; refusing automatic migration.')
if 'trafficStats:' not in text: raise SystemExit('trafficStats section missing; refusing migration.')
end=userpass+1
while end<len(text) and not (text[end].startswith('  ') and not text[end].startswith('    ')): end+=1
users=[]
for line in text[userpass+1:end]:
    m=re.fullmatch(r'    ([A-Za-z0-9_-]{1,32}):[ \t]*(.*)',line)
    if m: users.append((m.group(1),m.group(2).strip().strip('"\'')))
if not users: raise SystemExit('No userpass credentials found; refusing automatic migration.')
con=sqlite3.connect(db)
con.execute('create table if not exists users(username text primary key,password text not null,enabled integer not null default 1)')
for username,password in users:
    con.execute('insert into users(username,password,enabled) values(?,?,1) on conflict(username) do update set password=excluded.password,enabled=1',(username,password))
con.commit(); con.close()
out=text[:auth+1]+['  type: http','  http:','    url: http://127.0.0.1:9998/auth']+text[end:]
fd,tmp=tempfile.mkstemp(prefix='hysteria-config.',dir='/etc/hysteria'); os.close(fd)
with open(tmp,'w',encoding='utf-8') as f: f.write('\n'.join(out)+'\n')
os.replace(tmp,cfg)
with open(env_path,'a',encoding='utf-8') as f: f.write('\nHYSTERIA_DYNAMIC_AUTH=1\nHYSTERIA_AUTH_PORT=9998\n')
PY
  chown root:hysteria-control /etc/hysteria/config.yaml "$CONFIG"
  chmod 0640 /etc/hysteria/config.yaml "$CONFIG"
  MIGRATED=1
fi
install -d -o root -g root -m 0755 "$INSTALL_DIR/assets" "$INSTALL_DIR/assets/fonts"
install -o root -g root -m 0644 "$WORK_DIR/app.py" "$INSTALL_DIR/app.py"
install -o root -g root -m 0644 "$WORK_DIR/VERSION" "$INSTALL_DIR/VERSION"
for font in ibm-plex-sans-cyrillic.woff2 ibm-plex-sans-latin.woff2 ibm-plex-mono-cyrillic.woff2 ibm-plex-mono-latin.woff2 OFL.txt; do
  install -o root -g root -m 0644 "$WORK_DIR/fonts/$font" "$INSTALL_DIR/assets/fonts/$font"
done

systemctl restart hysteria-control.service
systemctl is-active --quiet hysteria-control.service
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
APPLIED=0
printf 'Hysteria Control updated to %s. Users and server configuration were kept.\n' "$(tr -d '\n' < "$INSTALL_DIR/VERSION")"
