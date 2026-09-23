# Hysteria Control

[Русская версия](README.ru.md)

A lightweight, self-hosted Hysteria 2 server and web panel for managing users, connection links, QR codes, traffic, and basic server health. The panel is a small Flask app with SQLite; there is no Docker, Nginx, PostgreSQL, or separate frontend build.

## One-command installation

Requirements:

- Ubuntu 22.04+ or Debian 11+ with systemd and root access.
- A public server and a domain whose DNS already points to it.
- TCP port 80 reachable temporarily/permanently for Let's Encrypt, UDP port 443 for Hysteria, and TCP port 8443 for the panel by default.
- 1 vCPU and 1 GB RAM recommended; 512 MB RAM is a practical minimum.

Run this from an interactive terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh -o /tmp/hysteria-control-install.sh && sudo bash /tmp/hysteria-control-install.sh
```

The installer asks for the domain, a Let's Encrypt contact email, and the panel login. It pins Hysteria to v2.12.3 by default, creates random panel and API secrets and a first VPN user named `primary`, then prints the panel password and initial connection link. Save them. Secret files are readable only by root and the dedicated panel service account.

To set values without the prompts, export them in the shell before running the command:

```sh
export HC_DOMAIN=vpn.example.com HC_EMAIL=admin@example.com HC_PANEL_USER=admin
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh -o /tmp/hysteria-control-install.sh && sudo --preserve-env=HC_DOMAIN,HC_EMAIL,HC_PANEL_USER bash /tmp/hysteria-control-install.sh
```

To install a different Hysteria version, set `HY2_VERSION`, for example `v2.12.3`. An existing Hysteria service is reconfigured for this panel and its config is backed up. Existing Hysteria users are not imported; their old links stop working after reconfiguration. The installer refuses to overwrite an existing panel installation or use occupied required ports.

## What it installs

- Hysteria 2 on UDP/443, with per-user credentials and its stats API bound to `127.0.0.1:9999`.
- The HTTPS panel on TCP/8443 (or `PANEL_PORT` if set).
- A Let's Encrypt certificate for the chosen domain, with automatic renewal. Renewals restart both the panel and Hysteria so they use the new certificate.
- A private SQLite database under `/var/lib/hysteria-control` and secrets/configuration under `/etc/hysteria-control`.
- The web panel runs as a dedicated unprivileged account. A fixed root-owned helper performs only the Hysteria config rebuild and service restart needed for user management.

If UFW is already active, the installer opens TCP/80, TCP/8443 (or your selected `PANEL_PORT`), and UDP/443. Otherwise, open those ports in your VPS provider's firewall. TCP/80 is needed for certificate issuance and renewal. Set `PANEL_PORT` in the environment to change the panel port.

## Services and troubleshooting

```sh
systemctl status hysteria-server hysteria-control --no-pager
journalctl -u hysteria-server -u hysteria-control -n 100 --no-pager
systemctl restart hysteria-control
```

Open the panel at its root URL (for example, `https://your-domain:8443/`). Action paths such as `/add`, `/toggle`, `/delete`, `/sni`, and `/password` are form endpoints, not pages; opening them directly with a browser GET redirects to the panel home without changing anything.

Administrators can open the password form from the button beside the theme switch. The form requires the current password and a matching new password of at least 12 characters. The new password is stored as a salted PBKDF2 hash in the private SQLite database; changing it invalidates existing panel sessions.

At least one VPN user must stay enabled because Hysteria cannot start with an empty `userpass` list. New usernames use Latin letters (including uppercase), numbers, `_`, or `-`. Names that differ only by letter case are treated as duplicates.

Hysteria is installed through the [official Hysteria server installation script](https://v2.hysteria.network/docs/getting-started/Server-Installation-Script/) and uses the official `userpass`, TLS, and Traffic Stats API configuration. The SNI must match the installed certificate domain; changing to another SNI requires a certificate for that domain.

The installer targets a fresh Ubuntu/Debian server and also detects an existing Hysteria installation. In that case it reconfigures Hysteria for this panel and keeps a timestamped backup of `/etc/hysteria/config.yaml`. Back up `/var/lib/hysteria-control/panel.db`, `/etc/hysteria/config.yaml`, and `/etc/hysteria-control/panel.env` before making manual changes. Keep the panel password private and restrict TCP/8443 at your provider firewall if you know the networks from which you administer the server.

The one-command installer downloads the matching `app.py` automatically. No manual `scp`, `cp`, or creation of `/opt/hysteria-control` is required.

## Development checks

```sh
bash -n install.sh
python3 -m py_compile app.py
```

## License

No license has been selected yet. Until one is added, the source is visible but reuse and redistribution are not granted.
