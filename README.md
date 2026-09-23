# Hysteria Control

A lightweight, self-hosted Hysteria 2 server and web panel for managing users, connection links, QR codes, traffic, and basic server health. The panel is a small Flask app with SQLite; there is no Docker, Nginx, PostgreSQL, or separate frontend build.

## One-command installation

Requirements:

- Ubuntu 22.04+ or Debian 11+ with systemd and root access.
- A public server and a domain whose DNS already points to it.
- TCP port 80 reachable temporarily/permanently for Let's Encrypt, UDP port 443 for Hysteria, and TCP port 8443 for the panel by default.
- 1 vCPU and 1 GB RAM recommended; 512 MB RAM is a practical minimum.

Run this on a fresh server from an interactive terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo bash
```

The installer asks for the domain, a Let's Encrypt contact email, and the panel login. It pins Hysteria to v2.12.3 by default, creates random panel and API secrets, and prints the initial panel password once. Save it. Secret files are readable only by root and the dedicated panel service account.

To set values without the prompts, export them in the shell before running the command:

```sh
export HC_DOMAIN=vpn.example.com HC_EMAIL=admin@example.com HC_PANEL_USER=admin
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo --preserve-env=HC_DOMAIN,HC_EMAIL,HC_PANEL_USER bash
```

To install a different Hysteria version, set `HY2_VERSION`, for example `v2.12.3`. The script refuses to overwrite an existing Hysteria config/service, an existing `/opt/hysteria-control`, or occupied required ports. It does not migrate or remove existing services.

## What it installs

- Hysteria 2 on UDP/443, with per-user credentials and its stats API bound to `127.0.0.1:9999`.
- The HTTPS panel on TCP/8443 (or `PANEL_PORT` if set).
- A Let's Encrypt certificate for the chosen domain, with automatic renewal. Renewals reload the panel certificate.
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

Administrators can change their password from the dashboard. The form requires the current password and a matching new password of at least 12 characters. The new password is stored as a salted PBKDF2 hash in the private SQLite database; changing it invalidates existing panel sessions.

Hysteria is installed through the [official Hysteria server installation script](https://v2.hysteria.network/docs/getting-started/Server-Installation-Script/) and uses the official `userpass`, TLS, and Traffic Stats API configuration. The SNI must match the installed certificate domain; changing to another SNI requires a certificate for that domain.

The installer targets a fresh Ubuntu/Debian server. Back up `/var/lib/hysteria-control/panel.db`, `/etc/hysteria/config.yaml`, and `/etc/hysteria-control/panel.env` before making manual changes. Keep the panel password private and restrict TCP/8443 at your provider firewall if you know the networks from which you administer the server.

## Development checks

```sh
bash -n install.sh
python3 -m py_compile app.py
```

## License

No license has been selected yet. Until one is added, the source is visible but reuse and redistribution are not granted.
