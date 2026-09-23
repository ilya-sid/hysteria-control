# Hysteria Control

A lightweight Hysteria 2 server and web panel for managing users, connection links, QR codes, traffic, and basic server health. Built with Flask and SQLite; no Docker, Nginx, PostgreSQL, or frontend build.

## One-command installation

Requirements: Ubuntu 22.04+ or Debian 11+ with systemd and root access; a public server and a domain already pointed to it; TCP port 80 reachable for Let's Encrypt, UDP/443 for Hysteria, and TCP/8443 for the panel by default. Recommended: 1 vCPU and 1 GB RAM (512 MB minimum).

Run on a fresh server from an interactive terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo bash
```

The installer asks for the domain, a Let's Encrypt contact email, and panel login. Hysteria is pinned to v2.12.3 by default. Random panel/API secrets are generated; save the initial panel password printed once after installation. Secret files are restricted to root and the panel service account.

For non-interactive setup, export values before running the installer:

```sh
export HC_DOMAIN=vpn.example.com HC_EMAIL=admin@example.com HC_PANEL_USER=admin
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo --preserve-env=HC_DOMAIN,HC_EMAIL,HC_PANEL_USER bash
```

The panel uses TCP/8443 by default (customize with PANEL_PORT); Hysteria uses UDP/443. TCP/80 is required for certificate issuance and renewal. If UFW is active, the installer opens the required ports; otherwise, configure your provider firewall. The installer refuses to overwrite existing Hysteria configuration/services or occupied required ports.

## Services and troubleshooting

```sh
systemctl status hysteria-server hysteria-control --no-pager
journalctl -u hysteria-server -u hysteria-control -n 100 --no-pager
systemctl restart hysteria-control
```

Hysteria is installed using the [official server installation script](https://v2.hysteria.network/docs/getting-started/Server-Installation-Script/) and official userpass, TLS, and Traffic Stats API settings. SNI must match the installed certificate domain. Back up /var/lib/hysteria-control/panel.db, /etc/hysteria/config.yaml, and /etc/hysteria-control/panel.env before manual changes.

## Development checks

```sh
bash -n install.sh
python3 -m py_compile app.py
```

## License

No license has been selected yet. Until one is added, the source is visible but reuse and redistribution are not granted.
