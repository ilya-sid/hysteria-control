# Hysteria Control

[English version](#english)

Лёгкая панель управления сервером Hysteria 2: создание и отключение пользователей, ссылки и QR-коды подключений, статистика трафика и состояние сервера. Панель написана на Flask и использует SQLite. Docker, Nginx, PostgreSQL и отдельная сборка фронтенда не требуются.

## Установка одной командой

Поддерживаются Ubuntu 22.04+ и Debian 11+ с systemd. Нужны root-доступ, публичный сервер и домен, DNS-запись которого уже указывает на сервер. Должны быть доступны TCP/80 для получения TLS-сертификата Let's Encrypt, UDP/443 для Hysteria и TCP/8443 для панели (по умолчанию). Рекомендуется 1 ГБ RAM; 512 МБ — практический минимум.

Запустите на чистом сервере из интерактивного терминала:

```sh
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo bash
```

Установщик спросит домен, email для Let's Encrypt и логин панели. По умолчанию устанавливается Hysteria v2.12.3. Панельный пароль и секрет API создаются случайно; начальный пароль панели будет показан один раз в конце — сохраните его. Сервис панели работает от отдельной непривилегированной учётной записи.

Чтобы передать значения заранее и пропустить вопросы установщика:

```sh
export HC_DOMAIN=vpn.example.com HC_EMAIL=admin@example.com HC_PANEL_USER=admin
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo --preserve-env=HC_DOMAIN,HC_EMAIL,HC_PANEL_USER bash
```

Панель использует TCP/8443 (порт можно изменить переменной PANEL_PORT), Hysteria — UDP/443. TCP/80 нужен для выпуска и обновления сертификата. Если UFW уже включён, установщик добавит правила для необходимых портов; иначе настройте firewall у хостинг-провайдера. Установщик не перезаписывает найденную конфигурацию/службу Hysteria и остановится, если нужные порты заняты. Он предназначен для чистого сервера и не удаляет существующие службы.

## Службы и диагностика

```sh
systemctl status hysteria-server hysteria-control --no-pager
journalctl -u hysteria-server -u hysteria-control -n 100 --no-pager
systemctl restart hysteria-control
```

Для TLS используется сертификат Let's Encrypt для указанного домена. SNI должен совпадать с доменом сертификата. Перед ручными изменениями сделайте резервные копии базы /var/lib/hysteria-control/panel.db, конфигурации /etc/hysteria/config.yaml и файла настроек /etc/hysteria-control/panel.env.

## English

A lightweight Hysteria 2 server and web panel for managing users, connection links, QR codes, traffic, and basic server health. Built with Flask and SQLite; no Docker, Nginx, PostgreSQL, or frontend build is required.

### One-command installation

Requirements: Ubuntu 22.04+ or Debian 11+ with systemd and root access; a public server and a domain already pointed to it; TCP port 80 reachable for Let's Encrypt, UDP/443 for Hysteria, and TCP/8443 for the panel by default. Recommended: 1 vCPU and 1 GB RAM (512 MB minimum).

Run on a fresh server from an interactive terminal:

```sh
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo bash
```

The installer asks for the domain, a Let's Encrypt contact email, and panel login. Hysteria is pinned to v2.12.3 by default. Random panel/API secrets are generated; save the initial panel password printed once after installation. The panel runs under a dedicated unprivileged account.

For non-interactive setup, export values before running the installer:

```sh
export HC_DOMAIN=vpn.example.com HC_EMAIL=admin@example.com HC_PANEL_USER=admin
curl -fsSL https://raw.githubusercontent.com/ilya-sid/hysteria-control/main/install.sh | sudo --preserve-env=HC_DOMAIN,HC_EMAIL,HC_PANEL_USER bash
```

The panel uses TCP/8443 by default (customize with PANEL_PORT); Hysteria uses UDP/443. TCP/80 is required for certificate issuance and renewal. If UFW is active, the installer opens the required ports; otherwise, configure your provider firewall. The installer refuses to overwrite existing Hysteria configuration/services or occupied required ports. It is intended for a fresh server and does not remove existing services.

### Services and troubleshooting

```sh
systemctl status hysteria-server hysteria-control --no-pager
journalctl -u hysteria-server -u hysteria-control -n 100 --no-pager
systemctl restart hysteria-control
```

Hysteria is installed using the [official server installation script](https://v2.hysteria.network/docs/getting-started/Server-Installation-Script/) and official userpass, TLS, and Traffic Stats API settings. SNI must match the installed certificate domain. Back up /var/lib/hysteria-control/panel.db, /etc/hysteria/config.yaml, and /etc/hysteria-control/panel.env before manual changes.

## License

No license has been selected yet. Until one is added, the source is visible but reuse and redistribution are not granted.
