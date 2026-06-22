# WatchMyLAN Lite

WatchMyLAN Lite is a self-hosted local network monitor built with FastAPI, Scapy and SQLite. It discovers devices using ARP and ICMP, keeps connection history, measures response time and provides a responsive web dashboard.

## Highlights

- Hybrid ARP, ICMP and kernel-neighbor discovery.
- Automatic local subnet and active interface detection.
- mDNS, SSDP, NetBIOS and reverse-DNS name enrichment.
- Online/offline state with configurable missed-scan tolerance.
- IP, MAC, hostname, custom name, vendor OUI and device type.
- Connection history, connected-since time and IP-change events.
- Response-time metrics, uptime, availability and stability charts.
- Persistent sorting, search, filters, favorites and CSV export.
- Wake-on-LAN and optional TCP service discovery.
- Alerts for new unknown devices through Telegram, email or webhook.
- Optional HTTP Basic authentication and local HTTPS through Caddy.
- Automatic SQLite backups with configurable retention.
- Remote agents for VLANs or separate broadcast domains.
- Single-page frontend with no JavaScript build step.

## Stack

- Backend: Python 3.12, FastAPI, SQLModel and Scapy.
- Database: SQLite.
- Frontend: HTML5, Tailwind CSS CDN and vanilla JavaScript.
- Deployment: multi-stage Docker image and Docker Compose.
- HTTPS: Caddy with an internal certificate authority.

## Quick Start With Docker

Requirements:

- Linux host on the network to monitor.
- Docker Engine 24+ and Docker Compose v2.
- Root or permission to manage Docker.

```bash
git clone https://github.com/angelrb95/WatchMyLAN-Lite.git
cd WatchMyLAN-Lite
cp .env.example .env
```

Edit `.env` and set the LAN address of the Docker host:

```dotenv
WATCHMYLAN_HOST=192.168.1.10
```

Start the application:

```bash
docker compose up -d --build
```

Open:

- HTTP: `http://SERVER_IP:8088`
- HTTPS: `https://SERVER_IP:8443`

The HTTPS certificate is issued by Caddy's local CA. Browsers will warn until that CA is trusted on the client.

> `network_mode: host` and the `NET_RAW`/`NET_ADMIN` capabilities are required. Bridge networking cannot see the physical LAN ARP broadcast domain.

See [INSTALL.md](INSTALL.md) for the complete installation, update, backup, agent and troubleshooting guide.

## Configuration

Most runtime options can be changed from **Configuration** without rebuilding the image. Environment variables provide initial defaults.

| Variable | Default | Purpose |
| --- | --- | --- |
| `WATCHMYLAN_HOST` | `localhost` | Hostname/IP used by local HTTPS. |
| `APP_PORT` | `8088` | HTTP application port. |
| `HTTPS_PORT` | `8443` | Caddy HTTPS port. |
| `SCAN_INTERVAL_SECONDS` | `120` | Automatic scan interval. |
| `OFFLINE_AFTER_MISSES` | `3` | Missed scans before Offline. |
| `ARP_TIMEOUT_SECONDS` | `2` | ARP response timeout. |
| `ARP_RETRIES` | `1` | ARP retry count. |
| `ARP_PASSES` | `3` | ARP passes per scan. |
| `INCLUDE_KERNEL_NEIGHBORS` | `true` | Merge the host neighbor table. |
| `ENABLE_PING_SWEEP` | `true` | Enable concurrent ICMP discovery. |
| `PING_TIMEOUT_SECONDS` | `1` | ICMP timeout per host. |
| `PING_WORKERS` | `128` | Maximum requested ping concurrency. |
| `TELEGRAM_URL` | empty | Telegram bot destination. |
| `SMTP_*` | empty | Email alert configuration. |

Telegram URL format:

```text
telegram://BOT_TOKEN@telegram?channels=CHAT_ID
```

Never commit `.env`; it is intentionally ignored by Git.

## Alerts

Automatic alerts are sent only when a MAC address has never been seen before and is not marked as known. Reconnects and normal offline transitions do not generate alerts.

Supported destinations:

- Telegram bot.
- SMTP email.
- Generic JSON webhook, including Home Assistant webhooks.

## Network Discovery

Each scan combines multiple sources:

1. Broadcast ARP through Scapy.
2. Concurrent ICMP responses and response-time measurement.
3. Linux neighbor table before and after the sweep.
4. Previously confirmed IP/MAC mappings when ICMP responds.
5. Reverse DNS, mDNS, SSDP and NetBIOS names.

Additional directly reachable `/24` networks can be configured in the UI. Networks separated by routers, VLAN ACLs or different ARP domains require an agent.

## Remote Agents

Create an agent in **Configuration > VLAN Agents**. The token is shown once. On a Linux host attached to the remote segment:

```bash
export WATCHMYLAN_SERVER=http://MAIN_SERVER_IP:8088
export WATCHMYLAN_AGENT_TOKEN=GENERATED_TOKEN
export WATCHMYLAN_SUBNET=192.168.20.0/24
export WATCHMYLAN_INTERFACE=eth0
sudo -E python agent.py
```

The agent performs local ARP discovery and reports results to the main server using its token.

## Data And Backups

Persistent data is stored in `./data/watchmylan.db`. Docker Compose mounts `./data` into the container. Automatic and manual backups are stored under `./data/backups` and use SQLite's online backup API.

The following directories must never be committed:

- `data/`
- `caddy-data/`
- `caddy-config/`

## Security

- Enable authentication from Configuration before exposing the dashboard beyond a trusted LAN.
- Prefer HTTPS and trust the Caddy local CA on managed clients.
- Do not publish port `8088` to the Internet.
- Store Telegram, SMTP and webhook credentials only in `.env` or the settings database.
- Rotate any credential accidentally shared in chat, logs or Git history.
- TCP service discovery is disabled by default and should only be used on networks you administer.

## API Overview

| Endpoint | Purpose |
| --- | --- |
| `GET /api/devices` | List devices. |
| `PUT /api/devices/{mac}` | Edit a device. |
| `DELETE /api/devices/{mac}` | Delete device and history. |
| `POST /api/devices/{mac}/wake` | Send Wake-on-LAN. |
| `GET /api/devices/{mac}/history` | Connection history. |
| `POST /api/devices/{mac}/services` | Optional TCP service scan. |
| `POST /api/scan` | Trigger a scan. |
| `GET /api/analytics` | Availability and latency metrics. |
| `GET/PUT /api/settings` | Read/update configuration. |
| `GET/POST /api/backups` | List/create backups. |
| `GET/POST /api/agents` | Manage VLAN agents. |
| `GET /health` | Health check. |

FastAPI OpenAPI documentation is available at `/docs`.

## Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8088
```

ARP scanning requires Linux and elevated raw-socket privileges. The frontend is served directly from `static/index.html`.

## Updating

```bash
git pull --ff-only
docker compose up -d --build
```

Database schema upgrades are incremental and preserve existing data. Create a backup before updating.

## Project Layout

```text
.
|-- main.py                 FastAPI, scanner and API
|-- database.py             SQLModel models and migrations
|-- features.py             vendors, discovery, backups and services
|-- agent.py                remote VLAN agent
|-- static/index.html       single-page dashboard
|-- Dockerfile              multi-stage image
|-- docker-compose.yml      host-network deployment
|-- Caddyfile               local HTTPS proxy
|-- .env.example            safe configuration template
`-- INSTALL.md              full installation guide
```

## Notes

- Some devices intentionally block ICMP; they can still be online through ARP.
- Randomized/private MAC addresses may not have a vendor.
- Historical charts become more useful as automatic scans accumulate samples.
- Deleting an online device causes it to be rediscovered during the next scan.
