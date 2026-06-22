# Complete Installation Guide

This guide installs WatchMyLAN Lite on a Linux server, including Docker, persistence, HTTPS, updates, backups and VLAN agents.

## 1. Choose The Host

Use a Linux machine connected directly to the LAN being monitored. Suitable choices include:

- Debian or Ubuntu server.
- A Proxmox LXC with nesting and raw-network permissions.
- A Proxmox virtual machine.
- A Raspberry Pi or small x86 home server.

Docker host networking is Linux-specific. Docker Desktop on Windows or macOS runs inside a VM and cannot scan the physical LAN ARP domain reliably.

Recommended minimum resources:

- 1 CPU core.
- 512 MB RAM.
- 2 GB free disk space.
- Static IP or DHCP reservation.

## 2. Install Docker On Debian/Ubuntu

Remove conflicting distribution packages if present:

```bash
sudo apt-get remove -y docker.io docker-compose docker-doc podman-docker containerd runc || true
```

Install Docker from the official convenience script:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh
sudo systemctl enable --now docker
```

Verify:

```bash
sudo docker version
sudo docker compose version
```

Optional: allow the current user to manage Docker:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

Membership in the Docker group is effectively root access.

## 3. Download WatchMyLAN Lite

```bash
sudo mkdir -p /opt/watchmylan-lite
sudo chown "$USER":"$USER" /opt/watchmylan-lite
git clone https://github.com/angelrb95/WatchMyLAN-Lite.git /opt/watchmylan-lite
cd /opt/watchmylan-lite
```

## 4. Create Configuration

```bash
cp .env.example .env
nano .env
```

At minimum, set the LAN address of the server:

```dotenv
WATCHMYLAN_HOST=192.168.1.10
APP_PORT=8088
HTTPS_PORT=8443
```

Optional Telegram example:

```dotenv
TELEGRAM_URL=telegram://BOT_TOKEN@telegram?channels=CHAT_ID
```

Optional SMTP example:

```dotenv
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=watchmylan@example.com
SMTP_PASSWORD=CHANGE_ME
SMTP_FROM=watchmylan@example.com
ALERT_EMAIL_TO=admin@example.com
SMTP_TLS=true
```

Protect the file:

```bash
chmod 600 .env
```

## 5. Start With Docker Compose

```bash
docker compose up -d --build
```

Check status and logs:

```bash
docker compose ps
docker compose logs -f --tail=100 watchmylan-lite
```

Open:

```text
http://SERVER_IP:8088
https://SERVER_IP:8443
```

The application starts an automatic scan immediately. A `/24` scan can take around 10-25 seconds depending on timeouts and device behavior.

## 6. Firewall

If a host firewall is enabled, allow the web ports only from the LAN. Example with UFW:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8088 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 8443 proto tcp
```

Do not forward these ports from the Internet-facing router.

## 7. HTTPS Certificate

Caddy creates an internal certificate for `WATCHMYLAN_HOST`. Browsers do not trust its private CA automatically.

The root certificate is stored at:

```text
./caddy-data/caddy/pki/authorities/local/root.crt
```

Copy that certificate to managed client devices and import it into the trusted root certificate store. Alternatively, keep using HTTP on a trusted isolated LAN or configure Caddy with a DNS name and a certificate trusted by your organization.

Changing `WATCHMYLAN_HOST` requires recreating Caddy:

```bash
docker compose up -d --force-recreate watchmylan-https
```

## 8. First Configuration

Open **Configuration** in the dashboard and review:

1. Scan interval and offline tolerance.
2. ARP passes and ICMP timeout.
3. mDNS, SSDP and NetBIOS discovery.
4. Telegram, email or webhook alerts.
5. Backup interval and metrics retention.
6. Optional authentication.
7. Optional TCP service discovery.

Authentication is disabled initially. When enabling it, set a username and a password of at least eight characters in the same save operation.

## 9. Persistence And Backups

Persistent directories:

```text
./data/          SQLite database and backups
./caddy-data/    Caddy certificates
./caddy-config/  Caddy runtime configuration
```

Create a manual backup from Configuration or copy the generated SQLite backup:

```bash
ls -lh data/backups/
```

For an external backup:

```bash
tar -czf watchmylan-backup-$(date +%F).tar.gz data caddy-data .env
```

Store archives outside the Docker host. The `.env` archive contains secrets and must be encrypted/protected.

## 10. Updating

Create a backup, then:

```bash
cd /opt/watchmylan-lite
git pull --ff-only
docker compose up -d --build
docker image prune -f
```

Check health:

```bash
curl -fsS http://127.0.0.1:8088/health
```

SQLite migrations run automatically and are designed to preserve existing records.

## 11. Uninstalling

Stop containers while preserving data:

```bash
docker compose down
```

Remove the application and all local data only after making a backup:

```bash
docker compose down
cd /opt
sudo rm -rf /opt/watchmylan-lite
```

## 12. Manual Installation Without Docker

Manual installation is supported on Linux. Raw sockets require root or equivalent capabilities.

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv libpcap0.8 iproute2 iputils-ping avahi-utils samba-common-bin
git clone https://github.com/angelrb95/WatchMyLAN-Lite.git
cd WatchMyLAN-Lite
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
sudo DATA_DIR=/var/lib/watchmylan .venv/bin/uvicorn main:app --host 0.0.0.0 --port 8088
```

For long-term manual operation, create a dedicated systemd unit and protect the data directory. Docker Compose is the recommended deployment.

## 13. Proxmox Notes

### Virtual Machine

A VM is the simplest option. Attach its virtual NIC to the LAN bridge and reserve a static IP. Install Docker normally inside the VM.

### LXC

Docker in LXC requires nesting and may require additional permissions depending on Proxmox security settings. A privileged LXC is easier but has a larger security impact. Confirm that the container can:

```bash
ip link show
ping -c 1 ROUTER_IP
```

The application container itself receives `NET_RAW` and `NET_ADMIN` through Compose.

## 14. VLAN And Remote Agent Installation

ARP does not cross routers. For each separated VLAN, run `agent.py` on a Linux machine connected to that VLAN.

On the main dashboard:

1. Open **Configuration > VLAN Agents**.
2. Create an agent name and subnet.
3. Store the generated token; it is shown only once.

On the VLAN host:

```bash
git clone https://github.com/angelrb95/WatchMyLAN-Lite.git
cd WatchMyLAN-Lite
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

export WATCHMYLAN_SERVER=http://MAIN_SERVER_IP:8088
export WATCHMYLAN_AGENT_TOKEN=GENERATED_TOKEN
export WATCHMYLAN_SUBNET=192.168.20.0/24
export WATCHMYLAN_INTERFACE=eth0
export WATCHMYLAN_INTERVAL=120

sudo -E .venv/bin/python agent.py
```

Run it under systemd or a host-network Docker container for permanent operation.

## 15. Troubleshooting

### No devices are discovered

Confirm host networking and capabilities:

```bash
docker inspect watchmylan-lite --format '{{.HostConfig.NetworkMode}} {{json .HostConfig.CapAdd}}'
```

Expected network mode: `host`.

Test ARP visibility from the host:

```bash
ip neigh show
ping -c 1 ROUTER_IP
```

### Devices incorrectly become offline

- Increase **Offline after misses**.
- Keep the ping sweep and kernel-neighbor merge enabled.
- Increase ARP passes for Wi-Fi/IoT devices.
- Check VLAN isolation or wireless client isolation.

### Names are empty

Many home routers do not publish reverse DNS. Set a custom name in the dashboard. Keep mDNS, SSDP and NetBIOS enabled for compatible devices.

### HTTPS container restarts

Check whether ports 80 or 8443 are occupied:

```bash
sudo ss -lntup | grep -E ':80|:8443'
docker logs watchmylan-https
```

The supplied Caddyfile disables automatic HTTP redirects and should only bind the configured HTTPS port.

### Permission denied from Scapy

Verify Compose includes:

```yaml
network_mode: host
cap_add:
  - NET_RAW
  - NET_ADMIN
```

### Database recovery

Stop the application and replace the database with a known-good backup:

```bash
docker compose stop watchmylan-lite
cp data/backups/watchmylan-YYYYMMDD-HHMMSS.db data/watchmylan.db
docker compose start watchmylan-lite
```

### Inspect logs

```bash
docker compose logs --tail=200 watchmylan-lite
docker compose logs --tail=100 watchmylan-https
```
