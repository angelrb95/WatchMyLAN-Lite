# Guía completa de instalación

[Español](INSTALL.md) | [English](INSTALL.en.md) | [Volver al README](README.md)

Esta guía explica cómo instalar WatchMyLAN Lite en un servidor Linux con Docker, persistencia, HTTPS, actualizaciones, copias de seguridad y agentes para VLAN.

## 1. Elegir el servidor

Utiliza un equipo Linux conectado directamente a la red que quieres supervisar. Algunas opciones adecuadas:

- Servidor Debian o Ubuntu.
- Contenedor LXC de Proxmox con nesting y permisos de red raw.
- Máquina virtual en Proxmox.
- Raspberry Pi o pequeño servidor x86.

La red host de Docker es específica de Linux. Docker Desktop en Windows o macOS se ejecuta dentro de una máquina virtual y no puede explorar de forma fiable el dominio ARP de la red física.

Recursos mínimos recomendados:

- 1 núcleo de CPU.
- 512 MB de RAM.
- 2 GB de espacio libre.
- IP estática o reserva DHCP.

## 2. Instalar Docker en Debian o Ubuntu

Elimina paquetes incompatibles si están instalados:

```bash
sudo apt-get remove -y docker.io docker-compose docker-doc podman-docker containerd runc || true
```

Instala Docker:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh
sudo systemctl enable --now docker
```

Comprueba la instalación:

```bash
sudo docker version
sudo docker compose version
```

Opcionalmente, permite al usuario actual administrar Docker:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

La pertenencia al grupo Docker equivale prácticamente a tener acceso root.

## 3. Descargar WatchMyLAN Lite

```bash
sudo mkdir -p /opt/watchmylan-lite
sudo chown "$USER":"$USER" /opt/watchmylan-lite
git clone https://github.com/angelrb95/WatchMyLAN-Lite.git /opt/watchmylan-lite
cd /opt/watchmylan-lite
```

Si `/opt/watchmylan-lite` contiene una instalación antigua que no es un repositorio Git, haz primero una copia de `data/` y reemplaza los archivos de aplicación por un clon limpio.

## 4. Crear la configuración

```bash
cp .env.example .env
nano .env
```

Como mínimo, indica la dirección LAN del servidor:

```dotenv
WATCHMYLAN_HOST=192.168.1.10
APP_PORT=8088
HTTPS_PORT=8443
```

Ejemplo opcional de Telegram:

```dotenv
TELEGRAM_URL=telegram://BOT_TOKEN@telegram?channels=CHAT_ID
```

Ejemplo opcional de SMTP:

```dotenv
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=watchmylan@example.com
SMTP_PASSWORD=CAMBIAR
SMTP_FROM=watchmylan@example.com
ALERT_EMAIL_TO=admin@example.com
SMTP_TLS=true
```

Protege el archivo:

```bash
chmod 600 .env
```

## 5. Iniciar con Docker Compose

```bash
docker compose up -d --build
```

Comprueba los contenedores y los registros:

```bash
docker compose ps
docker compose logs -f --tail=100 watchmylan-lite
```

Abre en el navegador:

```text
http://IP_DEL_SERVIDOR:8088
https://IP_DEL_SERVIDOR:8443
```

La aplicación inicia un escaneo automático al arrancar. Una red `/24` suele tardar entre 10 y 25 segundos según los tiempos de espera y el comportamiento de los dispositivos.

## 6. Cortafuegos

Si utilizas un cortafuegos, permite los puertos web únicamente desde la LAN. Ejemplo con UFW:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8088 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 8443 proto tcp
```

No redirijas estos puertos desde el router hacia Internet.

## 7. Certificado HTTPS

Caddy crea un certificado interno para `WATCHMYLAN_HOST`. Los navegadores no confían automáticamente en su autoridad privada.

El certificado raíz se encuentra en:

```text
./caddy-data/caddy/pki/authorities/local/root.crt
```

Cópialo a los dispositivos administrados e impórtalo en el almacén de autoridades raíz de confianza. También puedes utilizar HTTP dentro de una LAN aislada o configurar Caddy con un nombre DNS y un certificado reconocido por tu organización.

Después de cambiar `WATCHMYLAN_HOST`, recrea Caddy:

```bash
docker compose up -d --force-recreate watchmylan-https
```

## 8. Primera configuración

Abre **Configuración** en el panel y revisa:

1. Intervalo de escaneo y tolerancia Offline.
2. Pasadas ARP y tiempo de espera ICMP.
3. Descubrimiento mDNS, SSDP y NetBIOS.
4. Avisos por Telegram, correo o webhook.
5. Intervalo de copias y retención de métricas.
6. Autenticación opcional.
7. Exploración TCP opcional.

La autenticación está desactivada inicialmente. Para activarla, guarda a la vez un nombre de usuario y una contraseña de al menos ocho caracteres.

## 9. Persistencia y copias de seguridad

Directorios persistentes:

```text
./data/          base de datos SQLite y copias
./caddy-data/    certificados de Caddy
./caddy-config/  configuración interna de Caddy
```

Crea una copia manual desde **Configuración** o consulta las copias generadas:

```bash
ls -lh data/backups/
```

Copia externa completa:

```bash
tar -czf watchmylan-backup-$(date +%F).tar.gz data caddy-data .env
```

Guarda el archivo fuera del servidor Docker. Contiene secretos de `.env` y debe protegerse o cifrarse.

## 10. Actualizar

Crea una copia de seguridad y ejecuta:

```bash
cd /opt/watchmylan-lite
git pull --ff-only
docker compose up -d --build
docker image prune -f
```

Comprueba el servicio:

```bash
curl -fsS http://127.0.0.1:8088/health
```

Las migraciones de SQLite se ejecutan automáticamente y están diseñadas para conservar los registros existentes.

## 11. Desinstalar

Detén los contenedores conservando los datos:

```bash
docker compose down
```

Para eliminar también la aplicación y sus datos, crea primero una copia y después:

```bash
docker compose down
cd /opt
sudo rm -rf /opt/watchmylan-lite
```

## 12. Instalación manual sin Docker

La instalación manual es compatible con Linux. Los sockets raw requieren root o capacidades equivalentes.

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

Para uso permanente crea una unidad systemd dedicada y protege el directorio de datos. Docker Compose es el método recomendado.

## 13. Notas para Proxmox

### Máquina virtual

Es la opción más sencilla. Conecta su interfaz virtual al bridge de la LAN, reserva una IP fija e instala Docker normalmente dentro de la máquina.

### Contenedor LXC

Docker dentro de LXC requiere nesting y, según la configuración de seguridad de Proxmox, permisos adicionales. Un LXC privilegiado resulta más sencillo, pero tiene un impacto de seguridad mayor.

Comprueba que el LXC puede acceder a la red:

```bash
ip link show
ping -c 1 IP_DEL_ROUTER
```

El contenedor de la aplicación recibe `NET_RAW` y `NET_ADMIN` mediante Docker Compose.

## 14. VLAN y agentes remotos

ARP no atraviesa routers. Ejecuta `agent.py` en un equipo Linux conectado a cada VLAN separada.

En el panel principal:

1. Abre **Configuración > Agentes VLAN**.
2. Crea un agente indicando nombre y subred.
3. Guarda el token generado; solo se muestra una vez.

En el host de la VLAN:

```bash
git clone https://github.com/angelrb95/WatchMyLAN-Lite.git
cd WatchMyLAN-Lite
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

export WATCHMYLAN_SERVER=http://IP_SERVIDOR_PRINCIPAL:8088
export WATCHMYLAN_AGENT_TOKEN=TOKEN_GENERADO
export WATCHMYLAN_SUBNET=192.168.20.0/24
export WATCHMYLAN_INTERFACE=eth0
export WATCHMYLAN_INTERVAL=120

sudo -E .venv/bin/python agent.py
```

Para uso permanente, ejecútalo mediante systemd o un contenedor Docker con red host.

## 15. Resolución de problemas

### No se descubre ningún dispositivo

Comprueba la red host y las capacidades:

```bash
docker inspect watchmylan-lite --format '{{.HostConfig.NetworkMode}} {{json .HostConfig.CapAdd}}'
```

El modo de red esperado es `host`. Comprueba también la visibilidad ARP desde el servidor:

```bash
ip neigh show
ping -c 1 IP_DEL_ROUTER
```

### Algunos dispositivos aparecen Offline incorrectamente

- Aumenta **Fallos para offline**.
- Mantén activos el barrido ping y la tabla de vecinos.
- Aumenta las pasadas ARP para equipos Wi-Fi o IoT.
- Revisa el aislamiento de clientes inalámbricos y las VLAN.

### Los nombres de red aparecen vacíos

Muchos routers domésticos no publican DNS inverso. Asigna un nombre personalizado desde el panel y mantén activos mDNS, SSDP y NetBIOS para los dispositivos compatibles.

### El contenedor HTTPS se reinicia

Comprueba si los puertos 80 o 8443 están ocupados:

```bash
sudo ss -lntup | grep -E ':80|:8443'
docker logs watchmylan-https
```

El `Caddyfile` incluido desactiva las redirecciones HTTP automáticas y solo debe enlazar el puerto HTTPS configurado.

### Scapy muestra Permission denied

Comprueba que Docker Compose contiene:

```yaml
network_mode: host
cap_add:
  - NET_RAW
  - NET_ADMIN
```

### Recuperar la base de datos

Detén la aplicación y restaura una copia válida:

```bash
docker compose stop watchmylan-lite
cp data/backups/watchmylan-YYYYMMDD-HHMMSS.db data/watchmylan.db
docker compose start watchmylan-lite
```

### Consultar registros

```bash
docker compose logs --tail=200 watchmylan-lite
docker compose logs --tail=100 watchmylan-https
```

## 16. Comprobación final

```bash
docker compose ps
curl -fsS http://127.0.0.1:8088/health
docker compose logs --since=5m watchmylan-lite
```

El contenedor debe aparecer como `Up`, `/health` debe responder correctamente y los registros no deben mostrar errores durante el arranque.
