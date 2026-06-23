from __future__ import annotations

import asyncio
import base64
import csv
import hmac
import io
import ipaddress
import json
import math
import os
import re
import secrets
import smtplib
import socket
import ssl
import statistics
import subprocess
import time
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

import psutil
from fastapi import Depends, FastAPI, HTTPException, Request as FastAPIRequest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from scapy.all import ARP, Ether, srp  # type: ignore
from sqlmodel import Session, select

from database import Agent, AppSetting, ConnectionEvent, Device, DeviceMetric, DeviceUpdate, ScanSnapshot, engine, get_session, init_db
from features import (
    create_backup,
    discover_ssdp,
    hash_password,
    lookup_vendor,
    parse_ports,
    resolve_mdns,
    resolve_netbios,
    scan_ports,
    send_webhook,
    verify_password,
)


APP_NAME = "WatchMyLAN Lite"
STATIC_DIR = Path(__file__).parent / "static"
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATABASE_PATH = DATA_DIR / "watchmylan.db"
BACKUP_DIR = DATA_DIR / "backups"
DEFAULT_SETTINGS: dict[str, Any] = {
    "scan_interval_seconds": int(os.getenv("SCAN_INTERVAL_SECONDS", "120")),
    "offline_after_misses": int(os.getenv("OFFLINE_AFTER_MISSES", "3")),
    "arp_timeout_seconds": float(os.getenv("ARP_TIMEOUT_SECONDS", "2.0")),
    "arp_retries": int(os.getenv("ARP_RETRIES", "1")),
    "arp_passes": int(os.getenv("ARP_PASSES", "2")),
    "include_kernel_neighbors": os.getenv("INCLUDE_KERNEL_NEIGHBORS", "true").lower() == "true",
    "enable_ping_sweep": os.getenv("ENABLE_PING_SWEEP", "true").lower() == "true",
    "ping_timeout_seconds": int(os.getenv("PING_TIMEOUT_SECONDS", "1")),
    "ping_workers": int(os.getenv("PING_WORKERS", "128")),
    "telegram_enabled": bool(os.getenv("TELEGRAM_URL", "")),
    "telegram_url": os.getenv("TELEGRAM_URL", ""),
    "email_enabled": bool(os.getenv("SMTP_HOST", "") and os.getenv("ALERT_EMAIL_TO", "")),
    "smtp_host": os.getenv("SMTP_HOST", ""),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "smtp_username": os.getenv("SMTP_USERNAME", ""),
    "smtp_password": os.getenv("SMTP_PASSWORD", ""),
    "smtp_from": os.getenv("SMTP_FROM", os.getenv("SMTP_USERNAME", "")),
    "alert_email_to": os.getenv("ALERT_EMAIL_TO", ""),
    "smtp_tls": os.getenv("SMTP_TLS", "true").lower() == "true",
    "mdns_enabled": True,
    "ssdp_enabled": True,
    "netbios_enabled": True,
    "extra_networks": "",
    "webhook_enabled": False,
    "webhook_url": "",
    "port_scan_enabled": False,
    "port_scan_ports": "22,53,80,443,445,554,1883,3000,5000,8000,8080,8123,8443,9000,32400",
    "backup_enabled": True,
    "backup_interval_hours": 24,
    "backup_retention": 14,
    "metrics_retention_days": 30,
    "auth_enabled": False,
    "auth_username": "admin",
    "auth_password_hash": "",
}
runtime_settings = DEFAULT_SETTINGS.copy()
SECRET_SETTINGS = {"telegram_url", "smtp_password", "webhook_url", "auth_password_hash"}

scan_lock = asyncio.Lock()
scanner_task: asyncio.Task[None] | None = None
backup_task: asyncio.Task[None] | None = None
last_scan_status: dict[str, Any] = {
    "running": False,
    "last_started_at": None,
    "last_finished_at": None,
    "last_duration_ms": None,
    "last_found": None,
    "last_error": "",
}


class SettingsUpdate(BaseModel):
    scan_interval_seconds: int | None = Field(default=None, ge=30, le=86400)
    offline_after_misses: int | None = Field(default=None, ge=1, le=50)
    arp_timeout_seconds: float | None = Field(default=None, ge=0.2, le=30)
    arp_retries: int | None = Field(default=None, ge=0, le=10)
    arp_passes: int | None = Field(default=None, ge=1, le=10)
    include_kernel_neighbors: bool | None = None
    enable_ping_sweep: bool | None = None
    ping_timeout_seconds: int | None = Field(default=None, ge=1, le=10)
    ping_workers: int | None = Field(default=None, ge=1, le=512)
    telegram_enabled: bool | None = None
    telegram_url: str | None = None
    email_enabled: bool | None = None
    smtp_host: str | None = None
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    alert_email_to: str | None = None
    smtp_tls: bool | None = None
    mdns_enabled: bool | None = None
    ssdp_enabled: bool | None = None
    netbios_enabled: bool | None = None
    extra_networks: str | None = None
    webhook_enabled: bool | None = None
    webhook_url: str | None = None
    port_scan_enabled: bool | None = None
    port_scan_ports: str | None = None
    backup_enabled: bool | None = None
    backup_interval_hours: int | None = Field(default=None, ge=1, le=720)
    backup_retention: int | None = Field(default=None, ge=1, le=365)
    metrics_retention_days: int | None = Field(default=None, ge=1, le=365)
    auth_enabled: bool | None = None
    auth_username: str | None = None
    auth_password: str | None = Field(default=None, min_length=8, max_length=128)


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    subnet: str = Field(default="", max_length=80)


class AgentReport(BaseModel):
    devices: list[dict[str, str]]


class BulkKnownUpdate(BaseModel):
    macs: list[str] = Field(default_factory=list, max_length=1000)
    known: bool = True


def setting(key: str) -> Any:
    return runtime_settings[key]


def decode_setting(key: str, value: str) -> Any:
    default = DEFAULT_SETTINGS[key]
    if isinstance(default, bool):
        return value.lower() == "true"
    if isinstance(default, int):
        return int(value)
    if isinstance(default, float):
        return float(value)
    return value


def load_settings() -> None:
    runtime_settings.clear()
    runtime_settings.update(DEFAULT_SETTINGS)
    with Session(engine) as session:
        for item in session.exec(select(AppSetting)).all():
            if item.key in DEFAULT_SETTINGS:
                runtime_settings[item.key] = decode_setting(item.key, item.value)


def backfill_inventory() -> None:
    with Session(engine) as session:
        for device in session.exec(select(Device)).all():
            if not device.vendor:
                device.vendor = lookup_vendor(device.mac)
            if not device.device_type or device.device_type == "Otro":
                device.device_type = infer_device_type(display_name(device), device.vendor)
            session.add(device)
        session.commit()


def public_settings() -> dict[str, Any]:
    result = {key: value for key, value in runtime_settings.items() if key not in SECRET_SETTINGS}
    result.update(
        {
            "telegram_url": "",
            "telegram_configured": bool(setting("telegram_url")),
            "smtp_password": "",
            "smtp_password_configured": bool(setting("smtp_password")),
            "webhook_url": "",
            "webhook_configured": bool(setting("webhook_url")),
            "auth_password": "",
            "auth_password_configured": bool(setting("auth_password_hash")),
        }
    )
    return result


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def aware_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def default_route_ip() -> str | None:
    """Detecta la IP local que usa la ruta por defecto sin enviar trafico real."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return None


def active_network() -> tuple[str, ipaddress.IPv4Network]:
    """Busca la interfaz IPv4 activa y calcula su subred local."""
    stats = psutil.net_if_stats()
    route_ip = default_route_ip()
    candidates: list[tuple[str, ipaddress.IPv4Address, ipaddress.IPv4Network]] = []

    for name, addresses in psutil.net_if_addrs().items():
        if name in stats and not stats[name].isup:
            continue

        for addr in addresses:
            if addr.family != socket.AF_INET or not addr.netmask:
                continue
            if addr.address.startswith("127."):
                continue

            ip = ipaddress.IPv4Address(addr.address)
            network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
            candidates.append((name, ip, network))

    if not candidates:
        raise RuntimeError("No active IPv4 network interface found")

    if route_ip:
        for name, ip, network in candidates:
            if str(ip) == route_ip:
                return name, network

    name, _, network = candidates[0]
    return name, network


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def local_interface_device(interface_name: str) -> dict[str, str] | None:
    """Incluye el propio host, que nunca aparece en su tabla de vecinos."""
    ip = ""
    mac = ""
    link_family = getattr(psutil, "AF_LINK", None)
    for address in psutil.net_if_addrs().get(interface_name, []):
        if address.family == socket.AF_INET and not address.address.startswith("127."):
            ip = address.address
        elif link_family is not None and address.family == link_family:
            mac = address.address.upper()
    if not ip or not mac or mac == "00:00:00:00:00:00":
        return None
    return {"mac": mac, "ip": ip, "hostname": socket.gethostname(), "local": "true"}


def known_devices_by_ip() -> dict[str, dict[str, str]]:
    with Session(engine) as session:
        devices = session.exec(select(Device)).all()
        return {
            device.ip: {
                "mac": device.mac,
                "ip": device.ip,
                "hostname": device.hostname or device.custom_name,
            }
            for device in devices
        }


def sort_key(ip: str) -> tuple[int, int, int, int]:
    return tuple(int(part) for part in ip.split("."))


def scan_networks(primary: ipaddress.IPv4Network) -> list[ipaddress.IPv4Network]:
    networks = [primary]
    for value in setting("extra_networks").split(","):
        value = value.strip()
        if not value:
            continue
        try:
            network = ipaddress.IPv4Network(value, strict=False)
            if network.version == 4 and network.prefixlen >= 24 and network not in networks:
                networks.append(network)
        except ValueError:
            print(f"[scanner] invalid extra network ignored: {value}")
    return networks


def display_name(device: Device | dict[str, str]) -> str:
    if isinstance(device, Device):
        return device.custom_name or device.hostname or device.ip
    return device.get("hostname") or device.get("ip") or device.get("mac", "")


def infer_device_type(name: str, vendor: str) -> str:
    text = f"{name} {vendor}".lower()
    rules = [
        ("Router", ("router", "halo", "gateway")),
        ("Camara", ("camara", "camera", "ring", "mirilla")),
        ("Servidor", ("proxmox", "nas", "synology", "plex", "jellyfin", "grafana", "adguard", "home assistant", "wireguard")),
        ("Entretenimiento", ("nintendo", "fire stick", "tv", "amazon")),
        ("Movil", ("movil", "mobile", "tablet", "portatil")),
        ("Ordenador", (" pc", "desktop", "asustek", "gigabyte", "micro-star")),
        ("IoT", ("enchufe", "meross", "tuya", "vacuum", "alarma", "nerdminer", "iot")),
    ]
    return next((category for category, words in rules if any(word in text for word in words)), "Otro")


def kernel_neighbors(interface_name: str, network: ipaddress.IPv4Network) -> list[dict[str, str]]:
    """Lee la tabla ARP/neighbor del host como respaldo del escaneo activo."""
    if not setting("include_kernel_neighbors"):
        return []

    try:
        result = subprocess.run(
            ["ip", "neigh", "show", "dev", interface_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    states_allowed = {"REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"}
    devices: list[dict[str, str]] = []

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or "lladdr" not in parts:
            continue

        ip = parts[0]
        state = parts[-1].upper()
        if state not in states_allowed:
            continue

        try:
            parsed_ip = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        if parsed_ip not in network:
            continue

        mac = parts[parts.index("lladdr") + 1].upper()
        devices.append({"mac": mac, "ip": ip, "hostname": resolve_hostname(ip)})

    return devices


def ping_host(ip: str) -> float | None:
    """Fuerza trafico unicast y devuelve la latencia medida en milisegundos."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, setting("ping_timeout_seconds"))), ip],
            check=False,
            capture_output=True,
            text=True,
            timeout=max(2, setting("ping_timeout_seconds") + 1),
        )
        if result.returncode != 0:
            return None
        match = re.search(r"time[=<]([0-9.]+)\s*ms", result.stdout)
        return float(match.group(1)) if match else 0.1
    except (OSError, subprocess.TimeoutExpired):
        return None


def ping_sweep(network: ipaddress.IPv4Network) -> dict[str, float]:
    if not setting("enable_ping_sweep"):
        return {}

    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:
        return {}

    alive: dict[str, float] = {}
    # Limitar la concurrencia evita desbordar la cola ARP del kernel en /24.
    with ThreadPoolExecutor(max_workers=min(setting("ping_workers"), 64, len(hosts))) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in as_completed(futures):
            latency = future.result()
            if latency is not None:
                alive[futures[future]] = latency
    return alive


def arp_scan_sync() -> list[dict[str, Any]]:
    """
    Ejecuta un barrido ARP en la LAN.

    ARP pregunta "quien tiene esta IP" dentro del segmento local. Los equipos que
    responden devuelven su MAC, por eso este metodo es mas fiable que ping para
    descubrir dispositivos conectados en la misma red.
    """
    interface_name, network = active_network()
    networks = scan_networks(network)
    devices: dict[str, dict[str, Any]] = {}

    def merge(item: dict[str, Any]) -> None:
        current = devices.get(item["mac"])
        if current and not item.get("hostname"):
            item["hostname"] = current.get("hostname", "")
        devices[item["mac"]] = item

    local_device = local_interface_device(interface_name)
    if local_device:
        merge(local_device)

    # Conserva vecinos validos antes de que el barrido concurrente cambie su estado.
    for target_network in networks:
        for item in kernel_neighbors(interface_name, target_network):
            merge(item)

    # Varias pasadas cortas suelen detectar mejor camaras, IoT y VMs que
    # responden de forma irregular al broadcast ARP.
    for target_network in networks:
        for _ in range(max(1, setting("arp_passes"))):
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target_network))
            answered, _ = srp(
                packet,
                iface=interface_name,
                timeout=setting("arp_timeout_seconds"),
                retry=setting("arp_retries"),
                verbose=False,
            )

            for _, response in answered:
                mac = response.hwsrc.upper()
                ip = response.psrc
                merge({"mac": mac, "ip": ip, "hostname": resolve_hostname(ip)})

    # Algunos dispositivos no responden bien al broadcast ARP, pero si a ping.
    # El ping no da la MAC directamente; hace que el kernel la aprenda y despues
    # la recogemos desde "ip neigh".
    latency_by_ip: dict[str, float] = {}
    for target_network in networks:
        latency_by_ip.update(ping_sweep(target_network))

    # Complementa el escaneo activo con la tabla ARP del kernel del host.
    for target_network in networks:
        for item in kernel_neighbors(interface_name, target_network):
            merge(item)

    # Si ICMP responde pero el kernel descarta la entrada ARP durante el barrido,
    # reutiliza la relacion IP/MAC previamente confirmada en la base de datos.
    discovered_ips = {item["ip"] for item in devices.values()}
    known_by_ip = known_devices_by_ip()
    for ip in set(latency_by_ip) - discovered_ips:
        if ip in known_by_ip:
            merge(known_by_ip[ip])

    # Muchas redes domesticas no publican DNS inverso. En ese caso conserva el
    # nombre ya confirmado por el usuario para no mostrar una columna vacia.
    for item in devices.values():
        known = known_by_ip.get(item["ip"])
        if not item.get("hostname") and known:
            item["hostname"] = known["hostname"]
        if item["ip"] in latency_by_ip:
            item["latency_ms"] = latency_by_ip[item["ip"]]

    ssdp_names = discover_ssdp() if setting("ssdp_enabled") else {}
    unnamed = [item for item in devices.values() if not item.get("hostname")]
    for item in unnamed:
        item["hostname"] = ssdp_names.get(item["ip"], "")
        if not item["hostname"] and setting("mdns_enabled"):
            item["hostname"] = resolve_mdns(item["ip"])
        if not item["hostname"] and setting("netbios_enabled"):
            item["hostname"] = resolve_netbios(item["ip"])

    return sorted(devices.values(), key=lambda item: sort_key(item["ip"]))


def persist_scan_results(found_devices: list[dict[str, Any]]) -> dict[str, Any]:
    found_macs = {item["mac"] for item in found_devices}
    timestamp = now_utc()
    events: list[dict[str, str]] = []

    with Session(engine) as session:
        existing_devices = session.exec(select(Device)).all()
        existing_by_mac = {device.mac: device for device in existing_devices}

        for item in found_devices:
            device = existing_by_mac.get(item["mac"])
            if device:
                was_offline = device.status == "Offline"
                if device.ip != item["ip"]:
                    session.add(ConnectionEvent(mac=device.mac, event_type="ip_changed", occurred_at=timestamp, ip=item["ip"]))
                device.ip = item["ip"]
                if item["hostname"]:
                    device.hostname = item["hostname"]
                if not device.vendor:
                    device.vendor = lookup_vendor(device.mac)
                if device.device_type == "Otro":
                    device.device_type = infer_device_type(display_name(device), device.vendor)
                device.last_seen = timestamp
                if was_offline or device.connected_since is None:
                    device.connected_since = timestamp
                    session.add(ConnectionEvent(mac=device.mac, event_type="online", occurred_at=timestamp, ip=device.ip))
                device.status = "Online"
                device.missed_scans = 0
                session.add(device)
            else:
                # Solo una MAC nunca vista genera aviso. Las reconexiones no notifican.
                is_local = item.get("local") == "true"
                if not is_local:
                    events.append(
                        {
                            "type": "new",
                            "title": "Nuevo dispositivo desconocido",
                            "message": f"{item['ip']} - {item['mac']} {item['hostname']}".strip(),
                        }
                    )
                device = Device(
                    mac=item["mac"],
                    ip=item["ip"],
                    hostname=item["hostname"],
                    first_seen=timestamp,
                    last_seen=timestamp,
                    status="Online",
                    missed_scans=0,
                    known=is_local,
                    connected_since=timestamp,
                    vendor=lookup_vendor(item["mac"]),
                )
                device.device_type = infer_device_type(display_name(device), device.vendor)
                session.add(device)
                session.add(ConnectionEvent(mac=device.mac, event_type="first_seen", occurred_at=timestamp, ip=device.ip))

            latency = item.get("latency_ms")
            if isinstance(latency, (int, float)):
                device.latency_ms = round(float(latency), 2)
                device.latency_updated_at = timestamp
                session.add(DeviceMetric(mac=device.mac, occurred_at=timestamp, latency_ms=device.latency_ms))
                session.add(device)

        for device in existing_devices:
            if device.mac in found_macs:
                continue
            device.missed_scans += 1
            if device.missed_scans >= setting("offline_after_misses") and device.status != "Offline":
                device.status = "Offline"
                device.connected_since = None
                session.add(ConnectionEvent(mac=device.mac, event_type="offline", occurred_at=timestamp, ip=device.ip))
            session.add(device)

        session.commit()

    return {"found": len(found_devices), "events": events}


def telegram_targets() -> tuple[str, list[str]]:
    if not setting("telegram_enabled") or not setting("telegram_url"):
        return "", []

    parsed = urlsplit(setting("telegram_url"))
    if parsed.scheme != "telegram" or not parsed.username or not parsed.password:
        return "", []

    token = f"{parsed.username}:{parsed.password}"
    channels = parse_qs(parsed.query).get("channels", [])
    targets = [target.strip() for value in channels for target in value.split(",") if target.strip()]
    return token, targets


def send_telegram(message: str) -> None:
    token, targets = telegram_targets()
    if not token or not targets:
        return

    for chat_id in targets:
        payload = f"chat_id={chat_id}&text={message}".encode()
        request = Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            urlopen(request, timeout=10).read()
        except Exception as exc:
            print(f"[alert] telegram failed: {exc}")


def send_email(subject: str, body: str) -> None:
    if not setting("email_enabled") or not setting("smtp_host") or not setting("alert_email_to") or not setting("smtp_from"):
        return

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = setting("smtp_from")
    message["To"] = setting("alert_email_to")
    message.set_content(body)

    try:
        if setting("smtp_tls"):
            with smtplib.SMTP(setting("smtp_host"), setting("smtp_port"), timeout=10) as smtp:
                smtp.starttls(context=ssl.create_default_context())
                if setting("smtp_username") and setting("smtp_password"):
                    smtp.login(setting("smtp_username"), setting("smtp_password"))
                smtp.send_message(message)
        else:
            with smtplib.SMTP_SSL(setting("smtp_host"), setting("smtp_port"), timeout=10) as smtp:
                if setting("smtp_username") and setting("smtp_password"):
                    smtp.login(setting("smtp_username"), setting("smtp_password"))
                smtp.send_message(message)
    except Exception as exc:
        print(f"[alert] email failed: {exc}")


def send_alerts(events: list[dict[str, str]]) -> None:
    for event in events:
        text = f"{APP_NAME}: {event['title']}\n{event['message']}"
        send_telegram(text)
        send_email(event["title"], text)
        if setting("webhook_enabled") and setting("webhook_url"):
            send_webhook(setting("webhook_url"), {**event, "source": APP_NAME, "occurred_at": now_utc().isoformat()})


def send_wol(mac: str) -> None:
    normalized = mac.replace(":", "").replace("-", "").upper()
    if len(normalized) != 12:
        raise ValueError("Invalid MAC address")

    try:
        mac_bytes = bytes.fromhex(normalized)
    except ValueError as exc:
        raise ValueError("Invalid MAC address") from exc

    packet = b"\xff" * 6 + mac_bytes * 16
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, ("255.255.255.255", 9))


async def run_scan() -> dict[str, Any]:
    async with scan_lock:
        last_scan_status.update(
            {
                "running": True,
                "last_started_at": now_utc().isoformat(),
                "last_error": "",
            }
        )
        started = time.monotonic()
        try:
            found_devices = await asyncio.to_thread(arp_scan_sync)
            result = await asyncio.to_thread(persist_scan_results, found_devices)
            await asyncio.to_thread(send_alerts, result["events"])
            duration_ms = int((time.monotonic() - started) * 1000)
            with Session(engine) as session:
                devices = session.exec(select(Device)).all()
                session.add(
                    ScanSnapshot(
                        occurred_at=now_utc(),
                        found=result["found"],
                        online=sum(device.status == "Online" for device in devices),
                        offline=sum(device.status == "Offline" for device in devices),
                        unknown=sum(not device.known for device in devices),
                        duration_ms=duration_ms,
                    )
                )
                session.commit()
            finished_at = now_utc().isoformat()
            last_scan_status.update(
                {
                    "running": False,
                    "last_finished_at": finished_at,
                    "last_duration_ms": duration_ms,
                    "last_found": result["found"],
                    "last_error": "",
                }
            )
            return {
                "found": result["found"],
                "events": result["events"],
                "scanned_at": finished_at,
                "offline_after_misses": setting("offline_after_misses"),
                "duration_ms": duration_ms,
            }
        except Exception as exc:
            last_scan_status.update(
                {
                    "running": False,
                    "last_finished_at": now_utc().isoformat(),
                    "last_error": str(exc),
                }
            )
            raise


async def scanner_loop() -> None:
    while True:
        try:
            await run_scan()
        except Exception as exc:
            print(f"[scanner] scan failed: {exc}")
        await asyncio.sleep(setting("scan_interval_seconds"))


async def backup_loop() -> None:
    while True:
        try:
            if setting("backup_enabled") and DATABASE_PATH.exists():
                await asyncio.to_thread(create_backup, DATABASE_PATH, BACKUP_DIR, setting("backup_retention"))
            cutoff = now_utc() - timedelta(days=setting("metrics_retention_days"))
            with Session(engine) as session:
                for metric in session.exec(select(DeviceMetric).where(DeviceMetric.occurred_at < cutoff)).all():
                    session.delete(metric)
                for snapshot in session.exec(select(ScanSnapshot).where(ScanSnapshot.occurred_at < cutoff)).all():
                    session.delete(snapshot)
                session.commit()
        except Exception as exc:
            print(f"[backup] failed: {exc}")
        await asyncio.sleep(setting("backup_interval_hours") * 3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global scanner_task, backup_task
    init_db()
    load_settings()
    backfill_inventory()
    scanner_task = asyncio.create_task(scanner_loop())
    backup_task = asyncio.create_task(backup_loop())
    try:
        yield
    finally:
        if scanner_task:
            scanner_task.cancel()
            try:
                await scanner_task
            except asyncio.CancelledError:
                pass
        if backup_task:
            backup_task.cancel()
            try:
                await backup_task
            except asyncio.CancelledError:
                pass


app = FastAPI(title=APP_NAME, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def optional_basic_auth(request: FastAPIRequest, call_next):
    if not setting("auth_enabled") or request.url.path in {"/health", "/api/agents/report"}:
        return await call_next(request)

    authorization = request.headers.get("Authorization", "")
    try:
        scheme, encoded = authorization.split(" ", 1)
        username, password = base64.b64decode(encoded).decode().split(":", 1)
        valid = (
            scheme.lower() == "basic"
            and hmac.compare_digest(username, setting("auth_username"))
            and verify_password(password, setting("auth_password_hash"))
        )
    except (ValueError, UnicodeDecodeError):
        valid = False
    if not valid:
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
            headers={"WWW-Authenticate": 'Basic realm="WatchMyLAN"'},
        )
    return await call_next(request)


@app.get("/api/devices")
def list_devices(session: Session = Depends(get_session)) -> list[Device]:
    devices = session.exec(select(Device)).all()
    return sorted(
        devices,
        key=lambda device: (
            0 if device.status == "Online" else 1,
            -device.last_seen.timestamp(),
            device.ip,
        ),
    )


@app.put("/api/devices/{mac}")
def update_device(mac: str, payload: DeviceUpdate, session: Session = Depends(get_session)) -> Device:
    device = session.get(Device, mac.upper())
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    if payload.custom_name is not None:
        device.custom_name = payload.custom_name.strip()
    if payload.notes is not None:
        device.notes = payload.notes.strip()
    if payload.known is not None:
        device.known = payload.known
    if payload.favorite is not None:
        device.favorite = payload.favorite
    if payload.device_type is not None:
        allowed_types = {"Router", "Camara", "Servidor", "Entretenimiento", "Movil", "Ordenador", "IoT", "Otro"}
        if payload.device_type not in allowed_types:
            raise HTTPException(status_code=422, detail="Invalid device type")
        device.device_type = payload.device_type

    session.add(device)
    session.commit()
    session.refresh(device)
    return device


@app.delete("/api/devices/{mac}")
def delete_device(mac: str, session: Session = Depends(get_session)) -> dict[str, str]:
    normalized_mac = mac.upper()
    device = session.get(Device, normalized_mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    events = session.exec(select(ConnectionEvent).where(ConnectionEvent.mac == normalized_mac)).all()
    for event in events:
        session.delete(event)
    session.delete(device)
    session.commit()
    return {"status": "deleted", "mac": normalized_mac}


@app.post("/api/devices/bulk-known")
def bulk_update_known(payload: BulkKnownUpdate, session: Session = Depends(get_session)) -> dict[str, Any]:
    normalized = {mac.upper() for mac in payload.macs if isinstance(mac, str)}
    if not normalized:
        raise HTTPException(status_code=422, detail="No devices selected")

    updated = 0
    for mac in normalized:
        device = session.get(Device, mac)
        if not device:
            continue
        device.known = payload.known
        session.add(device)
        updated += 1
    session.commit()
    return {"status": "updated", "updated": updated, "known": payload.known}


@app.get("/api/devices/{mac}/history")
def device_history(mac: str, session: Session = Depends(get_session)) -> list[ConnectionEvent]:
    normalized_mac = mac.upper()
    if not session.get(Device, normalized_mac):
        raise HTTPException(status_code=404, detail="Device not found")
    statement = (
        select(ConnectionEvent)
        .where(ConnectionEvent.mac == normalized_mac)
        .order_by(ConnectionEvent.occurred_at.desc())
        .limit(250)
    )
    return list(session.exec(statement).all())


@app.post("/api/devices/{mac}/wake")
def wake_device(mac: str, session: Session = Depends(get_session)) -> dict[str, str]:
    normalized_mac = mac.upper()
    device = session.get(Device, normalized_mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    try:
        send_wol(device.mac)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {"status": "sent", "mac": device.mac}


@app.post("/api/scan")
async def trigger_scan() -> dict[str, Any]:
    return await run_scan()


@app.get("/api/scan/status")
def scan_status() -> dict[str, Any]:
    return {**last_scan_status, "scan_interval_seconds": setting("scan_interval_seconds")}


@app.get("/api/config")
def config() -> dict[str, Any]:
    return {
        "scan_interval_seconds": setting("scan_interval_seconds"),
        "offline_after_misses": setting("offline_after_misses"),
        "telegram_enabled": setting("telegram_enabled") and bool(setting("telegram_url")),
        "email_enabled": setting("email_enabled") and bool(setting("smtp_host")),
        "wake_on_lan_enabled": True,
    }


@app.get("/api/settings")
def get_settings() -> dict[str, Any]:
    return public_settings()


@app.put("/api/settings")
def update_settings(payload: SettingsUpdate, session: Session = Depends(get_session)) -> dict[str, Any]:
    values = payload.model_dump(exclude_unset=True)
    password = values.pop("auth_password", None)
    if password:
        values["auth_password_hash"] = hash_password(password)
    if values.get("auth_enabled") and not (values.get("auth_password_hash") or setting("auth_password_hash")):
        raise HTTPException(status_code=422, detail="Set an authentication password first")
    for key, value in values.items():
        # Un secreto vacio significa conservar el valor ya guardado.
        if key in SECRET_SETTINGS and not value:
            continue
        if isinstance(value, str):
            value = value.strip()

        runtime_settings[key] = value
        item = session.get(AppSetting, key) or AppSetting(key=key)
        item.value = str(value).lower() if isinstance(value, bool) else str(value)
        item.updated_at = now_utc()
        session.add(item)

    session.commit()
    return public_settings()


@app.post("/api/alerts/test")
async def test_alerts() -> dict[str, Any]:
    event = {
        "type": "test",
        "title": "Aviso de prueba",
        "message": "La configuracion de avisos funciona correctamente.",
    }
    await asyncio.to_thread(send_alerts, [event])
    return {"status": "sent"}


@app.get("/api/analytics")
def analytics(hours: int = 168, session: Session = Depends(get_session)) -> dict[str, Any]:
    hours = max(1, min(hours, 24 * 365))
    start = now_utc() - timedelta(hours=hours)
    snapshots = sorted(
        session.exec(
            select(ScanSnapshot).where(ScanSnapshot.occurred_at >= start).order_by(ScanSnapshot.occurred_at.desc()).limit(1000)
        ).all(),
        key=lambda item: aware_utc(item.occurred_at),
    )
    devices = session.exec(select(Device)).all()
    uptime: list[dict[str, Any]] = []
    instability: list[dict[str, Any]] = []
    event_buckets: dict[int, dict[str, int]] = {}
    total_disconnects = 0
    total_ip_changes = 0
    total_new_devices = 0
    event_bucket_seconds = max(3600, int(hours * 3600 / 120))

    def percentile(values: list[float], fraction: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
        return round(ordered[index], 2)

    for device in devices:
        events = session.exec(
            select(ConnectionEvent)
            .where(ConnectionEvent.mac == device.mac)
            .order_by(ConnectionEvent.occurred_at.asc())
        ).all()
        monitored_from = max(start, aware_utc(device.first_seen))
        period_seconds = max(1.0, (now_utc() - monitored_from).total_seconds())
        online = False
        cursor = monitored_from
        online_seconds = 0.0
        for event in events:
            occurred = aware_utc(event.occurred_at)
            if occurred <= monitored_from:
                online = event.event_type in {"online", "first_seen"}
                continue
            if online:
                online_seconds += (occurred - cursor).total_seconds()
            online = event.event_type in {"online", "first_seen"}
            cursor = occurred
        if online and device.status == "Online":
            online_seconds += (now_utc() - cursor).total_seconds()
        uptime.append(
            {
                "mac": device.mac,
                "name": display_name(device),
                "uptime_percent": round(max(0, min(100, online_seconds / period_seconds * 100)), 1),
                "latency_ms": device.latency_ms,
                "status": device.status,
            }
        )
        recent_events = [event for event in events if aware_utc(event.occurred_at) >= start]
        disconnects = sum(event.event_type == "offline" for event in recent_events)
        ip_changes = sum(event.event_type == "ip_changed" for event in recent_events)
        new_devices = sum(event.event_type == "first_seen" for event in recent_events)
        total_disconnects += disconnects
        total_ip_changes += ip_changes
        total_new_devices += new_devices
        if disconnects or ip_changes:
            instability.append({"mac": device.mac, "name": display_name(device), "disconnects": disconnects, "ip_changes": ip_changes})

        for event in recent_events:
            bucket = int(aware_utc(event.occurred_at).timestamp() // event_bucket_seconds * event_bucket_seconds)
            counts = event_buckets.setdefault(bucket, {"new_devices": 0, "disconnects": 0, "ip_changes": 0})
            if event.event_type == "first_seen":
                counts["new_devices"] += 1
            elif event.event_type == "offline":
                counts["disconnects"] += 1
            elif event.event_type == "ip_changed":
                counts["ip_changes"] += 1

    metrics = session.exec(
        select(DeviceMetric)
        .where(DeviceMetric.occurred_at >= start)
        .order_by(DeviceMetric.occurred_at.desc())
        .limit(10000)
    ).all()
    bucket_seconds = max(60, int(hours * 3600 / 240))
    buckets: dict[int, list[float]] = {}
    metrics_by_mac: dict[str, list[float]] = {}
    for metric in metrics:
        bucket = int(aware_utc(metric.occurred_at).timestamp() // bucket_seconds * bucket_seconds)
        buckets.setdefault(bucket, []).append(metric.latency_ms)
        metrics_by_mac.setdefault(metric.mac, []).append(metric.latency_ms)
    latency_series = []
    for bucket, values in sorted(buckets.items()):
        ordered = sorted(values)
        latency_series.append(
            {
                "occurred_at": datetime.fromtimestamp(bucket, timezone.utc),
                "average_ms": round(sum(values) / len(values), 2),
                "p95_ms": percentile(ordered, 0.95),
            }
        )

    device_lookup = {device.mac: device for device in devices}
    slowest_devices = []
    for mac, values in metrics_by_mac.items():
        device = device_lookup.get(mac)
        if not device:
            continue
        slowest_devices.append(
            {
                "mac": mac,
                "name": display_name(device),
                "status": device.status,
                "average_ms": round(statistics.fmean(values), 2),
                "p95_ms": percentile(values, 0.95),
                "maximum_ms": round(max(values), 2),
                "samples": len(values),
            }
        )
    slowest_devices.sort(key=lambda item: item["average_ms"], reverse=True)

    first_event_bucket = int(start.timestamp() // event_bucket_seconds * event_bucket_seconds)
    last_event_bucket = int(now_utc().timestamp() // event_bucket_seconds * event_bucket_seconds)
    event_series = []
    for bucket in range(first_event_bucket, last_event_bucket + 1, event_bucket_seconds):
        counts = event_buckets.get(bucket, {"new_devices": 0, "disconnects": 0, "ip_changes": 0})
        event_series.append({"occurred_at": datetime.fromtimestamp(bucket, timezone.utc), **counts})

    device_types: dict[str, int] = {}
    for device in devices:
        device_type = device.device_type or "Otro"
        device_types[device_type] = device_types.get(device_type, 0) + 1
    type_distribution = [
        {"type": device_type, "count": count, "percent": round(count / max(1, len(devices)) * 100, 1)}
        for device_type, count in sorted(device_types.items(), key=lambda item: item[1], reverse=True)
    ]

    current_latencies = sorted(
        device.latency_ms for device in devices if device.status == "Online" and device.latency_ms is not None
    )
    average_latency = round(sum(current_latencies) / len(current_latencies), 2) if current_latencies else None
    p95_latency = percentile(current_latencies, 0.95)
    period_latencies = [metric.latency_ms for metric in metrics]
    period_average_latency = round(statistics.fmean(period_latencies), 2) if period_latencies else None
    period_median_latency = round(statistics.median(period_latencies), 2) if period_latencies else None
    period_p95_latency = percentile(period_latencies, 0.95)
    latency_jitter = round(statistics.pstdev(period_latencies), 2) if len(period_latencies) > 1 else (0.0 if period_latencies else None)
    average_scan_ms = round(sum(item.duration_ms for item in snapshots) / len(snapshots)) if snapshots else None
    p95_scan_ms = percentile([float(item.duration_ms) for item in snapshots], 0.95)
    availability_values = [item.online / max(1, item.online + item.offline) * 100 for item in snapshots]
    peak_snapshot = max(snapshots, key=lambda item: item.online, default=None)
    minimum_snapshot = min(snapshots, key=lambda item: item.online, default=None)
    online_now = sum(device.status == "Online" for device in devices)
    known_devices = sum(device.known for device in devices)

    return {
        "hours": hours,
        "snapshots": snapshots,
        "uptime": sorted(uptime, key=lambda item: item["uptime_percent"], reverse=True),
        "latency_series": latency_series,
        "event_series": event_series,
        "slowest_devices": slowest_devices[:20],
        "device_types": type_distribution,
        "instability": sorted(instability, key=lambda item: (item["disconnects"], item["ip_changes"]), reverse=True),
        "summary": {
            "total_devices": len(devices),
            "online_now": online_now,
            "offline_now": len(devices) - online_now,
            "unknown_now": len(devices) - known_devices,
            "known_percent": round(known_devices / max(1, len(devices)) * 100, 1),
            "average_latency_ms": average_latency,
            "p95_latency_ms": p95_latency,
            "fastest_latency_ms": current_latencies[0] if current_latencies else None,
            "slowest_latency_ms": current_latencies[-1] if current_latencies else None,
            "period_average_latency_ms": period_average_latency,
            "period_median_latency_ms": period_median_latency,
            "period_p95_latency_ms": period_p95_latency,
            "latency_jitter_ms": latency_jitter,
            "average_scan_ms": average_scan_ms,
            "p95_scan_ms": p95_scan_ms,
            "scan_count": len(snapshots),
            "peak_online": peak_snapshot.online if peak_snapshot else None,
            "peak_online_at": peak_snapshot.occurred_at if peak_snapshot else None,
            "minimum_online": minimum_snapshot.online if minimum_snapshot else None,
            "new_devices": total_new_devices,
            "disconnects": total_disconnects,
            "ip_changes": total_ip_changes,
            "network_availability_percent": round(sum(availability_values) / len(availability_values), 1) if availability_values else None,
            "latency_samples": len(metrics),
        },
    }


@app.post("/api/devices/{mac}/services")
async def discover_services(mac: str, session: Session = Depends(get_session)) -> dict[str, Any]:
    if not setting("port_scan_enabled"):
        raise HTTPException(status_code=403, detail="Port scanning is disabled in settings")
    device = session.get(Device, mac.upper())
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        ports = parse_ports(setting("port_scan_ports"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid port list") from exc
    services = await scan_ports(device.ip, ports)
    device.open_ports = json.dumps(services)
    device.services_updated_at = now_utc()
    session.add(device)
    session.commit()
    return {"ip": device.ip, "services": services, "scanned_at": device.services_updated_at}


@app.get("/api/backups")
def list_backups() -> list[dict[str, Any]]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return [
        {"name": item.name, "size": item.stat().st_size, "created_at": datetime.fromtimestamp(item.stat().st_mtime, timezone.utc)}
        for item in sorted(BACKUP_DIR.glob("watchmylan-*.db"), reverse=True)
    ]


@app.post("/api/backups")
async def make_backup() -> dict[str, Any]:
    path = await asyncio.to_thread(create_backup, DATABASE_PATH, BACKUP_DIR, setting("backup_retention"))
    return {"name": path.name, "size": path.stat().st_size}


@app.get("/api/backups/{name}")
def download_backup(name: str) -> FileResponse:
    if Path(name).name != name or not name.startswith("watchmylan-") or not name.endswith(".db"):
        raise HTTPException(status_code=400, detail="Invalid backup name")
    path = BACKUP_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail="Backup not found")
    return FileResponse(path, filename=name, media_type="application/vnd.sqlite3")


@app.get("/api/agents")
def list_agents(session: Session = Depends(get_session)) -> list[dict[str, Any]]:
    return [
        {"id": agent.id, "name": agent.name, "subnet": agent.subnet, "enabled": agent.enabled, "last_seen": agent.last_seen}
        for agent in session.exec(select(Agent)).all()
    ]


@app.post("/api/agents")
def create_agent(payload: AgentCreate, session: Session = Depends(get_session)) -> dict[str, Any]:
    token = secrets.token_urlsafe(32)
    agent = Agent(name=payload.name.strip(), subnet=payload.subnet.strip(), token=token)
    session.add(agent)
    session.commit()
    session.refresh(agent)
    return {"id": agent.id, "name": agent.name, "subnet": agent.subnet, "token": token}


@app.delete("/api/agents/{agent_id}")
def delete_agent(agent_id: int, session: Session = Depends(get_session)) -> dict[str, str]:
    agent = session.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    session.delete(agent)
    session.commit()
    return {"status": "deleted"}


@app.post("/api/agents/report")
async def agent_report(payload: AgentReport, request: FastAPIRequest, session: Session = Depends(get_session)) -> dict[str, Any]:
    token = request.headers.get("X-Agent-Token", "")
    agent = session.exec(select(Agent).where(Agent.token == token, Agent.enabled == True)).first()  # noqa: E712
    if not agent:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    agent.last_seen = now_utc()
    session.add(agent)
    session.commit()

    events: list[dict[str, str]] = []
    timestamp = now_utc()
    for item in payload.devices:
        mac = item.get("mac", "").upper()
        ip = item.get("ip", "")
        if len(mac) != 17 or not ip:
            continue
        device = session.get(Device, mac)
        if device is None:
            device = Device(mac=mac, ip=ip, hostname=item.get("hostname", ""), connected_since=timestamp, vendor=lookup_vendor(mac))
            events.append({"type": "new", "title": "Nuevo dispositivo desconocido", "message": f"{ip} - {mac}"})
            session.add(ConnectionEvent(mac=mac, event_type="first_seen", occurred_at=timestamp, ip=ip))
        device.ip = ip
        device.hostname = item.get("hostname") or device.hostname
        device.last_seen = timestamp
        device.status = "Online"
        device.missed_scans = 0
        session.add(device)
    session.commit()
    await asyncio.to_thread(send_alerts, events)
    return {"accepted": len(payload.devices), "events": len(events)}
    await asyncio.to_thread(send_alerts, [event])
    return {
        "status": "sent",
        "telegram_enabled": setting("telegram_enabled") and bool(setting("telegram_url")),
        "email_enabled": setting("email_enabled") and bool(setting("smtp_host")),
    }


@app.get("/api/devices.csv")
def export_devices(session: Session = Depends(get_session)) -> StreamingResponse:
    devices = list_devices(session)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["status", "known", "favorite", "type", "vendor", "ip", "mac", "hostname", "custom_name", "notes", "latency_ms", "first_seen", "last_seen", "connected_since", "open_ports"])
    for device in devices:
        writer.writerow(
            [
                device.status,
                device.known,
                device.favorite,
                device.device_type,
                device.vendor,
                device.ip,
                device.mac,
                device.hostname,
                device.custom_name,
                device.notes,
                device.latency_ms,
                device.first_seen.isoformat(),
                device.last_seen.isoformat(),
                device.connected_since.isoformat() if device.connected_since else "",
                device.open_ports,
            ]
        )
    buffer.seek(0)
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=devices.csv"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
