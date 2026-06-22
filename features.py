from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from manuf import manuf


COMMON_SERVICES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    554: "RTSP", 631: "IPP", 1883: "MQTT", 3000: "Web",
    5000: "Web", 5353: "mDNS", 8000: "Web", 8080: "HTTP alt",
    8123: "Home Assistant", 8443: "HTTPS alt", 9000: "Web", 32400: "Plex",
}
_vendor_parser = manuf.MacParser(update=False)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def lookup_vendor(mac: str) -> str:
    try:
        return _vendor_parser.get_manuf_long(mac) or _vendor_parser.get_manuf(mac) or ""
    except Exception:
        return ""


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_text, digest_text = encoded.split("$", 2)
        if algorithm != "scrypt":
            return False
        salt = base64.b64decode(salt_text)
        expected = base64.b64decode(digest_text)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def resolve_mdns(ip: str) -> str:
    try:
        result = subprocess.run(
            ["avahi-resolve-address", ip], capture_output=True, text=True, timeout=2, check=False
        )
        if result.returncode == 0 and "\t" in result.stdout:
            return result.stdout.strip().split("\t", 1)[1].removesuffix(".local")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def resolve_netbios(ip: str) -> str:
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip], capture_output=True, text=True, timeout=3, check=False
        )
        for line in result.stdout.splitlines():
            if "<00>" in line and "GROUP" not in line:
                return line.strip().split()[0]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def discover_ssdp(timeout: float = 1.5) -> dict[str, str]:
    message = (
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    ).encode()
    found: dict[str, str] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.settimeout(timeout)
            sock.sendto(message, ("239.255.255.250", 1900))
            while True:
                try:
                    data, address = sock.recvfrom(65535)
                except socket.timeout:
                    break
                headers = data.decode(errors="ignore")
                server = next(
                    (line.split(":", 1)[1].strip() for line in headers.splitlines() if line.lower().startswith("server:")),
                    "SSDP",
                )
                found[address[0]] = server[:120]
    except OSError:
        pass
    return found


async def scan_ports(ip: str, ports: list[int], timeout: float = 0.4) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(64)

    async def probe(port: int) -> dict[str, Any] | None:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return {"port": port, "service": COMMON_SERVICES.get(port, "TCP")}
            except (OSError, asyncio.TimeoutError):
                return None

    results = await asyncio.gather(*(probe(port) for port in sorted(set(ports))))
    return [item for item in results if item is not None]


def send_webhook(url: str, event: dict[str, Any]) -> bool:
    if not url:
        return False
    request = Request(
        url,
        data=json.dumps(event).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "WatchMyLAN-Lite"},
        method="POST",
    )
    try:
        urlopen(request, timeout=10).read()
        return True
    except Exception as exc:
        print(f"[webhook] failed: {exc}")
        return False


def create_backup(database_path: Path, backup_dir: Path, retention: int) -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    destination = backup_dir / f"watchmylan-{utc_now().strftime('%Y%m%d-%H%M%S')}.db"
    with sqlite3.connect(database_path) as source, sqlite3.connect(destination) as target:
        source.backup(target)
    backups = sorted(backup_dir.glob("watchmylan-*.db"), reverse=True)
    for old_backup in backups[max(1, retention):]:
        old_backup.unlink(missing_ok=True)
    return destination


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(item) for item in part.split("-", 1))
            ports.update(range(max(1, start), min(65535, end) + 1))
        else:
            ports.add(int(part))
    return sorted(port for port in ports if 1 <= port <= 65535)[:1024]
