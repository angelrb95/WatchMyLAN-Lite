from __future__ import annotations

import json
import os
import socket
import time
from urllib.request import Request, urlopen

from scapy.all import ARP, Ether, get_if_addr, srp  # type: ignore


SERVER_URL = os.environ["WATCHMYLAN_SERVER"].rstrip("/")
AGENT_TOKEN = os.environ["WATCHMYLAN_AGENT_TOKEN"]
SUBNET = os.getenv("WATCHMYLAN_SUBNET", "192.168.1.0/24")
INTERFACE = os.getenv("WATCHMYLAN_INTERFACE", "eth0")
INTERVAL = int(os.getenv("WATCHMYLAN_INTERVAL", "120"))


def scan() -> list[dict[str, str]]:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=SUBNET)
    answered, _ = srp(packet, iface=INTERFACE, timeout=2, retry=1, verbose=False)
    devices = []
    for _, response in answered:
        try:
            hostname = socket.gethostbyaddr(response.psrc)[0]
        except OSError:
            hostname = ""
        devices.append({"mac": response.hwsrc.upper(), "ip": response.psrc, "hostname": hostname})
    return devices


def report(devices: list[dict[str, str]]) -> None:
    request = Request(
        f"{SERVER_URL}/api/agents/report",
        data=json.dumps({"devices": devices}).encode(),
        headers={"Content-Type": "application/json", "X-Agent-Token": AGENT_TOKEN},
        method="POST",
    )
    urlopen(request, timeout=30).read()


if __name__ == "__main__":
    print(f"Agent monitoring {SUBNET} through {INTERFACE}")
    while True:
        try:
            report(scan())
        except Exception as exc:
            print(f"Agent report failed: {exc}")
        time.sleep(INTERVAL)
