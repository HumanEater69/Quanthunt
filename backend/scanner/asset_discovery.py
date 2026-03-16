from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request


COMMON_SUBDOMAINS = [
    "api",
    "www",
    "mail",
    "vpn",
    "admin",
    "mobile",
    "gateway",
    "netbanking",
    "uat",
    "dev",
]


def discover_from_crtsh(domain: str, timeout: float = 8.0) -> set[str]:
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "QuantumShield/1.0"})
    assets: set[str] = set()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
    for row in data:
        value = str(row.get("name_value", "")).strip().lower()
        for part in value.splitlines():
            part = part.replace("*.", "").strip()
            if part and part.endswith(domain):
                assets.add(part)
    return assets


def discover_from_dns_bruteforce(domain: str) -> set[str]:
    assets: set[str] = set()
    for prefix in COMMON_SUBDOMAINS:
        host = f"{prefix}.{domain}".lower()
        try:
            socket.gethostbyname(host)
            assets.add(host)
        except OSError:
            continue
    return assets


def discover_assets(domain: str) -> list[str]:
    assets: set[str] = {domain.lower()}
    try:
        assets.update(discover_from_crtsh(domain))
    except Exception:
        pass
    assets.update(discover_from_dns_bruteforce(domain))
    return sorted(assets)

