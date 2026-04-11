from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def normalize_domain(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def belongs_to_domain(host: str, domain: str) -> bool:
    h = normalize_domain(host)
    d = normalize_domain(domain)
    return h == d or h.endswith(f".{d}")


def extract_hosts_from_text(text: str, domain: str) -> set[str]:
    hosts: set[str] = set()
    if not text:
        return hosts
    pattern = re.compile(r"(?:[a-z0-9_-]+\.)+" + re.escape(domain), re.IGNORECASE)
    for match in pattern.findall(text):
        host = normalize_domain(match)
        if host and belongs_to_domain(host, domain):
            hosts.add(host)
    return hosts


def load_inventory_hosts(path: Path, domain: str) -> set[str]:
    ext = path.suffix.lower()
    raw = path.read_text(encoding="utf-8", errors="ignore")
    hosts: set[str] = set()

    if ext == ".json":
        try:
            payload = json.loads(raw)
            raw = json.dumps(payload)
        except Exception:
            pass
        hosts.update(extract_hosts_from_text(raw, domain))
        return hosts

    if ext == ".csv":
        try:
            with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    for value in row.values():
                        text = str(value or "")
                        hosts.update(extract_hosts_from_text(text, domain))
            return hosts
        except Exception:
            pass

    hosts.update(extract_hosts_from_text(raw, domain))
    return hosts


def hosts_to_tokens(hosts: set[str], domain: str) -> set[str]:
    out: set[str] = set()
    for host in hosts:
        h = normalize_domain(host)
        if h == domain or not belongs_to_domain(h, domain):
            continue
        left = h[: -(len(domain) + 1)]
        first = left.split(".", 1)[0].strip().lower()
        if first:
            out.add(first)
        for token in re.split(r"[^a-z0-9]+", first):
            token = token.strip().lower()
            if len(token) >= 2:
                out.add(token)
    return out


def append_tokens(wordlist_path: Path, tokens: set[str]) -> int:
    existing: set[str] = set()
    if wordlist_path.exists():
        for line in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                existing.add(line)
    new_tokens = sorted(t for t in tokens if t not in existing)
    if not new_tokens:
        return 0
    content = "\n".join(new_tokens) + "\n"
    with wordlist_path.open("a", encoding="utf-8") as f:
        f.write("\n# Imported inventory tokens\n")
        f.write(content)
    return len(new_tokens)


def main() -> int:
    parser = argparse.ArgumentParser(description="Import internal subdomain inventory tokens into scanner wordlists.")
    parser.add_argument("--inventory", required=True, help="Path to inventory export file (json/csv/txt).")
    parser.add_argument("--domain", required=True, help="Target base domain, e.g. manipurral.bank.in")
    parser.add_argument("--target-wordlist", required=True, help="Target-specific wordlist file path.")
    parser.add_argument("--parent-wordlist", required=True, help="Parent-domain wordlist file path.")
    args = parser.parse_args()

    inventory_path = Path(args.inventory)
    if not inventory_path.exists() or not inventory_path.is_file():
        raise SystemExit(f"Inventory file not found: {inventory_path}")

    domain = normalize_domain(args.domain)
    hosts = load_inventory_hosts(inventory_path, domain)
    tokens = hosts_to_tokens(hosts, domain)
    if not tokens:
        print("No matching domain tokens found in inventory export.")
        return 0

    target_added = append_tokens(Path(args.target_wordlist), tokens)
    parent_added = append_tokens(Path(args.parent_wordlist), tokens)

    print(f"hosts_found={len(hosts)} tokens={len(tokens)}")
    print(f"target_added={target_added}")
    print(f"parent_added={parent_added}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
