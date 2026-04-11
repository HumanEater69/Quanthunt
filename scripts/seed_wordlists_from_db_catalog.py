from __future__ import annotations

import argparse
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path


def normalize_domain(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def tokenize_host(host: str) -> set[str]:
    host_l = normalize_domain(host)
    if not host_l or "." not in host_l:
        return set()

    labels = host_l.split(".")
    left = labels[0]
    out: set[str] = set()

    if left:
        out.add(left)

    for label in labels[:-1]:
        for token in re.split(r"[^a-z0-9]+", label):
            token = token.strip().lower()
            if 2 <= len(token) <= 40:
                out.add(token)

    return out


def load_hosts_from_db(db_path: Path) -> list[str]:
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    hosts: list[str] = []

    try:
        rows = cur.execute("SELECT hostname FROM assets WHERE hostname IS NOT NULL AND hostname != ''").fetchall()
        hosts.extend(str(r[0]) for r in rows if r and r[0])
    except Exception:
        pass

    try:
        rows = cur.execute("SELECT domain FROM scans WHERE domain IS NOT NULL AND domain != ''").fetchall()
        hosts.extend(str(r[0]) for r in rows if r and r[0])
    except Exception:
        pass

    conn.close()
    return hosts


def append_tokens(wordlist_path: Path, tokens: list[str]) -> int:
    existing: set[str] = set()
    if wordlist_path.exists():
        for line in wordlist_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip().lower()
            if line and not line.startswith("#"):
                existing.add(line)

    new_tokens = [t for t in tokens if t not in existing]
    if not new_tokens:
        return 0

    stamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    with wordlist_path.open("a", encoding="utf-8") as f:
        f.write("\n# Seeded from private DB catalog at " + stamp + "\n")
        for token in new_tokens:
            f.write(token + "\n")
    return len(new_tokens)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed scanner wordlists from private SQLite host catalog.")
    parser.add_argument("--db", required=True, help="Path to SQLite DB or backup.")
    parser.add_argument("--target-wordlist", required=True, help="Path to target domain wordlist.")
    parser.add_argument("--parent-wordlist", required=True, help="Path to parent domain wordlist.")
    parser.add_argument("--min-frequency", type=int, default=1, help="Minimum token frequency to keep.")
    parser.add_argument("--max-tokens", type=int, default=5000, help="Maximum tokens to append per wordlist.")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists() or not db_path.is_file():
        raise SystemExit(f"DB file not found: {db_path}")

    hosts = load_hosts_from_db(db_path)
    freq: Counter[str] = Counter()
    for host in hosts:
        for token in tokenize_host(host):
            freq[token] += 1

    filtered = [
        token
        for token, count in freq.most_common()
        if count >= max(1, int(args.min_frequency)) and 2 <= len(token) <= 40
    ]
    filtered = filtered[: max(1, int(args.max_tokens))]

    target_added = append_tokens(Path(args.target_wordlist), filtered)
    parent_added = append_tokens(Path(args.parent_wordlist), filtered)

    print(f"hosts={len(hosts)} unique_tokens={len(freq)} selected_tokens={len(filtered)}")
    print(f"target_added={target_added}")
    print(f"parent_added={parent_added}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
