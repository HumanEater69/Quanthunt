from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, select

from .crud import (
    append_chain_block,
    assemble_scan_payload,
    create_scan as create_scan_record,
    findings_payload,
    leaderboard_payload,
    scan_detail_payload,
    scans_list_payload,
)
from .db import engine, get_session
from .models import BatchScanRequest, OmegaChatRequest, PdfGenerateRequest, ScanRequest
from .reporting import build_quantum_certificate, build_scan_pdf, readiness_label
from .scanner import run_scan_pipeline
from .tasks import run_scan_task
from .tables import Asset, Base, CbomExport, ChainBlock, Scan


def _cors_origins_from_env() -> list[str]:
    default_origins = ["http://127.0.0.1:8000", "http://localhost:8000"]
    raw = os.getenv("CORS_ALLOW_ORIGINS", ",".join(default_origins)).strip()
    allow_insecure = os.getenv("ALLOW_INSECURE_CORS", "false").lower() == "true"
    if raw == "*" and allow_insecure:
        return ["*"]
    origins = [o.strip() for o in raw.split(",") if o.strip() and o.strip() != "*"]
    return origins or default_origins

app = FastAPI(title="Quanthunt API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins_from_env(),
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
USE_CELERY = os.getenv("USE_CELERY", "false").lower() == "true"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
REUSE_COMPLETED_SCANS = os.getenv("REUSE_COMPLETED_SCANS", "false").lower() == "true"
VPN_BLOCK_ENABLED = os.getenv("VPN_BLOCK_ENABLED", "true").lower() == "true"
VPN_BLOCK_ON_PROXY = os.getenv("VPN_BLOCK_ON_PROXY", "true").lower() == "true"
VPN_BLOCK_ON_HOSTING = os.getenv("VPN_BLOCK_ON_HOSTING", "true").lower() == "true"
VPN_CHECK_TIMEOUT_SEC = float(os.getenv("VPN_CHECK_TIMEOUT_SEC", "2.5"))
VPN_CACHE_TTL_SEC = float(os.getenv("VPN_CACHE_TTL_SEC", "300"))
VPN_GEO_ENDPOINT = os.getenv("VPN_GEO_ENDPOINT", "http://ip-api.com/json")
VPN_TRUST_X_FORWARDED_FOR = os.getenv("VPN_TRUST_X_FORWARDED_FOR", "true").lower() == "true"
VPN_SCORE_THRESHOLD = int(os.getenv("VPN_SCORE_THRESHOLD", "70"))
VPN_TLD_BLOCKLIST = {
    t.strip().lower().lstrip(".")
    for t in os.getenv("VPN_TLD_BLOCKLIST", "vpn,proxy").split(",")
    if t.strip()
}
VPN_REVERSE_KEYWORDS = {
    t.strip().lower()
    for t in os.getenv(
        "VPN_REVERSE_KEYWORDS",
        "vpn,proxy,tunnel,wireguard,openvpn,nord,surfshark,expressvpn,mullvad,proton",
    ).split(",")
    if t.strip()
}
VPN_NETWORK_KEYWORDS = {
    t.strip().lower()
    for t in os.getenv(
        "VPN_NETWORK_KEYWORDS",
        "vpn,proxy,anonymous,datacenter,colo,hosting,m247,ovh,choopa,vultr,digitalocean,linode,hetzner,leaseweb",
    ).split(",")
    if t.strip()
}
_VPN_CACHE: dict[str, tuple[float, bool, str]] = {}


def _normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d


def _is_valid_scan_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def _latest_reusable_scan(session, domain: str) -> Scan | None:
    completed = session.execute(
        select(Scan)
        .where(Scan.domain == domain, Scan.status == "completed")
        .order_by(desc(Scan.completed_at), desc(Scan.created_at))
    ).scalars().first()
    if completed:
        return completed
    in_flight = session.execute(
        select(Scan)
        .where(Scan.domain == domain, Scan.status.in_(["running", "queued"]))
        .order_by(desc(Scan.created_at))
    ).scalars().first()
    if in_flight:
        return in_flight
    return None


def _extract_tld(hostname: str | None) -> str:
    host = str(hostname or "").strip().strip(".").lower()
    if not host or "." not in host:
        return ""
    return host.rsplit(".", 1)[-1]


def _vpn_block_reasons(proxy: bool, hosting: bool, reverse_host: str | None) -> list[str]:
    reasons: list[str] = []
    if VPN_BLOCK_ON_PROXY and proxy:
        reasons.append("proxy/vpn network")
    if VPN_BLOCK_ON_HOSTING and hosting:
        reasons.append("hosting relay network")
    reverse_tld = _extract_tld(reverse_host)
    if reverse_tld and reverse_tld in VPN_TLD_BLOCKLIST:
        reasons.append(f"reverse DNS TLD .{reverse_tld}")
    return reasons


def _contains_keyword(text: str | None, keywords: set[str]) -> str:
    value = (text or "").strip().lower()
    if not value:
        return ""
    for kw in keywords:
        if kw in value:
            return kw
    return ""


def _vpn_signal_score(data: dict) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    proxy = bool(data.get("proxy"))
    hosting = bool(data.get("hosting"))
    mobile = bool(data.get("mobile"))
    reverse_host = str(data.get("reverse") or "").strip().lower()

    if proxy:
        score += 90
        reasons.append("provider flagged proxy/vpn")
    if hosting:
        score += 80
        reasons.append("provider flagged hosting/datacenter")
    if mobile:
        score -= 20

    reverse_tld = _extract_tld(reverse_host)
    if reverse_tld and reverse_tld in VPN_TLD_BLOCKLIST:
        score += 35
        reasons.append(f"reverse DNS uses blocked TLD .{reverse_tld}")

    reverse_kw = _contains_keyword(reverse_host, VPN_REVERSE_KEYWORDS)
    if reverse_kw:
        score += 35
        reasons.append(f"reverse DNS contains '{reverse_kw}'")

    asn_text = " ".join(
        [
            str(data.get("as") or ""),
            str(data.get("asname") or ""),
            str(data.get("org") or ""),
            str(data.get("isp") or ""),
        ]
    ).strip()
    network_kw = _contains_keyword(asn_text, VPN_NETWORK_KEYWORDS)
    if network_kw:
        score += 30
        reasons.append(f"network signature contains '{network_kw}'")

    score = max(0, min(score, 100))
    return score, reasons


def _client_ip_from_request(request: Request) -> str:
    if VPN_TRUST_X_FORWARDED_FOR:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            first = xff.split(",", 1)[0].strip()
            if first:
                return first
    return (request.client.host if request.client else "").strip()


def _is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (obj.is_private or obj.is_loopback or obj.is_reserved or obj.is_link_local or obj.is_multicast)


async def _check_vpn_block(ip: str) -> tuple[bool, str]:
    now = time.monotonic()
    cached = _VPN_CACHE.get(ip)
    if cached and now < cached[0]:
        return cached[1], cached[2]

    blocked = False
    reason = ""
    try:
        url = f"{VPN_GEO_ENDPOINT.rstrip('/')}/{ip}"
        params = {"fields": "status,message,query,proxy,hosting,mobile,reverse,as,asname,org,isp"}
        timeout = httpx.Timeout(VPN_CHECK_TIMEOUT_SEC)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(url, params=params)
            if resp.is_success:
                data = resp.json()
                reasons = _vpn_block_reasons(
                    bool(data.get("proxy")),
                    bool(data.get("hosting")),
                    data.get("reverse"),
                )
                score, score_reasons = _vpn_signal_score(data)
                all_reasons = list(dict.fromkeys([*reasons, *score_reasons]))
                blocked = bool(reasons) or score >= VPN_SCORE_THRESHOLD
                reason = ", ".join(all_reasons) if blocked else ""
    except Exception:
        blocked = False
        reason = ""

    _VPN_CACHE[ip] = (now + VPN_CACHE_TTL_SEC, blocked, reason)
    return blocked, reason


def _sync_asset_labels_for_scan(session, scan_id: str) -> list[Asset]:
    assets = session.execute(select(Asset).where(Asset.scan_id == scan_id)).scalars().all()
    for asset in assets:
        expected = readiness_label(float(asset.risk_score or 0))
        if asset.label != expected:
            asset.label = expected
    return assets


def _ensure_chain_block_for_completed_scan(session, scan: Scan) -> None:
    if scan.status != "completed":
        return
    assets = _sync_asset_labels_for_scan(session, scan.scan_id)
    existing = session.execute(select(ChainBlock.id).where(ChainBlock.scan_id == scan.scan_id)).first()
    if existing:
        return
    avg_risk = round(sum(a.risk_score for a in assets) / max(len(assets), 1), 2)
    labels = sorted({a.label for a in assets if a.label})
    cbom = session.execute(
        select(CbomExport).where(CbomExport.scan_id == scan.scan_id).order_by(desc(CbomExport.id))
    ).scalars().first()
    append_chain_block(
        session,
        scan.scan_id,
        payload={
            "scan_id": scan.scan_id,
            "domain": scan.domain,
            "assets": len(assets),
            "avg_hndl_risk": avg_risk,
            "labels": labels,
            "cbom_components": len((cbom.cbom_json if cbom else {}).get("components", [])),
            "backfilled": True,
        },
        difficulty=2,
    )


def _backfill_completed_scans(session) -> None:
    completed = session.execute(select(Scan).where(Scan.status == "completed")).scalars().all()
    for scan in completed:
        _ensure_chain_block_for_completed_scan(session, scan)


def _verify_chain_integrity(session) -> dict:
    blocks = session.execute(
        select(ChainBlock).order_by(ChainBlock.block_index.asc(), ChainBlock.id.asc())
    ).scalars().all()
    if not blocks:
        return {
            "chain_type": "tamper-evident hash chain",
            "valid": True,
            "block_count": 0,
            "issues": [],
            "message": "No chain blocks found.",
        }

    issues: list[dict] = []
    expected_prev_hash = "0" * 64
    previous_index = 0
    for b in blocks:
        if b.block_index <= previous_index:
            issues.append(
                {
                    "type": "index_order",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "expected_gt": previous_index,
                }
            )
        if b.prev_hash != expected_prev_hash:
            issues.append(
                {
                    "type": "prev_hash_mismatch",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "expected_prev_hash": expected_prev_hash,
                    "actual_prev_hash": b.prev_hash,
                }
            )
        seed = f"{b.block_index}|{b.scan_id}|{b.payload_hash}|{b.prev_hash}|{b.difficulty}"
        computed = hashlib.sha256(f"{seed}|{b.nonce}".encode("utf-8")).hexdigest()
        if computed != b.block_hash:
            issues.append(
                {
                    "type": "block_hash_mismatch",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "expected_hash": computed,
                    "actual_hash": b.block_hash,
                }
            )
        prefix = "0" * max(1, int(b.difficulty or 0))
        if not str(b.block_hash or "").startswith(prefix):
            issues.append(
                {
                    "type": "difficulty_mismatch",
                    "scan_id": b.scan_id,
                    "block_index": b.block_index,
                    "difficulty": b.difficulty,
                }
            )
        expected_prev_hash = b.block_hash
        previous_index = b.block_index

    return {
        "chain_type": "tamper-evident hash chain",
        "valid": len(issues) == 0,
        "block_count": len(blocks),
        "head_block_index": blocks[-1].block_index,
        "head_hash": blocks[-1].block_hash,
        "issues": issues,
    }


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    with get_session() as session:
        _backfill_completed_scans(session)


@app.middleware("http")
async def vpn_access_guard(request: Request, call_next):
    if not VPN_BLOCK_ENABLED:
        return await call_next(request)

    ip = _client_ip_from_request(request)
    if not ip or not _is_public_ip(ip):
        return await call_next(request)

    blocked, reason = await _check_vpn_block(ip)
    if not blocked:
        return await call_next(request)

    detail = "Access blocked: disable VPN/Proxy and retry."
    if reason:
        detail = f"Access blocked: disable VPN/Proxy and retry ({reason})."

    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=403, content={"detail": detail, "code": "VPN_BLOCKED"})

    html = (
        "<html><head><title>Access Blocked</title></head>"
        "<body style='font-family:Arial,sans-serif;background:#f7f7f7;color:#222;padding:40px;'>"
        "<h2>Access blocked</h2>"
        "<p>VPN or proxy usage is not allowed while accessing this prototype.</p>"
        f"<p><strong>Reason:</strong> {reason or 'network privacy relay detected'}</p>"
        "<p>Please disable VPN/proxy and refresh this page.</p>"
        "</body></html>"
    )
    return Response(content=html, media_type="text/html", status_code=403)


@app.get("/")
async def root() -> FileResponse:
    return FileResponse(str(FRONTEND_DIR / "index.html"))


@app.post("/api/scan")
async def create_scan(req: ScanRequest) -> dict[str, str | bool]:
    domain_in = _normalize_domain(req.domain)
    if not _is_valid_scan_domain(domain_in):
        raise HTTPException(status_code=400, detail="Invalid domain. Please provide a valid hostname like pnb.bank.in")
    with get_session() as session:
        if REUSE_COMPLETED_SCANS:
            reusable = _latest_reusable_scan(session, domain_in)
            if reusable is not None:
                _ensure_chain_block_for_completed_scan(session, reusable)
                return {"scan_id": reusable.scan_id, "status": reusable.status, "reused": True}
        scan = create_scan_record(session, domain_in, deep_scan=req.deep_scan)
        scan_id = scan.scan_id
        domain = scan.domain
        status = scan.status
    payload: dict[str, str | bool] = {"scan_id": scan_id, "status": status, "reused": False}
    if USE_CELERY:
        run_scan_task.delay(scan_id, domain)
    else:
        asyncio.create_task(run_scan_pipeline(scan_id, domain))
    return payload


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    with get_session() as session:
        row = session.get(Scan, scan_id)
        if row:
            _ensure_chain_block_for_completed_scan(session, row)
        scan = scan_detail_payload(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    return scan


@app.get("/api/scans")
async def list_scans() -> list[dict]:
    with get_session() as session:
        return scans_list_payload(session)


@app.get("/api/chain/verify")
async def verify_chain() -> dict:
    with get_session() as session:
        return _verify_chain_integrity(session)


@app.get("/api/scan/{scan_id}/findings")
async def get_findings(scan_id: str) -> dict:
    with get_session() as session:
        data = findings_payload(session, scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    return data


@app.get("/api/scan/{scan_id}/cbom")
async def get_scan_cbom(scan_id: str) -> JSONResponse:
    with get_session() as session:
        row = session.get(Scan, scan_id)
        if row:
            _ensure_chain_block_for_completed_scan(session, row)
        scan = assemble_scan_payload(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    if not scan.get("cbom"):
        raise HTTPException(status_code=409, detail="CBOM not ready")
    return JSONResponse(scan["cbom"], media_type="application/vnd.cyclonedx+json")


@app.get("/api/scan/{scan_id}/report.pdf")
async def get_scan_pdf(scan_id: str) -> Response:
    with get_session() as session:
        row = session.get(Scan, scan_id)
        if row:
            _ensure_chain_block_for_completed_scan(session, row)
        scan = assemble_scan_payload(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    if not scan.get("findings"):
        raise HTTPException(status_code=409, detail="Scan report not ready")
    pdf = build_scan_pdf(scan)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=quanthunt-{scan_id}.pdf"},
    )


@app.get("/api/scan/{scan_id}/certificate.pdf")
async def get_scan_certificate(scan_id: str) -> Response:
    with get_session() as session:
        row = session.get(Scan, scan_id)
        if row:
            _ensure_chain_block_for_completed_scan(session, row)
        scan = assemble_scan_payload(session, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    findings = scan.get("findings") or []
    if not findings:
        raise HTTPException(status_code=409, detail="Scan findings are required before certificate generation")
    scores = [float(f.get("hndl_risk_score", 0)) for f in findings]
    avg_risk = sum(scores) / max(len(scores), 1)
    label = readiness_label(avg_risk)
    if label == "CRITICAL EXPOSURE":
        raise HTTPException(
            status_code=409,
            detail=f"Certificate available only for non-critical posture (HNDL <= 80). Current label: {label}",
        )
    pdf = build_quantum_certificate(scan, avg_risk)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=quanthunt-certificate-{scan_id}.pdf"},
    )


@app.post("/api/pdf/generate")
async def generate_pdf_on_demand(req: PdfGenerateRequest) -> Response:
    if not req.scan_id and not req.domain:
        raise HTTPException(status_code=400, detail="Provide scan_id or domain")

    with get_session() as session:
        target_scan_id = (req.scan_id or "").strip()
        if not target_scan_id:
            domain_in = _normalize_domain(req.domain or "")
            if not _is_valid_scan_domain(domain_in):
                raise HTTPException(status_code=400, detail="Invalid domain. Please provide a valid hostname like pnb.bank.in")
            latest = session.execute(
                select(Scan)
                .where(Scan.domain == domain_in, Scan.status == "completed")
                .order_by(desc(Scan.completed_at), desc(Scan.created_at))
            ).scalars().first()
            if latest is None:
                raise HTTPException(status_code=404, detail=f"No completed scan found for domain: {domain_in}")
            target_scan_id = latest.scan_id

        row = session.get(Scan, target_scan_id)
        if row:
            _ensure_chain_block_for_completed_scan(session, row)
        scan = assemble_scan_payload(session, target_scan_id)

    if scan is None:
        raise HTTPException(status_code=404, detail="scan_id not found")
    findings = scan.get("findings") or []
    if not findings:
        raise HTTPException(status_code=409, detail="Scan findings are required before branded PDF generation")

    if req.kind == "certificate":
        scores = [float(f.get("hndl_risk_score", 0)) for f in findings]
        avg_risk = sum(scores) / max(len(scores), 1)
        label = readiness_label(avg_risk)
        if label == "CRITICAL EXPOSURE":
            raise HTTPException(
                status_code=409,
                detail=f"Certificate available only for non-critical posture (HNDL <= 80). Current label: {label}",
            )
        pdf = build_quantum_certificate(scan, avg_risk)
        filename = f"quanthunt-certificate-{scan.get('scan_id', target_scan_id)}.pdf"
    else:
        pdf = build_scan_pdf(scan)
        filename = f"quanthunt-{scan.get('scan_id', target_scan_id)}-report.pdf"

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/api/scan/batch")
async def create_batch_scan(req: BatchScanRequest) -> dict:
    items: list[dict[str, str | bool]] = []
    queued: list[tuple[str, str]] = []
    invalid: list[str] = []
    normalized: list[str] = []
    for domain in req.domains:
        d = _normalize_domain(domain)
        if _is_valid_scan_domain(d):
            normalized.append(d)
        else:
            invalid.append(domain)
    if invalid:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Batch contains invalid domains. Provide valid hostnames like pnb.bank.in.",
                "invalid_domains": invalid,
            },
        )
    with get_session() as session:
        for domain in normalized:
            if REUSE_COMPLETED_SCANS:
                reusable = _latest_reusable_scan(session, domain)
                if reusable is not None:
                    _ensure_chain_block_for_completed_scan(session, reusable)
                    items.append({"domain": reusable.domain, "scan_id": reusable.scan_id, "status": reusable.status, "reused": True})
                    continue
            scan = create_scan_record(session, domain, deep_scan=req.deep_scan)
            items.append({"domain": scan.domain, "scan_id": scan.scan_id, "status": scan.status, "reused": False})
            queued.append((scan.scan_id, scan.domain))
    for scan_id, domain in queued:
        if USE_CELERY:
            run_scan_task.delay(scan_id, domain)
        else:
            asyncio.create_task(run_scan_pipeline(scan_id, domain))
    return {"submitted": len(items), "scheduled": len(queued), "reused": len(items) - len(queued), "scans": items}


@app.get("/api/leaderboard")
async def leaderboard() -> list[dict]:
    with get_session() as session:
        return leaderboard_payload(session)


def _extract_gemini_text(data: dict) -> str:
    for candidate in data.get("candidates", []):
        content = candidate.get("content") or {}
        chunks: list[str] = []
        for part in content.get("parts", []):
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                chunks.append(text.strip())
        if chunks:
            return "\n".join(chunks).strip()
    return ""


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _rows_from_context(context: str | None) -> list[dict]:
    if not context:
        return []
    rows: list[dict] = []
    for line in context.splitlines():
        m = re.match(
            r"\s*\d+\.\s*([^\s]+)\s+score=([0-9]+(?:\.[0-9]+)?)\s+assets=([0-9]+)",
            line.strip(),
        )
        if not m:
            continue
        domain = m.group(1)
        score = float(m.group(2))
        assets = int(m.group(3))
        rows.append({"domain": domain, "score": score, "assets": assets})
    return rows


def _source_from_context(context: str | None) -> str:
    if not context:
        return "unknown"
    for line in context.splitlines():
        if line.lower().startswith("source="):
            return line.split("=", 1)[1].strip().lower()
    return "unknown"


def _offline_chain_reply(message: str, context: str | None = None) -> tuple[str, str]:
    msg = _normalize_text(message)
    if "focus:analysis" in msg and "analysis" not in msg:
        msg = "analysis"
    if "focus:prediction" in msg and "prediction" not in msg and "predict" not in msg:
        msg = "prediction"
    if "focus:solutions" in msg and "solution" not in msg:
        msg = "solutions"
    rows = _rows_from_context(context)
    source = _source_from_context(context)
    ranked = sorted(rows, key=lambda x: x["score"]) if rows else []
    safest = ranked[0] if ranked else None
    riskiest = ranked[-1] if ranked else None
    top_domain = (riskiest or {}).get("domain", "your highest-risk bank domain")
    options = (
        "Try: hi | intro | best bank in terms of safety | riskiest bank and why | "
        "analysis | prediction | solutions | roadmap | top 3 risky | top 3 safest | "
        "pqc detection limits | chain block meaning | certificate criteria | testing coverage | demo script | cors stance"
    )

    if msg in {"1", "hi", "hello", "hey", "yo"}:
        return (
            "Hi, this is Quanthunt assistant offline mode.\n"
            "I can answer bank-safety questions from current scan context or demo baseline.\n"
            f"{options}",
            "greeting",
        )
    if msg in {"2", "intro", "introduction", "introduce", "what is quanthunt", "what is quantumshield"}:
        return (
            "Quanthunt is a PQC posture dashboard.\n"
            "It scans assets, evaluates HNDL crypto risk, and generates roadmap + CBOM outputs.\n"
            "PQC/FIPS mapping is heuristic from observed TLS/certificate metadata, and chain blocks are tamper-evident hash links (not decentralized blockchain consensus).",
            "intro",
        )
    if (
        (
            "best bank" in msg
            or "safest bank" in msg
            or msg in {"best", "safest", "best bank in terms of safety"}
        )
        and "top 3" not in msg
        and "top three" not in msg
    ):
        if safest:
            return (
                f"Safest bank candidate right now: {safest['domain']}.\n"
                f"Risk score: {safest['score']:.1f} across {safest['assets']} assets.\n"
                f"Context source: {source}. Lower score means safer posture in this model.",
                "best_bank",
            )
        return ("No bank ranking context available yet. Run scans or open leaderboard first.", "best_bank")
    if "riskiest bank" in msg or "worst bank" in msg or "highest risk" in msg:
        if riskiest:
            return (
                f"Highest-risk bank candidate: {riskiest['domain']}.\n"
                f"Risk score: {riskiest['score']:.1f} across {riskiest['assets']} assets.\n"
                "Why: higher average HNDL exposure and larger weak-asset footprint.",
                "riskiest_bank",
            )
        return ("No risk ranking context available yet. Run bank scans to generate this.", "riskiest_bank")
    if (
        ("top 3" in msg or "top three" in msg or "three") and ("risky" in msg or "highest risk" in msg)
    ) or msg in {"top 3 risky", "top risky"}:
        if ranked:
            top = list(reversed(ranked[-3:]))
            lines = [f"{i + 1}. {r['domain']} ({r['score']:.1f})" for i, r in enumerate(top)]
            return ("Top 3 risky banks:\n" + "\n".join(lines), "top_3_risky")
        return ("No ranking context available yet.", "top_3_risky")
    if (
        ("top 3" in msg or "top three" in msg or "three") and ("safe" in msg or "safest" in msg)
    ) or msg in {"top 3 safest", "top safest"}:
        if ranked:
            top = ranked[:3]
            lines = [f"{i + 1}. {r['domain']} ({r['score']:.1f})" for i, r in enumerate(top)]
            return ("Top 3 safest banks:\n" + "\n".join(lines), "top_3_safest")
        return ("No ranking context available yet.", "top_3_safest")
    if msg in {"analysis", "give analysis"} or "analysis" in msg:
        if ranked:
            avg = sum(r["score"] for r in ranked) / len(ranked)
            spread = ranked[-1]["score"] - ranked[0]["score"]
            return (
                f"Bank portfolio analysis ({source}):\n"
                f"- Safest: {ranked[0]['domain']} ({ranked[0]['score']:.1f})\n"
                f"- Riskiest: {ranked[-1]['domain']} ({ranked[-1]['score']:.1f})\n"
                f"- Average risk: {avg:.1f}\n"
                f"- Risk spread: {spread:.1f}",
                "analysis",
            )
        return ("No portfolio context available for analysis yet.", "analysis")
    if msg in {"prediction", "forecast", "give prediction", "predict"} or "prediction" in msg:
        if riskiest:
            predicted = min(100.0, riskiest["score"] + 6.0)
            return (
                f"90-day prediction for {riskiest['domain']}:\n"
                f"- Current risk: {riskiest['score']:.1f}\n"
                f"- Projected risk without remediation: {predicted:.1f}\n"
                "- Key drivers: exposed legacy crypto, weak TLS hardening cadence.",
                "prediction",
            )
        return ("No data to predict yet. Complete at least one bank scan.", "prediction")
    if msg in {"solution", "solutions", "give solution plan"} or "solution" in msg:
        return (
            "Recommended solutions:\n"
            "1. Patch top weak bank assets first by risk score.\n"
            "2. Enforce TLS/cipher baseline and rotate weak cert signatures.\n"
            "3. Add monthly bank-domain batch scan with drift alerts.\n"
            "4. Track safest vs riskiest delta to measure remediation impact.",
            "solutions",
        )
    if msg in {"3", "risk", "risks", "top risk", "top risky domains"} or ("risk" in msg and "domain" in msg):
        return (
            f"Top risk focus: {top_domain}.\n"
            "Immediate actions: upgrade key exchange to PQC-ready profile, harden TLS config, and rotate weak cert/signature chains.",
            "risks",
        )
    if msg in {"4", "roadmap", "migration roadmap", "30 day roadmap"} or "roadmap" in msg:
        return (
            f"30-day roadmap for {top_domain}:\n"
            "Week 1: inventory crypto + classify by risk.\n"
            "Week 2: patch TLS/cert weaknesses.\n"
            "Week 3: pilot PQC-capable endpoints.\n"
            "Week 4: rollout + monitor regression.",
            "roadmap",
        )
    if msg in {"5", "cbom", "sbom", "what is cbom"} or "cbom" in msg:
        return (
            "CBOM explains where cryptography is used, current algorithm posture, and migration priority.\n"
            "Use it to plan PQC transitions by business impact.",
            "cbom",
        )
    if (
        "pqc detection" in msg
        or "real pqc" in msg
        or "fips validation" in msg
        or "heuristic" in msg
    ):
        return (
            "PQC detection here is an external-observation heuristic.\n"
            "It uses observed TLS/certificate metadata and signals likely posture, not cryptographic proof of full production ML-KEM/ML-DSA deployment.",
            "pqc_limits",
        )
    if "blockchain" in msg or "chain block" in msg or "tamper evidence" in msg:
        return (
            "The audit chain is a tamper-evident hash chain, not a decentralized blockchain.\n"
            "Each completed scan writes one hash-linked block for integrity tracking and audit replay.",
            "chain_clarity",
        )
    if "certificate" in msg and ("criteria" in msg or "eligible" in msg or "require" in msg):
        return (
            "Certificate rule: aggregate HNDL must be non-critical.\n"
            "Current threshold: score <= 80 is eligible; score > 80 is blocked.",
            "certificate_criteria",
        )
    if "testing" in msg or "test coverage" in msg or msg in {"tests", "testing coverage"}:
        return (
            "Current offline regression checks cover HNDL label thresholds, key-exchange calibration, and offline intent routing.\n"
            "Add network-integration tests for scanner probes as the next hardening step.",
            "testing",
        )
    if "frontend polish" in msg or "ui polish" in msg:
        return (
            "Frontend polish guidance:\n"
            "1. Keep current layout, tighten copy clarity.\n"
            "2. Keep risk legends consistent with backend thresholds.\n"
            "3. Keep offline assistant prompts explicit for demo flow.",
            "frontend_polish",
        )
    if "demo script" in msg or "pitch flow" in msg or "demo flow" in msg:
        return (
            "Recommended 3-minute demo flow:\n"
            "1. Scan domain (or reuse existing completed scan).\n"
            "2. Show HNDL breakdown + findings.\n"
            "3. Open CBOM with FIPS mapping.\n"
            "4. Show hash-chain audit block.\n"
            "5. Ask OmegaGPT offline: analysis, prediction, solutions.",
            "demo_script",
        )
    if "cors" in msg:
        return (
            "Demo posture: CORS is allowlisted by origin now.\n"
            "For production, set CORS_ALLOW_ORIGINS strictly to approved intranet/app origins only.",
            "cors",
        )
    if "limitations" in msg or "weakness" in msg:
        return (
            "Known limitations:\n"
            "1. PQC/FIPS detection is heuristic from observable metadata.\n"
            "2. External scanning reflects exposed posture, not internal key-management internals.\n"
            "3. Offline assistant is deterministic and context-bound.",
            "limitations",
        )
    if msg in {"6", "compare", "comparison", "secure vs risk"} or "compare" in msg:
        return (
            "Business comparison:\n"
            "High-risk assets increase breach and compliance exposure.\n"
            "PQC-ready assets reduce migration cost and long-term cryptographic risk.",
            "compare",
        )
    return (
        "Live model unavailable, so I switched to offline guided answers.\n"
        f"{options}",
        "menu",
    )


@app.post("/api/omegagpt/chat")
@app.post("/api/omegagpt")
async def omegagpt_chat(req: OmegaChatRequest) -> dict:
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message is required")

    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    mode = req.mode or "auto"
    focus = req.focus or "general"

    system = (
        "You are OmegaGPT inside Quanthunt, a cybersecurity assistant focused on "
        "quantum-risk, HNDL, TLS posture, CBOM guidance, and practical remediation. "
        "Be explicit that PQC/FIPS detection here is heuristic from observable metadata and that chain blocks are tamper-evident hash-chain records, not decentralized blockchain consensus."
    )
    user_text = req.message.strip()
    if focus != "general":
        user_text = f"{user_text}\n\nfocus:{focus}"
    user_payload = user_text if not req.context else f"Context:\n{req.context}\n\nUser request:\n{user_text}"

    response_errors: list[str] = []
    if not api_key and mode != "offline":
        response_errors.append("live model key missing")
    if api_key and mode != "offline":
        payload = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user_payload}]}],
            "generationConfig": {"temperature": 0.25, "maxOutputTokens": 420},
        }
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, params={"key": api_key}, json=payload)
                resp.raise_for_status()
                text = _extract_gemini_text(resp.json())
                if text:
                    return {"reply": text, "model": model, "source": "gemini-live", "offline_mode": False}
                response_errors.append("gemini returned empty text")
        except Exception as ex:
            response_errors.append(f"gemini request failed: {ex}")
    elif mode == "offline":
        response_errors.append("forced offline mode")

    reply, intent = _offline_chain_reply(user_text, req.context)
    if response_errors:
        reply = f"Live model is unavailable right now. Switched to offline mode.\n\n{reply}"
    return {
        "reply": reply,
        "model": model,
        "source": "offline-fallback" if response_errors or not api_key else "gemini-live",
        "offline_mode": True,
        "offline_reason": ", ".join(response_errors) if response_errors else "live model unavailable",
        "intent": intent,
        "errors": response_errors,
    }
