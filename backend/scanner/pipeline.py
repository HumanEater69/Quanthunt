from __future__ import annotations

import asyncio

from ..crud import (
    add_crypto_finding,
    add_log,
    add_recommendation,
    append_chain_block,
    create_asset,
    save_cbom,
    set_scan_state,
)
from ..db import get_session
from ..models import APIInfo, TLSInfo
from .api_analyzer import analyze_api
from .ai_recommender import recommend_with_claude
from .asset_discovery import discover_assets
from .cbom_generator import build_cbom
from .pqc_engine import (
    classify_auth,
    classify_cert_algo,
    classify_key_exchange,
    classify_symmetric,
    classify_tls_version,
    hndl_score,
    label_for_score,
    recommendations_for_status,
)
from .tls_inspector import inspect_tls


def _db_log(scan_id: str, message: str, progress: int | None = None, status: str | None = None, error: str | None = None) -> None:
    with get_session() as session:
        add_log(session, scan_id, message)
        if progress is not None or status is not None or error is not None:
            current_status = status or "running"
            set_scan_state(session, scan_id, current_status, progress=progress, error=error)


async def _scan_asset(asset: str) -> tuple[TLSInfo, APIInfo]:
    tls_task = asyncio.to_thread(inspect_tls, asset, 443)
    api_task = asyncio.to_thread(analyze_api, asset)
    return await asyncio.gather(tls_task, api_task)


async def run_scan_pipeline(scan_id: str, domain: str) -> None:
    try:
        _db_log(scan_id, f"[DISCOVERY] Starting asset discovery for {domain}", 5, status="running")
        assets = await asyncio.to_thread(discover_assets, domain)
        _db_log(scan_id, f"[DISCOVERY] Found {len(assets)} assets", 20)

        packed_findings: list[dict] = []
        total = max(len(assets), 1)
        for idx, asset in enumerate(assets, start=1):
            _db_log(scan_id, f"[SCAN] Inspecting TLS/API for {asset}")
            tls, api = await _scan_asset(asset)

            key_exchange_status = classify_key_exchange(tls.cipher_suite, tls.tls_version)
            auth_status = classify_auth(tls, api)
            tls_status = classify_tls_version(tls.tls_version)
            cert_algo_status = classify_cert_algo(tls)
            symmetric_status = classify_symmetric(tls.cipher_suite)
            score = hndl_score(key_exchange_status, auth_status, tls_status, cert_algo_status, symmetric_status)
            label = label_for_score(score)
            base_recs = recommendations_for_status(score)
            summary = (
                f"TLS={tls.tls_version} cipher={tls.cipher_suite} "
                f"key_exchange={key_exchange_status} auth={auth_status} score={score}"
            )
            recs = await recommend_with_claude(asset, summary, base_recs)

            metadata = {"tls": tls.model_dump(), "api": api.model_dump()}
            with get_session() as session:
                row = create_asset(
                    session=session,
                    scan_id=scan_id,
                    hostname=asset,
                    tls_version=tls.tls_version,
                    cipher_suite=tls.cipher_suite,
                    risk_score=score,
                    label=label,
                    metadata_json=metadata,
                    asset_type="api" if api.api_ports_open else "web",
                )
                add_crypto_finding(session, scan_id, row.id, "key_exchange", tls.cipher_suite or "unknown", key_exchange_status)
                add_crypto_finding(session, scan_id, row.id, "authentication", tls.cert_sig_algo or "unknown", auth_status)
                add_crypto_finding(session, scan_id, row.id, "tls_version", tls.tls_version or "unknown", tls_status)
                add_crypto_finding(session, scan_id, row.id, "certificate", tls.cert_sig_algo or "unknown", cert_algo_status)
                add_crypto_finding(session, scan_id, row.id, "symmetric", tls.cipher_suite or "unknown", symmetric_status)
                phases = ["Phase 1", "Phase 2", "Phase 3", "Phase 4"]
                for i, rec in enumerate(recs):
                    add_recommendation(session, scan_id, row.id, rec, phase=phases[min(i, len(phases) - 1)])

            packed_findings.append(
                {
                    "asset": asset,
                    "tls": tls,
                    "api": api,
                    "hndl_risk_score": score,
                    "label": label,
                }
            )
            progress = 20 + int((idx / total) * 65)
            _db_log(scan_id, f"[PQC] {asset} classified as {label} with score {score}", progress)

        cbom_findings = []
        for f in packed_findings:
            # lightweight adapter to match existing cbom generator expectations
            cbom_findings.append(
                type(
                    "Tmp",
                    (),
                    {
                        "asset": f["asset"],
                        "tls": f["tls"],
                        "hndl_risk_score": f["hndl_risk_score"],
                        "label": f["label"],
                    },
                )()
            )
        cbom = build_cbom(domain, cbom_findings)
        avg_risk = round(sum(x["hndl_risk_score"] for x in packed_findings) / max(len(packed_findings), 1), 2)
        with get_session() as session:
            save_cbom(session, scan_id, cbom)
            append_chain_block(
                session,
                scan_id,
                payload={
                    "scan_id": scan_id,
                    "domain": domain,
                    "assets": len(packed_findings),
                    "avg_hndl_risk": avg_risk,
                    "labels": sorted({x["label"] for x in packed_findings}),
                    "cbom_components": len(cbom.get("components", [])),
                },
                difficulty=2,
            )
            set_scan_state(session, scan_id, "completed", progress=100)
            add_log(session, scan_id, "[DONE] Scan completed successfully")
    except Exception as ex:
        _db_log(scan_id, f"[ERROR] {ex}", status="failed", error=str(ex))
