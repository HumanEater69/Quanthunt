from __future__ import annotations

import asyncio

from .celery_app import celery_app
from .scanner.pipeline import run_scan_pipeline

@celery_app.task(name="quantumshield.run_scan")
def run_scan_task(
    scan_id: str,
    domain: str,
    scan_model: str = "general",
    dns_resolvers: list[str] | None = None,
    dns_doh_endpoints: list[str] | None = None,
    dns_enable_doh: bool | None = None,
) -> str:
    asyncio.run(
        run_scan_pipeline(
            scan_id,
            domain,
            scan_model=scan_model,
            dns_resolvers=dns_resolvers,
            dns_doh_endpoints=dns_doh_endpoints,
            dns_enable_doh=dns_enable_doh,
        )
    )
    return scan_id
