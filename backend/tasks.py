from __future__ import annotations

import asyncio

from .celery_app import celery_app
from .scanner.pipeline import run_scan_pipeline


@celery_app.task(name="quantumshield.run_scan")
def run_scan_task(scan_id: str, domain: str) -> str:
    asyncio.run(run_scan_pipeline(scan_id, domain))
    return scan_id

