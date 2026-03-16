from __future__ import annotations

import os

import httpx


ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"


async def recommend_with_claude(asset: str, summary: str, base_recommendations: list[str]) -> list[str]:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
    if not api_key:
        return base_recommendations

    prompt = (
        "You are a cybersecurity consultant for banking infrastructure. "
        "Given this finding summary, return exactly 3 concise actionable migration steps "
        "for a post-quantum transition roadmap.\n\n"
        f"Asset: {asset}\nSummary: {summary}\n"
    )

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 280,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(ANTHROPIC_URL, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            text = ""
            for block in data.get("content", []):
                if block.get("type") == "text":
                    text += block.get("text", "")
            lines = [x.strip("- ").strip() for x in text.splitlines() if x.strip()]
            cleaned = [l for l in lines if len(l) > 8][:3]
            return cleaned if cleaned else base_recommendations
    except Exception:
        return base_recommendations

