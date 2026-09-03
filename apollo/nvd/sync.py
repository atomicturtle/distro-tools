"""Upsert NVD rows for CVE IDs already present in Apollo."""

from __future__ import annotations

import asyncio
import datetime
import os
from typing import Iterable, Optional

import aiohttp

from apollo.db import AdvisoryCVE, NvdCve, RedHatAdvisoryCVE
from apollo.nvd.client import NvdApiError, fetch_nvd_cve


async def known_cve_ids() -> list[str]:
    """Distinct CVE IDs from Rocky clones and RH advisories."""
    rocky = await AdvisoryCVE.all().distinct().values_list("cve", flat=True)
    rh = await RedHatAdvisoryCVE.all().distinct().values_list("cve", flat=True)
    ids = {c for c in rocky if c} | {c for c in rh if c}
    return sorted(ids)


async def upsert_nvd_row(fields: dict) -> NvdCve:
    now = datetime.datetime.now(datetime.timezone.utc)
    existing = await NvdCve.filter(cve_id=fields["cve_id"]).first()
    if existing:
        for key, value in fields.items():
            setattr(existing, key, value)
        existing.fetched_at = now
        await existing.save()
        return existing
    return await NvdCve.create(**fields, fetched_at=now)


async def sync_cve_ids(
    cve_ids: Iterable[str],
    *,
    api_key: Optional[str] = None,
    sleep_seconds: Optional[float] = None,
) -> dict:
    """Fetch and upsert each CVE. Returns counts."""
    key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
    # NVD: ~5 req/30s without key, ~50 with key. Default conservatively.
    if sleep_seconds is None:
        sleep_seconds = 0.7 if key else 6.5

    counts = {"fetched": 0, "upserted": 0, "missing": 0, "errors": 0}
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for cve_id in cve_ids:
            try:
                fields = await fetch_nvd_cve(session, cve_id, api_key=key)
            except NvdApiError:
                counts["errors"] += 1
                await asyncio.sleep(sleep_seconds)
                continue
            counts["fetched"] += 1
            if fields is None:
                counts["missing"] += 1
            else:
                await upsert_nvd_row(fields)
                counts["upserted"] += 1
            await asyncio.sleep(sleep_seconds)
    return counts


async def sync_known_cves(
    *,
    limit: Optional[int] = None,
    only_missing: bool = False,
    api_key: Optional[str] = None,
    sleep_seconds: Optional[float] = None,
) -> dict:
    ids = await known_cve_ids()
    if only_missing:
        have = set(
            await NvdCve.all().values_list("cve_id", flat=True)
        )
        ids = [c for c in ids if c not in have]
    if limit is not None:
        ids = ids[:limit]
    counts = await sync_cve_ids(
        ids, api_key=api_key, sleep_seconds=sleep_seconds
    )
    counts["candidates"] = len(ids)
    return counts


async def nvd_for_cve_ids(cve_ids: Iterable[str]) -> dict[str, NvdCve]:
    ids = [c for c in cve_ids if c]
    if not ids:
        return {}
    rows = await NvdCve.filter(cve_id__in=ids)
    return {row.cve_id: row for row in rows}
