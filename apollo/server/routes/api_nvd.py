"""NVD CVE enrichment API (NIST join; RH scores stay authoritative)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from apollo.db import NvdCve

router = APIRouter(tags=["nvd"])


class NvdCveResponse(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss_v2_score: Optional[str] = None
    cvss_v2_vector: Optional[str] = None
    cvss_v3_score: Optional[str] = None
    cvss_v3_vector: Optional[str] = None
    cvss_v4_score: Optional[str] = None
    cvss_v4_vector: Optional[str] = None
    cwe: Optional[str] = None
    references: Optional[list[dict[str, Any]]] = None
    epss_score: Optional[str] = None
    epss_percentile: Optional[str] = None
    exploit_maturity: Optional[str] = None
    exploit_count: int = 0
    kev_listed: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_ransomware: Optional[str] = None
    cpes: Optional[list[str]] = None
    published_at: Optional[str] = None
    last_modified_at: Optional[str] = None
    fetched_at: Optional[str] = None

    class Config:
        orm_mode = True


class NvdCveListResponse(BaseModel):
    items: list[NvdCveResponse]
    missing: list[str] = []


def nvd_cve_to_response(row: NvdCve) -> NvdCveResponse:
    def _iso(dt):
        if dt is None:
            return None
        if isinstance(dt, datetime) and dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat("T").replace("+00:00", "Z")

    return NvdCveResponse(
        cve_id=row.cve_id,
        description=row.description,
        cvss_v2_score=row.cvss_v2_score,
        cvss_v2_vector=row.cvss_v2_vector,
        cvss_v3_score=row.cvss_v3_score,
        cvss_v3_vector=row.cvss_v3_vector,
        cvss_v4_score=row.cvss_v4_score,
        cvss_v4_vector=row.cvss_v4_vector,
        cwe=row.cwe,
        references=row.refs,
        epss_score=row.epss_score,
        epss_percentile=row.epss_percentile,
        exploit_maturity=row.exploit_maturity,
        exploit_count=int(row.exploit_count or 0),
        kev_listed=bool(row.kev_listed),
        kev_date_added=_iso(row.kev_date_added),
        kev_due_date=_iso(row.kev_due_date),
        kev_ransomware=row.kev_ransomware,
        cpes=row.cpes,
        published_at=_iso(row.published_at),
        last_modified_at=_iso(row.last_modified_at),
        fetched_at=_iso(row.fetched_at),
    )


@router.get("/cves", response_model=NvdCveListResponse)
async def list_nvd_cves(
    ids: str = Query(
        ...,
        description="Comma-separated CVE IDs (max 100)",
        examples=["CVE-2021-44228,CVE-2014-0160"],
    ),
):
    """Batch lookup of stored NVD enrichment rows."""
    raw_ids = [c.strip() for c in ids.split(",") if c.strip()]
    if not raw_ids:
        raise HTTPException(status_code=400, detail="ids is required")
    if len(raw_ids) > 100:
        raise HTTPException(status_code=400, detail="at most 100 CVE IDs")

    wanted = []
    original_by_upper = {}
    for raw in raw_ids:
        key = raw.upper()
        if key not in original_by_upper:
            original_by_upper[key] = raw
            wanted.append(key)
    rows = await NvdCve.filter(cve_id__in=wanted)
    by_id = {row.cve_id.upper(): row for row in rows}

    items: list[NvdCveResponse] = []
    missing: list[str] = []
    for cve_id in wanted:
        row = by_id.get(cve_id)
        if row:
            items.append(nvd_cve_to_response(row))
        else:
            missing.append(original_by_upper[cve_id])
    return NvdCveListResponse(items=items, missing=missing)


@router.get("/cves/{cve_id}", response_model=NvdCveResponse)
async def get_nvd_cve(cve_id: str):
    """Return stored NVD enrichment for a CVE ID (must already be synced)."""
    row = await NvdCve.filter(cve_id=cve_id.upper()).first()
    if not row:
        # Also try the raw form callers passed.
        row = await NvdCve.filter(cve_id=cve_id).first()
    if not row:
        raise HTTPException(status_code=404, detail=f"No NVD data for {cve_id}")
    return nvd_cve_to_response(row)
