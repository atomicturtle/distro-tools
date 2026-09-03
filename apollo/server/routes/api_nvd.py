"""NVD CVE enrichment API (NIST join; RH scores stay authoritative)."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, HTTPException
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
    published_at: Optional[str] = None
    last_modified_at: Optional[str] = None
    fetched_at: Optional[str] = None

    class Config:
        orm_mode = True


def nvd_cve_to_response(row: NvdCve) -> NvdCveResponse:
    def _iso(dt):
        if dt is None:
            return None
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
        published_at=_iso(row.published_at),
        last_modified_at=_iso(row.last_modified_at),
        fetched_at=_iso(row.fetched_at),
    )


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
