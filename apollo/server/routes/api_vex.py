"""OpenVEX-style export for Rocky CVE product statuses.

Emits full OpenVEX statements with pkg:rpm/rockylinux PURLs for fixed
statuses. not_shipped / under_investigation stay product-scoped and are
never package lists. Excluded from updateinfo by design.
"""

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from apollo.db import AdvisoryPackage, CveProductStatus, SupportedProduct
from apollo.exports.csaf_vex import entries_from_cve_statuses
from apollo.exports.openvex import build_openvex

router = APIRouter(tags=["vex"])

_STATUS_TO_VEX = {
    "fixed": "fixed",
    "not_shipped": "not_affected",
    "under_investigation": "under_investigation",
}


@router.get("/cves/{cve_id}")
async def vex_for_cve(cve_id: str):
    cve = cve_id.upper()
    if not cve.startswith("CVE-"):
        raise HTTPException(
            status_code=400, detail="cve_id must look like CVE-YYYY-NNNN"
        )

    rows = await CveProductStatus.filter(cve=cve).prefetch_related(
        "supported_product"
    )
    if not rows:
        raise HTTPException(status_code=404, detail=f"No VEX status for {cve}")

    advisory_ids = {
        row.advisory_id
        for row in rows
        if row.status == "fixed" and row.advisory_id
    }
    packages_by_advisory_id = {}
    if advisory_ids:
        packages = await AdvisoryPackage.filter(
            advisory_id__in=list(advisory_ids)
        )
        for pkg in packages:
            packages_by_advisory_id.setdefault(pkg.advisory_id, []).append(pkg)

    entries = entries_from_cve_statuses(rows, packages_by_advisory_id)
    return build_openvex(cve, entries)


@router.get("/products/{product_name}")
async def vex_for_product(
    product_name: str,
    status: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=2000),
):
    """List VEX statement summaries for a supported product."""
    product = await SupportedProduct.filter(name=product_name).first()
    if not product:
        raise HTTPException(
            status_code=404, detail=f"Unknown product {product_name}"
        )

    query = CveProductStatus.filter(supported_product_id=product.id)
    if status:
        query = query.filter(status=status)
    rows = await query.limit(limit).order_by("cve", "id")

    return {
        "product": product.name,
        "total": await query.count(),
        "generated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "statements": [
            {
                "cve": row.cve,
                "status": _STATUS_TO_VEX.get(row.status, row.status),
                "reason": row.reason,
                "advisory_id": row.advisory_id if row.status == "fixed" else None,
            }
            for row in rows
        ],
    }
