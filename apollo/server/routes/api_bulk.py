"""Bulk dump API — full errata.json per Rocky Linux major version."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from tortoise.queryset import Prefetch

from apollo.db import Advisory, AdvisoryPackage
from apollo.exports.bulk import build_errata_dump

router = APIRouter(tags=["bulk"])

_SUPPORTED_MAJORS = frozenset({8, 9, 10})


@router.get("/rocky-linux/{major}/errata.json")
async def bulk_errata_json(major: int):
    """Return a full errata.json array for Rocky Linux <major>."""
    if major not in _SUPPORTED_MAJORS:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Unsupported major version {major}; "
                f"expected one of {sorted(_SUPPORTED_MAJORS)}"
            ),
        )

    product_prefix = f"Rocky Linux {major}"
    advisories = (
        await Advisory.filter(published_at__not_isnull=True)
        .prefetch_related(
            "cves",
            "fixes",
            "red_hat_advisory",
            Prefetch(
                "packages",
                queryset=AdvisoryPackage.filter(
                    product_name__startswith=product_prefix
                ),
            ),
        )
        .order_by("name")
    )

    payload = build_errata_dump(advisories, major)
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": (
                f'inline; filename="rocky-linux-{major}-errata.json"'
            ),
            "X-Apollo-Errata-Count": str(len(payload)),
        },
    )
