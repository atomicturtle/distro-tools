"""OVAL API — one document per Rocky Linux major version."""

from __future__ import annotations

import gzip

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from tortoise.queryset import Prefetch

from apollo.db import Advisory, AdvisoryPackage
from apollo.exports.oval import build_oval_xml, oval_filename

router = APIRouter(tags=["oval"])

_SUPPORTED_MAJORS = frozenset({8, 9, 10})


@router.get("/rocky-linux/{major}")
async def oval_for_major(
    major: int,
    compress: bool = Query(False, description="Return gzip-compressed XML"),
):
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
            Prefetch(
                "packages",
                queryset=AdvisoryPackage.filter(
                    product_name__startswith=product_prefix
                ),
            ),
        )
        .order_by("name")
    )
    xml = build_oval_xml(advisories, major)
    filename = oval_filename(major)
    if compress:
        payload = gzip.compress(xml.encode("utf-8"))
        return Response(
            content=payload,
            media_type="application/gzip",
            headers={
                "Content-Disposition": f'inline; filename="{filename}.gz"',
                "Content-Encoding": "gzip",
            },
        )
    return Response(
        content=xml,
        media_type="application/xml",
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
        },
    )
