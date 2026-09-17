"""CSAF SA and VEX HTTP APIs plus provider metadata."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from apollo.db import Advisory, AdvisoryPackage, CveProductStatus, NvdCve
from apollo.exports.csaf_sa import RockySACSAFGenerator
from apollo.exports.csaf_vex import VexCSAFGenerator, entries_from_cve_statuses
from apollo.exports.provider import advisory_index, changes_csv_rows, provider_metadata

router = APIRouter(tags=["csaf"])

_sa_generator = RockySACSAFGenerator()
_vex_generator = VexCSAFGenerator()


def _json_response(payload, filename: str) -> Response:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'inline; filename="{filename}"',
        },
    )


@router.get("/provider-metadata.json")
async def csaf_provider_metadata():
    advisories = await Advisory.filter(published_at__not_isnull=True).only(
        "name", "published_at", "updated_at", "rocky_published_at"
    )
    years = set()
    for adv in advisories:
        try:
            years.add(adv.name.split("-")[1].split(":")[0])
        except (IndexError, AttributeError):
            pass
    return provider_metadata(advisory_years=years)


@router.get("/advisories/")
async def csaf_advisories_index():
    advisories = (
        await Advisory.filter(published_at__not_isnull=True)
        .order_by("name")
        .only("name")
    )
    return advisory_index(advisories)


@router.get("/advisories/changes.csv")
async def csaf_advisories_changes():
    advisories = await Advisory.filter(published_at__not_isnull=True).only(
        "name", "published_at", "updated_at", "rocky_published_at"
    )
    return Response(
        content=changes_csv_rows(advisories),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'inline; filename="changes.csv"',
        },
    )


@router.get("/advisories/{rlsa_id}")
async def csaf_advisory(rlsa_id: str):
    advisory = (
        await Advisory.filter(name=rlsa_id)
        .prefetch_related(
            "cves",
            "fixes",
            "packages",
            "red_hat_advisory",
        )
        .first()
    )
    if not advisory:
        raise HTTPException(status_code=404, detail=f"Advisory {rlsa_id} not found")
    doc = _sa_generator.generate(advisory)
    return _json_response(doc, f"{rlsa_id.lower().replace(':', '_')}.json")


@router.get("/vex/{cve_id}")
async def csaf_vex(cve_id: str):
    cve = cve_id.upper()
    if not cve.startswith("CVE-"):
        raise HTTPException(
            status_code=400, detail="cve_id must look like CVE-YYYY-NNNN"
        )

    rows = await CveProductStatus.filter(cve=cve).prefetch_related(
        "supported_product", "advisory"
    )
    if not rows:
        raise HTTPException(status_code=404, detail=f"No VEX status for {cve}")

    advisory_ids = {
        row.advisory_id for row in rows if row.status == "fixed" and row.advisory_id
    }
    packages_by_advisory_id = {}
    if advisory_ids:
        packages = await AdvisoryPackage.filter(advisory_id__in=list(advisory_ids))
        for pkg in packages:
            packages_by_advisory_id.setdefault(pkg.advisory_id, []).append(pkg)

    entries = entries_from_cve_statuses(rows, packages_by_advisory_id)
    nvd = await NvdCve.filter(cve_id=cve).first()
    description = nvd.description if nvd else None
    scores = []
    if nvd:
        scores.append(nvd)
    fixed_adv_ids = [row.advisory_id for row in rows if row.advisory_id]
    if fixed_adv_ids:
        advisories = await Advisory.filter(
            id__in=fixed_adv_ids
        ).prefetch_related("cves")
        for adv in advisories:
            for cve_row in adv.cves:
                if cve_row.cve == cve:
                    scores.append(cve_row)

    doc = _vex_generator.generate(
        cve, entries, scores=scores, description=description
    )
    return _json_response(doc, f"{cve.lower()}.json")
