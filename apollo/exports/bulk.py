"""Bulk errata.json export from Apollo advisories."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Optional

from apollo.exports import attribution
from apollo.rpm_helpers import parse_nevra

_KIND_TO_TYPE = {
    "Security": "security",
    "Bug Fix": "bugfix",
    "Enhancement": "enhancement",
}

_SUM_TYPE = {
    "sha256": 5,
    "sha512": 6,
    "sha1": 2,
    "md5": 1,
}


def _ms(dt: Optional[datetime]) -> Optional[dict]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return {"$date": int(dt.timestamp() * 1000)}


def _title_severity(severity: str) -> str:
    if not severity:
        return "None"
    return severity[:1].upper() + severity[1:].lower()


def product_matches_major(product_name: str, major: int) -> bool:
    prefix = f"Rocky Linux {major}"
    if product_name == prefix:
        return True
    return product_name.startswith(prefix + " ")


def _filename_from_nevra(nevra: str) -> str:
    try:
        parsed = parse_nevra(nevra)
        name = (
            f"{parsed['name']}-{parsed['version']}-"
            f"{parsed['release']}.{parsed['arch']}"
        )
    except ValueError:
        name = nevra
        head = name.split("-", 1)[0]
        if ":" in head and head.split(":", 1)[0].isdigit():
            name = name.split(":", 1)[1]
    if not name.endswith(".rpm"):
        name = f"{name}.rpm"
    return name


def _package_entry(pkg, reboot_suggested: bool) -> Optional[dict[str, Any]]:
    try:
        parsed = parse_nevra(pkg.nevra)
    except ValueError:
        return None
    checksum_type = (pkg.checksum_type or "sha256").lower()
    return {
        "src": "",
        "name": parsed.get("name") or pkg.package_name,
        "epoch": str(parsed.get("epoch") if parsed.get("epoch") is not None else "0"),
        "version": parsed.get("version") or "",
        "release": parsed.get("release") or "",
        "arch": parsed.get("arch") or "",
        "filename": _filename_from_nevra(pkg.nevra),
        "sum": pkg.checksum or "",
        "sum_type": _SUM_TYPE.get(checksum_type, 5),
        "reboot_suggested": 1 if reboot_suggested else 0,
    }


def _fill_src_rpms(packages: list) -> None:
    by_nvr = {}
    for pkg in packages:
        if pkg.get("arch") == "src":
            by_nvr[(pkg["name"], pkg["version"], pkg["release"])] = pkg["filename"]
    for pkg in packages:
        if pkg.get("arch") == "src":
            continue
        src = by_nvr.get((pkg["name"], pkg["version"], pkg["release"]))
        if src:
            pkg["src"] = src


def advisory_to_errata(advisory, major: int) -> Optional[dict[str, Any]]:
    packages = []
    for pkg in advisory.packages:
        if not product_matches_major(pkg.product_name or "", major):
            continue
        entry = _package_entry(pkg, bool(advisory.reboot_suggested))
        if entry is not None:
            packages.append(entry)
    if not packages:
        return None

    _fill_src_rpms(packages)

    issued = advisory.rocky_published_at or advisory.published_at
    updated = advisory.updated_at or issued
    year = (issued or datetime.now(timezone.utc)).year

    references = []
    rh_name = None
    if getattr(advisory, "red_hat_advisory", None) is not None:
        rh_name = advisory.red_hat_advisory.name
        references.append(
            {
                "href": attribution.red_hat_errata_url(rh_name),
                "type": "rhsa",
                "id": rh_name,
                "title": rh_name,
            }
        )
    references.append(
        {
            "href": f"{attribution.UI_ERRATA_BASE}/{major}/{advisory.name}.html",
            "type": "self",
            "id": advisory.name,
            "title": advisory.name,
        }
    )
    for cve_row in advisory.cves:
        cve = cve_row.cve
        references.append(
            {
                "href": f"{attribution.CVE_URL_BASE}/{cve}",
                "type": "cve",
                "id": cve,
                "title": cve,
            }
        )
    for fix in advisory.fixes:
        ticket = getattr(fix, "ticket_id", None) or getattr(fix, "ticket", None)
        if not ticket:
            continue
        references.append(
            {
                "href": getattr(fix, "source", None)
                or getattr(fix, "source_link", None)
                or "",
                "type": "bugzilla",
                "id": ticket,
                "title": getattr(fix, "description", None) or "",
            }
        )

    collection = f"rocky-linux-{major}"
    return {
        "updateinfo_id": advisory.name,
        "issued_date": _ms(issued),
        "fromstr": attribution.FROMSTR,
        "title": f"{_title_severity(advisory.severity)}: {advisory.synopsis}",
        "type": _KIND_TO_TYPE.get(advisory.kind, "security"),
        "release": "0",
        "version": "1",
        "rights": attribution.rights_line(year, rh_name),
        "solution": (
            "For details on how to apply this update, which includes the changes "
            "described in this advisory, refer to:\n\n"
            "https://docs.rockylinux.org/"
        ),
        "status": "final",
        "severity": _title_severity(advisory.severity),
        "summary": advisory.synopsis,
        "pushcount": "1",
        "updated_date": _ms(updated),
        "description": advisory.description or advisory.topic or "",
        "references": references,
        "pkglist": {
            "name": collection,
            "shortname": collection,
            "packages": packages,
        },
    }


def build_errata_dump(advisories: Iterable[Any], major: int) -> list:
    out = []
    for advisory in advisories:
        item = advisory_to_errata(advisory, major)
        if item is not None:
            out.append(item)
    out.sort(key=lambda row: row["updateinfo_id"])
    return out
