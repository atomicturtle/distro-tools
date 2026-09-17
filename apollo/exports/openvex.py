"""OpenVEX document builder for Rocky Linux CVE product statuses.

Adapted from CEM ``openvex.py`` (CEM_BASELINE) with Rocky publisher /
``pkg:rpm/rockylinux`` PURLs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from apollo.exports import attribution
from apollo.exports import purl as purl_mod

_STATUS_TO_OPENVEX = {
    "fixed": "fixed",
    "not_shipped": "not_affected",
    "under_investigation": "under_investigation",
    "known_not_affected": "not_affected",
}

_NOT_AFFECTED_JUSTIFICATION = "component_not_present"


def build_openvex(
    cve_id: str,
    entries: list,
    *,
    author: Optional[str] = None,
) -> dict[str, Any]:
    """Build an OpenVEX v0.2.0 document from VexProductEntry-like objects."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    statements = []
    for entry in entries:
        status = _STATUS_TO_OPENVEX.get(entry.status, entry.status)
        products = []
        if entry.status == "fixed":
            if not entry.package_nevras:
                continue
            for nevra in entry.package_nevras:
                purl = purl_mod.purl_from_nevra(nevra)
                if purl:
                    products.append({"@id": purl})
        else:
            products = [
                {
                    "@id": entry.product_key,
                    "name": entry.product_name,
                }
            ]

        if not products:
            continue

        stmt: dict[str, Any] = {
            "vulnerability": {"name": cve_id},
            "products": products,
            "status": status,
            "timestamp": now,
        }
        if status == "not_affected":
            stmt["justification"] = (
                entry.justification or _NOT_AFFECTED_JUSTIFICATION
            )
            if entry.action_statement:
                stmt["impact_statement"] = entry.action_statement
        elif entry.action_statement:
            stmt["action_statement"] = entry.action_statement
        statements.append(stmt)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{attribution.OPENVEX_BASE_URL}/cves/{cve_id}",
        "author": author or attribution.COMPANY_NAME,
        "timestamp": now,
        "version": 1,
        "statements": statements,
    }


def csaf_vex_to_openvex(csaf_document: dict[str, Any]) -> dict[str, Any]:
    """Convert a CSAF VEX document to OpenVEX (scanner interoperability)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    tracking_id = (
        (csaf_document.get("document") or {}).get("tracking") or {}
    ).get("id", "vex")

    statements = []
    for vuln in csaf_document.get("vulnerabilities") or []:
        cve = vuln.get("cve")
        if not cve:
            continue
        product_status = vuln.get("product_status") or {}
        for status, product_ids in product_status.items():
            open_status = _STATUS_TO_OPENVEX.get(status, status)
            products = []
            for pid in sorted(set(product_ids or [])):
                bare = pid.split(":", 1)[1] if ":" in pid else pid
                bare = bare.split("::", 1)[0]
                purl = purl_mod.purl_from_nevra(bare)
                if purl:
                    products.append({"@id": purl})
                else:
                    products.append({"@id": pid})
            if not products:
                continue
            stmt: dict[str, Any] = {
                "vulnerability": {"name": cve},
                "products": products,
                "status": open_status,
                "timestamp": now,
            }
            if open_status == "not_affected":
                stmt["justification"] = _NOT_AFFECTED_JUSTIFICATION
            statements.append(stmt)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{attribution.OPENVEX_BASE_URL}/cves/{tracking_id}",
        "author": attribution.COMPANY_NAME,
        "timestamp": now,
        "version": 1,
        "statements": statements,
    }
