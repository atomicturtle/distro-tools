"""CSAF 2.0 VEX generator for Rocky Linux CVE product statuses.

Adapted from CEM ``vex.py`` (CEM_BASELINE). Fail-closed: fixed entries
without NEVRAs are omitted rather than emitting SRPM-only product_ids.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from apollo.exports import attribution
from apollo.exports import cpe as cpe_mod
from apollo.exports import purl as purl_mod

logger = logging.getLogger(__name__)

_STATUS_TO_CSAF = {
    "fixed": "fixed",
    "not_shipped": "known_not_affected",
    "under_investigation": "under_investigation",
}

_NOT_AFFECTED_JUSTIFICATION = "component_not_present"


@dataclass
class VexProductEntry:
    product_key: str
    product_name: str
    cpe_23: Optional[str]
    status: str
    justification: Optional[str] = None
    action_statement: Optional[str] = None
    package_nevras: list = field(default_factory=list)
    module_stream: Optional[str] = None

    def product_ids(self) -> list:
        if self.status == "fixed":
            if not self.package_nevras:
                raise ValueError(
                    f"fixed VEX entry for {self.product_key} has no "
                    "package_nevras; refuse product-only product_id"
                )
            return [
                _qualify(f"{self.product_key}:{nevra}", self.module_stream)
                for nevra in self.package_nevras
            ]
        return [
            _qualify(f"{self.product_key}:product", self.module_stream),
        ]


def _qualify(product_id: str, module_stream: Optional[str]) -> str:
    return f"{product_id}::{module_stream}" if module_stream else product_id


class VexCSAFGenerator:
    CSAF_VERSION = "2.0"
    GENERATOR_NAME = "Rocky Linux Apollo CSAF VEX Generator"
    GENERATOR_VERSION = "1.0.0"
    PUBLISHER = attribution.PUBLISHER

    def generate(
        self,
        cve_id: str,
        entries: list,
        scores: Optional[list] = None,
        tracking_version: int = 1,
        description: Optional[str] = None,
    ) -> dict:
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
        scores = scores or []

        usable = []
        for entry in entries:
            if entry.status == "fixed" and not entry.package_nevras:
                logger.warning(
                    "Omitting fixed VEX entry for %s/%s: no NEVRAs",
                    cve_id,
                    entry.product_key,
                )
                continue
            usable.append(entry)

        status_groups = defaultdict(list)
        all_product_ids = []
        for entry in usable:
            csaf_status = _STATUS_TO_CSAF.get(entry.status, entry.status)
            pids = entry.product_ids()
            status_groups[csaf_status].extend(pids)
            all_product_ids.extend(pids)

        return {
            "document": self._build_document(
                cve_id, timestamp, tracking_version, description
            ),
            "product_tree": self._build_product_tree(usable),
            "vulnerabilities": [
                self._build_vulnerability(
                    cve_id, description, status_groups, usable, scores
                )
            ],
        }

    def _build_document(self, cve_id, timestamp, tracking_version, description):
        notes = [attribution.legal_disclaimer_note()]
        if description:
            notes.insert(
                0,
                {
                    "category": "description",
                    "text": description,
                    "title": "Vulnerability Description",
                },
            )
        year = cve_id.split("-")[1] if "-" in cve_id else "0000"
        self_url = f"{attribution.CSAF_BASE_URL}/vex/{cve_id}"
        return {
            "category": "csaf_vex",
            "csaf_version": self.CSAF_VERSION,
            "distribution": {
                "text": attribution.vex_distribution_text(),
                "tlp": attribution.tlp_block(),
            },
            "lang": "en",
            "notes": notes,
            "publisher": self.PUBLISHER,
            "references": [
                {
                    "category": "self",
                    "summary": f"Rocky Linux CSAF VEX for {cve_id}",
                    "url": self_url,
                },
                {
                    "category": "external",
                    "summary": cve_id,
                    "url": f"{attribution.CVE_URL_BASE}/{cve_id}",
                },
            ],
            "title": f"Rocky Linux VEX for {cve_id}",
            "tracking": {
                "id": cve_id,
                "status": "final",
                "version": str(tracking_version),
                "revision_history": [
                    {
                        "date": timestamp,
                        "number": str(tracking_version),
                        "summary": "Generated from Apollo CVE product status",
                    }
                ],
                "initial_release_date": timestamp,
                "current_release_date": timestamp,
                "generator": {
                    "engine": {
                        "name": self.GENERATOR_NAME,
                        "version": self.GENERATOR_VERSION,
                    },
                    "date": timestamp,
                },
            },
        }

    def _build_product_tree(self, entries) -> dict:
        by_product = {}
        for entry in entries:
            by_product.setdefault(entry.product_key, entry)

        product_branches = []
        arch_pkg_branches = defaultdict(list)

        for entry in by_product.values():
            helper = {}
            if entry.cpe_23:
                helper["cpe"] = entry.cpe_23
            product_branches.append(
                {
                    "category": "product_name",
                    "name": entry.product_name,
                    "product": {
                        "product_id": entry.product_key,
                        "name": entry.product_name,
                        **(
                            {"product_identification_helper": helper}
                            if helper
                            else {}
                        ),
                    },
                }
            )
            for nevra in entry.package_nevras:
                purl = purl_mod.purl_from_nevra(nevra)
                arch = "*"
                if purl and "arch=" in purl:
                    arch = purl.split("arch=")[-1].split("&")[0]
                branch = {
                    "category": "product_version",
                    "name": nevra,
                    "product": {
                        "product_id": nevra,
                        "name": nevra,
                        "product_identification_helper": (
                            {"purl": purl} if purl else {}
                        ),
                    },
                }
                arch_pkg_branches[arch].append(branch)

        vendor_branches = [
            {
                "category": "product_family",
                "name": "Rocky Linux",
                "branches": product_branches,
            }
        ]
        for arch, branches in sorted(arch_pkg_branches.items()):
            vendor_branches.append(
                {
                    "category": "architecture",
                    "name": arch,
                    "branches": branches,
                }
            )

        relationships = []
        for entry in entries:
            for pid in entry.product_ids():
                if ":" not in pid:
                    continue
                relationships.append(
                    {
                        "product_reference": pid.split(":", 1)[1].split("::")[0],
                        "relates_to_product_reference": entry.product_key,
                        "category": "default_component_of",
                        "full_product_name": {
                            "name": f"{pid} as a component of {entry.product_name}",
                            "product_id": pid,
                        },
                    }
                )

        tree = {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Rocky Enterprise Software Foundation",
                    "branches": vendor_branches,
                }
            ]
        }
        if relationships:
            tree["relationships"] = relationships
        return tree

    def _build_vulnerability(
        self, cve_id, description, status_groups, entries, scores
    ):
        product_status = {
            status: sorted(set(pids))
            for status, pids in status_groups.items()
            if pids
        }
        vuln: dict[str, Any] = {
            "cve": cve_id,
            "product_status": product_status,
            "references": [
                {
                    "category": "external",
                    "summary": cve_id,
                    "url": f"{attribution.CVE_URL_BASE}/{cve_id}",
                }
            ],
        }
        if description:
            vuln["notes"] = [
                {
                    "category": "description",
                    "text": description,
                    "title": "Vulnerability Description",
                }
            ]

        flags = []
        for entry in entries:
            if entry.status != "not_shipped":
                continue
            flags.append(
                {
                    "label": entry.justification or _NOT_AFFECTED_JUSTIFICATION,
                    "product_ids": entry.product_ids(),
                }
            )
        if flags:
            vuln["flags"] = flags

        remediations = []
        for entry in entries:
            if entry.status != "fixed":
                continue
            remediations.append(
                {
                    "category": "vendor_fix",
                    "details": entry.action_statement
                    or f"Fixed for {entry.product_name}",
                    "product_ids": entry.product_ids(),
                    "url": f"{attribution.CSAF_BASE_URL}/vex/{cve_id}",
                }
            )
        if remediations:
            vuln["remediations"] = remediations

        cvss_scores = []
        for score in scores:
            vector = getattr(score, "cvss3_scoring_vector", None) or getattr(
                score, "cvss_v3_vector", None
            )
            base = getattr(score, "cvss3_base_score", None) or getattr(
                score, "cvss_v3_score", None
            )
            if not vector or not base:
                continue
            all_pids = []
            for pids in product_status.values():
                all_pids.extend(pids)
            try:
                base_f = float(base)
            except (TypeError, ValueError):
                continue
            cvss_scores.append(
                {
                    "products": sorted(set(all_pids)),
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": vector,
                        "baseScore": base_f,
                    },
                }
            )
        if cvss_scores:
            vuln["scores"] = cvss_scores
        return vuln


def entries_from_cve_statuses(rows, packages_by_advisory_id=None) -> list:
    """Build VexProductEntry list from CveProductStatus rows."""
    packages_by_advisory_id = packages_by_advisory_id or {}
    entries = []
    for row in rows:
        product = row.supported_product
        product_name = product.name if product else f"product-{row.supported_product_id}"
        major = None
        if product_name.startswith("Rocky Linux"):
            major = cpe_mod.rocky_major_from_product_name(
                f"{product_name} {getattr(product, 'variant', '') or ''}".strip()
            )
            # SupportedProduct is usually just "Rocky Linux"; major may come
            # from package product_name instead.
        product_key = f"rocky:product:{row.supported_product_id}"
        nevras = []
        if row.status == "fixed" and row.advisory_id:
            for pkg in packages_by_advisory_id.get(row.advisory_id, []):
                nevras.append(pkg.nevra)
                if major is None:
                    major = cpe_mod.rocky_major_from_product_name(
                        pkg.product_name or ""
                    )
        cpe = (
            cpe_mod.compute_rocky_platform_cpe(major)
            if major
            else None
        )
        action = None
        if row.status == "fixed" and row.advisory_id:
            action = f"Fixed in advisory_id={row.advisory_id}"
        entries.append(
            VexProductEntry(
                product_key=product_key,
                product_name=product_name,
                cpe_23=cpe,
                status=row.status,
                justification=(
                    _NOT_AFFECTED_JUSTIFICATION
                    if row.status == "not_shipped"
                    else None
                ),
                action_statement=action or row.reason,
                package_nevras=nevras,
            )
        )
    return entries
