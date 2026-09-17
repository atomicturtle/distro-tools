"""CSAF 2.0 Security Advisory generator for Rocky Linux RLSAs.

Adapted from CEM ``rocky_clone.py`` (CEM_BASELINE) with Rocky publisher
metadata and RLSA tracking IDs (no CIQ/CRLSA rebranding).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from apollo.exports import attribution
from apollo.exports import cpe as cpe_mod
from apollo.exports import purl as purl_mod
from apollo.exports.cwe_names import get_cwe_name
from apollo.rpm_helpers import parse_nevra

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "critical": "Critical",
    "important": "Important",
    "moderate": "Moderate",
    "low": "Low",
    "none": "None",
}


class RockySACSAFGenerator:
    """Generate CSAF 2.0 security advisories from Apollo Advisory ORM objects."""

    CSAF_VERSION = "2.0"
    GENERATOR_NAME = "Rocky Linux Apollo CSAF SA Generator"
    GENERATOR_VERSION = "1.0.0"
    PUBLISHER = attribution.PUBLISHER

    def generate(self, advisory, version: str = "1.0.0") -> dict[str, Any]:
        published = advisory.rocky_published_at or advisory.published_at
        published_iso = _iso(published)
        generation_time = _iso(datetime.now(timezone.utc))
        packages = list(advisory.packages or [])
        product_tree = self._build_product_tree(packages)
        tracking_id = advisory.name

        doc = {
            "document": self._build_document(
                tracking_id=tracking_id,
                title=advisory.synopsis or tracking_id,
                topic=advisory.topic or "",
                description=advisory.description or "",
                published_at=published_iso,
                severity=advisory.severity,
                advisory=advisory,
                version=version,
                generation_time=generation_time,
            ),
            "product_tree": product_tree,
            "vulnerabilities": self._build_vulnerabilities(advisory, packages),
        }
        return doc

    def _build_document(
        self,
        tracking_id,
        title,
        topic,
        description,
        published_at,
        severity,
        advisory,
        version,
        generation_time,
    ):
        notes = []
        if topic:
            notes.append(
                {"category": "summary", "text": topic, "title": "Topic"}
            )
        if description:
            notes.append(
                {
                    "category": "description",
                    "text": description,
                    "title": "Description",
                }
            )
        notes.append(attribution.legal_disclaimer_note())

        self_url = f"{attribution.CSAF_BASE_URL}/advisories/{tracking_id}"

        references = [
            {
                "category": "self",
                "summary": f"Rocky Linux Security Advisory {tracking_id}",
                "url": self_url,
            },
            {
                "category": "external",
                "summary": f"Rocky Linux Errata {tracking_id}",
                "url": f"{attribution.UI_ERRATA_BASE}/{tracking_id}",
            },
        ]
        rh = getattr(advisory, "red_hat_advisory", None)
        if rh is not None and getattr(rh, "name", None):
            references.append(
                {
                    "category": "external",
                    "summary": f"Red Hat Security Advisory {rh.name}",
                    "url": attribution.red_hat_errata_url(rh.name),
                }
            )
        for fix in advisory.fixes or []:
            href = getattr(fix, "source", None) or ""
            if not href:
                continue
            summary = getattr(fix, "description", None) or (
                f"Bug fix {getattr(fix, 'ticket_id', '')}"
            )
            references.append(
                {"category": "external", "summary": summary, "url": href}
            )

        document = {
            "category": "csaf_security_advisory",
            "csaf_version": self.CSAF_VERSION,
            "distribution": {
                "text": attribution.sa_distribution_text(),
                "tlp": attribution.tlp_block(),
            },
            "notes": notes,
            "publisher": self.PUBLISHER,
            "references": references,
            "title": title,
            "tracking": {
                "id": tracking_id,
                "status": "final",
                "version": version,
                "revision_history": [
                    {
                        "date": published_at,
                        "number": version,
                        "summary": "Initial release",
                    }
                ],
                "initial_release_date": published_at,
                "current_release_date": generation_time,
                "generator": {
                    "engine": {
                        "name": self.GENERATOR_NAME,
                        "version": self.GENERATOR_VERSION,
                    },
                    "date": generation_time,
                },
            },
        }
        if severity:
            document["aggregate_severity"] = {
                "text": _SEVERITY_MAP.get(severity.lower(), severity)
            }
        return document

    def _build_product_tree(self, packages) -> dict[str, Any]:
        by_product: dict[str, list] = {}
        parsed_pkgs = []
        for pkg in packages:
            try:
                parsed = parse_nevra(pkg.nevra)
            except ValueError:
                logger.warning("Skipping unparseable NEVRA %s", pkg.nevra)
                continue
            product_name = pkg.product_name or "Rocky Linux"
            by_product.setdefault(product_name, []).append((pkg, parsed))
            parsed_pkgs.append((pkg, parsed, product_name))

        if not parsed_pkgs:
            return {"branches": []}

        product_name_branches = []
        platform_ids = []
        for product_name, items in sorted(by_product.items()):
            major = cpe_mod.rocky_major_from_product_name(product_name) or 0
            platform_id = f"rocky:linux:{major}" if major else "rocky:linux"
            platform_ids.append((platform_id, product_name, major))
            helper = {}
            if major:
                helper["cpe"] = cpe_mod.compute_rocky_platform_cpe(major)
            product_name_branches.append(
                {
                    "category": "product_name",
                    "name": product_name,
                    "product": {
                        "product_id": platform_id,
                        "name": product_name,
                        **(
                            {"product_identification_helper": helper}
                            if helper
                            else {}
                        ),
                    },
                }
            )

        by_arch: dict[str, list] = {}
        for pkg, parsed, _product_name in parsed_pkgs:
            by_arch.setdefault(parsed["arch"], []).append((pkg, parsed))

        arch_branches = []
        for arch, items in sorted(by_arch.items()):
            pkg_branches = []
            for pkg, parsed in items:
                helper = {
                    "purl": purl_mod.compute_purl(
                        parsed["name"],
                        parsed["version"],
                        parsed["release"],
                        parsed["arch"],
                        str(parsed.get("epoch") or "0"),
                    )
                }
                pkg_branches.append(
                    {
                        "category": "product_version",
                        "name": pkg.nevra,
                        "product": {
                            "product_id": pkg.nevra,
                            "name": pkg.nevra,
                            "product_identification_helper": helper,
                        },
                    }
                )
            arch_branches.append(
                {
                    "category": "architecture",
                    "name": arch,
                    "branches": pkg_branches,
                }
            )

        vendor_branches = [
            {
                "category": "product_family",
                "name": "Rocky Linux",
                "branches": product_name_branches,
            }
        ]
        vendor_branches.extend(arch_branches)

        relationships = []
        for pkg, parsed, product_name in parsed_pkgs:
            major = cpe_mod.rocky_major_from_product_name(product_name) or 0
            platform_id = f"rocky:linux:{major}" if major else "rocky:linux"
            combined = f"{platform_id}:{pkg.nevra}"
            relationships.append(
                {
                    "product_reference": pkg.nevra,
                    "relates_to_product_reference": platform_id,
                    "category": "default_component_of",
                    "full_product_name": {
                        "name": (
                            f"{pkg.nevra} as a component of {product_name}"
                        ),
                        "product_id": combined,
                    },
                }
            )

        return {
            "branches": [
                {
                    "category": "vendor",
                    "name": "Rocky Enterprise Software Foundation",
                    "branches": vendor_branches,
                }
            ],
            "relationships": relationships,
        }

    def _build_vulnerabilities(self, advisory, packages) -> list:
        vulns = []
        product_ids = []
        for pkg in packages:
            try:
                parse_nevra(pkg.nevra)
            except ValueError:
                continue
            major = cpe_mod.rocky_major_from_product_name(
                pkg.product_name or ""
            ) or 0
            platform_id = f"rocky:linux:{major}" if major else "rocky:linux"
            product_ids.append(f"{platform_id}:{pkg.nevra}")

        for cve_row in advisory.cves or []:
            cve = cve_row.cve
            notes = []
            if getattr(cve_row, "cwe", None):
                notes.append(
                    {
                        "category": "general",
                        "title": "CWE",
                        "text": get_cwe_name(cve_row.cwe) or cve_row.cwe,
                    }
                )
            vuln: dict[str, Any] = {
                "cve": cve,
                "product_status": {"fixed": sorted(set(product_ids))},
                "references": [
                    {
                        "category": "external",
                        "summary": cve,
                        "url": f"{attribution.CVE_URL_BASE}/{cve}",
                    }
                ],
            }
            if notes:
                vuln["notes"] = notes
            scores = []
            if getattr(cve_row, "cvss3_base_score", None) and getattr(
                cve_row, "cvss3_scoring_vector", None
            ):
                try:
                    base_score = float(cve_row.cvss3_base_score)
                except (TypeError, ValueError):
                    base_score = None
                vector = cve_row.cvss3_scoring_vector
                if base_score is not None and vector and vector != "UNKNOWN":
                    scores.append(
                        {
                            "products": sorted(set(product_ids)),
                            "cvss_v3": {
                                "version": "3.1",
                                "vectorString": vector,
                                "baseScore": base_score,
                                "baseSeverity": (
                                    _SEVERITY_MAP.get(
                                        (advisory.severity or "").lower(),
                                        "None",
                                    )
                                ),
                            },
                        }
                    )
            if scores:
                vuln["scores"] = scores
            remediations = [
                {
                    "category": "vendor_fix",
                    "details": (
                        f"Update packages listed in {advisory.name}."
                    ),
                    "product_ids": sorted(set(product_ids)),
                    "url": f"{attribution.CSAF_BASE_URL}/advisories/{advisory.name}",
                }
            ]
            vuln["remediations"] = remediations
            vulns.append(vuln)
        return vulns


def _iso(dt: Optional[datetime]) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def advisory_filename(advisory_name: str) -> str:
    return advisory_name.lower().replace(":", "_") + ".json"


def advisory_year(advisory_name: str) -> str:
    try:
        return advisory_name.split("-")[1].split(":")[0]
    except (IndexError, AttributeError):
        return "0000"
