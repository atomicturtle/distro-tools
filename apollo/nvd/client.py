"""NVD CVE API client and parsers (NIST NVD 2.0)."""

from __future__ import annotations

import datetime
import os
from typing import Any, Optional

import aiohttp

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdApiError(Exception):
    pass


def _metric_score_vector(metrics: dict, keys: list[str]) -> tuple[Optional[str], Optional[str]]:
    for key in keys:
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer Primary over Secondary when present.
        primary = None
        for entry in entries:
            if entry.get("type") == "Primary":
                primary = entry
                break
        entry = primary or entries[0]
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        vector = data.get("vectorString")
        return (
            str(score) if score is not None else None,
            vector,
        )
    return None, None


def parse_nvd_vulnerability(vuln: dict) -> dict[str, Any]:
    """Map one NVD 2.0 ``vulnerabilities[]`` item to upsert fields."""
    cve = vuln.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        raise NvdApiError("NVD vulnerability missing cve.id")

    description = None
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            description = desc.get("value")
            break
    if description is None and cve.get("descriptions"):
        description = cve["descriptions"][0].get("value")

    metrics = cve.get("metrics") or {}
    cvss_v2_score, cvss_v2_vector = _metric_score_vector(
        metrics, ["cvssMetricV2"]
    )
    cvss_v3_score, cvss_v3_vector = _metric_score_vector(
        metrics, ["cvssMetricV31", "cvssMetricV30"]
    )
    cvss_v4_score, cvss_v4_vector = _metric_score_vector(
        metrics, ["cvssMetricV40"]
    )

    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if value and value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    references: list[dict[str, Any]] = []
    for ref in cve.get("references") or []:
        url = ref.get("url")
        if not url:
            continue
        references.append(
            {
                "url": url,
                "source": ref.get("source"),
                "tags": ref.get("tags") or [],
            }
        )

    published = cve.get("published")
    modified = cve.get("lastModified")

    def _parse_ts(raw: Optional[str]) -> Optional[datetime.datetime]:
        if not raw:
            return None
        # NVD uses ISO-8601 with optional fractional seconds.
        try:
            return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_v2_score": cvss_v2_score,
        "cvss_v2_vector": cvss_v2_vector,
        "cvss_v3_score": cvss_v3_score,
        "cvss_v3_vector": cvss_v3_vector,
        "cvss_v4_score": cvss_v4_score,
        "cvss_v4_vector": cvss_v4_vector,
        "cwe": ", ".join(cwes) if cwes else None,
        "refs": references or None,
        "published_at": _parse_ts(published),
        "last_modified_at": _parse_ts(modified),
    }


async def fetch_nvd_cve(
    session: aiohttp.ClientSession,
    cve_id: str,
    *,
    api_key: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Fetch one CVE from NVD. Returns None when NVD has no match."""
    headers = {}
    key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key

    params = {"cveId": cve_id}
    async with session.get(NVD_CVE_API, params=params, headers=headers) as resp:
        if resp.status == 404:
            return None
        if resp.status != 200:
            body = await resp.text()
            raise NvdApiError(
                f"NVD HTTP {resp.status} for {cve_id}: {body[:200]}"
            )
        payload = await resp.json()

    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    return parse_nvd_vulnerability(vulns[0])
