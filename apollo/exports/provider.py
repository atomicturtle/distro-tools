"""CSAF 2.0 provider-metadata, index.txt, and changes/releases CSV helpers.

Path layout matches Red Hat's browseable CSAF tree:

  {root}/provider-metadata.json
  {root}/advisories/index.txt
  {root}/advisories/changes.csv
  {root}/advisories/releases.csv
  {root}/advisories/deletions.csv
  {root}/advisories/{year}/{id}.json
  {root}/vex/… (same shape)
"""

from __future__ import annotations

import csv
import io
import os
from datetime import datetime, timezone
from typing import Iterable, Optional, Sequence

from apollo.exports import attribution
from apollo.exports.csaf_sa import advisory_filename, advisory_year


def vex_filename(cve_id: str) -> str:
    return f"{cve_id.lower()}.json"


def vex_year(cve_id: str) -> str:
    parts = (cve_id or "").split("-")
    if len(parts) >= 2 and parts[1].isdigit():
        return parts[1]
    return "0000"


def advisory_relpath(advisory_name: str) -> str:
    """Path relative to the advisories/ track directory."""
    return f"{advisory_year(advisory_name)}/{advisory_filename(advisory_name)}"


def vex_relpath(cve_id: str) -> str:
    """Path relative to the vex/ track directory."""
    return f"{vex_year(cve_id)}/{vex_filename(cve_id)}"


def _iso(ts) -> str:
    if ts is None:
        ts = datetime.now(timezone.utc)
    if isinstance(ts, str):
        return ts
    if getattr(ts, "tzinfo", None) is None and hasattr(ts, "replace"):
        ts = ts.replace(tzinfo=timezone.utc)
    if hasattr(ts, "astimezone"):
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def index_txt(relative_paths: Iterable[str]) -> str:
    """RH/CEM-style index.txt: one relative path per line, trailing newline."""
    lines = sorted({p.strip() for p in relative_paths if p and p.strip()})
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def path_timestamp_csv(rows: Sequence[tuple[str, object]]) -> str:
    """RH-style CSV with columns path,timestamp (no header; path ends in .json).

    Red Hat's changes.csv / releases.csv / deletions.csv are consumed by
    Apollo's own RH poller as ``path -> timestamp`` without a header row.
    """
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    for path, ts in sorted(rows, key=lambda row: row[0]):
        if not path or not path.endswith(".json"):
            continue
        writer.writerow([path, _iso(ts)])
    return buf.getvalue()


def changes_csv_rows(advisories: Iterable) -> str:
    """API-oriented changes.csv (with header) for /api/v3/csaf/advisories/changes.csv."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["path", "timestamp"])
    rows = []
    for advisory in advisories:
        name = advisory.name if hasattr(advisory, "name") else advisory["name"]
        ts = (
            getattr(advisory, "updated_at", None)
            or getattr(advisory, "rocky_published_at", None)
            or getattr(advisory, "published_at", None)
        )
        if isinstance(advisory, dict):
            ts = advisory.get("updated_at") or advisory.get("published_at")
        rows.append((f"advisories/{advisory_relpath(name)}", ts))
    for path, ts in sorted(rows, key=lambda row: row[0]):
        writer.writerow([path, _iso(ts)])
    return buf.getvalue()


def advisory_index(advisories: Iterable) -> list:
    """Return a lightweight CSAF advisory index list for the HTTP API."""
    out = []
    for advisory in advisories:
        name = advisory.name if hasattr(advisory, "name") else advisory["name"]
        out.append(
            {
                "id": name,
                "url": f"{attribution.CSAF_BASE_URL}/advisories/{name}",
                "path": f"advisories/{advisory_relpath(name)}",
            }
        )
    out.sort(key=lambda row: row["id"])
    return out


def provider_metadata(
    *,
    last_updated: Optional[datetime] = None,
    advisory_years: Optional[Iterable[str]] = None,
    vex_years: Optional[Iterable[str]] = None,
    base_url: Optional[str] = None,
) -> dict:
    """Build CSAF 2.0 provider-metadata.json for Rocky Linux Apollo."""
    base = (base_url or attribution.CSAF_BASE_URL).rstrip("/")
    updated = last_updated or datetime.now(timezone.utc)
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)

    distributions = [
        {
            "directory_url": f"{base}/advisories/",
            "summary": "Rocky Linux Security Advisories (CSAF SA)",
        },
        {
            "directory_url": f"{base}/vex/",
            "summary": "Rocky Linux CSAF VEX documents",
        },
    ]
    for year in sorted(set(advisory_years or [])):
        distributions.append(
            {
                "directory_url": f"{base}/advisories/{year}/",
                "summary": f"Rocky Linux CSAF SA documents for {year}",
            }
        )
    for year in sorted(set(vex_years or [])):
        distributions.append(
            {
                "directory_url": f"{base}/vex/{year}/",
                "summary": f"Rocky Linux CSAF VEX documents for {year}",
            }
        )

    public_keys = []
    fingerprint = (
        os.environ.get("APOLLO_CSAF_GPG_FINGERPRINT")
        or os.environ.get("APOLLO_CSAF_GPG_KEY")
        or ""
    ).strip()
    if fingerprint:
        public_keys.append(
            {
                "fingerprint": fingerprint.replace(" ", ""),
                "url": os.environ.get(
                    "APOLLO_CSAF_GPG_PUBLIC_URL",
                    f"{base}/openpgp.asc",
                ),
            }
        )

    return {
        "canonical_url": f"{base}/provider-metadata.json",
        "last_updated": updated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "list_on_CSAF_providers": True,
        "metadata_version": "2.0",
        "mirror_on_CSAF_aggregators": False,
        "public_openpgp_keys": public_keys,
        "publisher": attribution.PUBLISHER,
        "role": "csaf_publisher",
        "distributions": distributions,
    }
