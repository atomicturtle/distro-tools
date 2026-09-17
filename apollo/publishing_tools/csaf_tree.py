"""Write a static CSAF provider tree for mirroring / scanner subscription.

Layout (RH-compatible under ``{out}`` or ``{out}/csaf/v2`` with ``--prefix``):

  provider-metadata.json
  advisories/
    index.txt
    changes.csv
    releases.csv
    deletions.csv
    {year}/rlsa-….json
  vex/
    index.txt
    changes.csv
    releases.csv
    deletions.csv
    {year}/cve-….json

Publish options (nginx, GitHub, object storage) are separate; this module only
materializes the on-disk tree.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

from tortoise import Tortoise

from apollo.db import Advisory, AdvisoryPackage, CveProductStatus, NvdCve
from apollo.exports.csaf_sa import RockySACSAFGenerator
from apollo.exports.csaf_vex import VexCSAFGenerator, entries_from_cve_statuses
from apollo.exports.provider import (
    advisory_relpath,
    index_txt,
    path_timestamp_csv,
    provider_metadata,
    vex_relpath,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("csaf_tree")


@dataclass
class TreeDocument:
    """One CSAF JSON document plus timestamps for changes/releases CSV."""

    relpath: str
    document: dict
    changed_at: object
    released_at: object


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _write_track(
    track_dir: Path,
    documents: Iterable[TreeDocument],
) -> list[str]:
    """Write JSON docs + index/changes/releases/deletions for one track."""
    docs = list(documents)
    relpaths = []
    changes_rows = []
    releases_rows = []

    for doc in docs:
        target = track_dir / doc.relpath
        _write_json(target, doc.document)
        relpaths.append(doc.relpath)
        changes_rows.append((doc.relpath, doc.changed_at))
        releases_rows.append((doc.relpath, doc.released_at))
        logger.info("Wrote %s", target)

    track_dir.mkdir(parents=True, exist_ok=True)
    (track_dir / "index.txt").write_text(index_txt(relpaths), encoding="utf-8")
    (track_dir / "changes.csv").write_text(
        path_timestamp_csv(changes_rows), encoding="utf-8"
    )
    (track_dir / "releases.csv").write_text(
        path_timestamp_csv(releases_rows), encoding="utf-8"
    )
    # No Apollo deletions yet; keep an empty RH-shaped file for aggregators.
    (track_dir / "deletions.csv").write_text("", encoding="utf-8")
    logger.info(
        "Wrote %s metadata (%d documents)", track_dir.name, len(relpaths)
    )
    return relpaths


def write_tree_documents(
    out_dir: str,
    *,
    advisories: Iterable[TreeDocument],
    vex_documents: Optional[Iterable[TreeDocument]] = None,
    base_url: Optional[str] = None,
    prefix: str = "",
) -> Path:
    """Materialize a CSAF provider tree from pre-built documents (no DB)."""
    root = Path(out_dir)
    if prefix:
        root = root / prefix.strip("/")
    root.mkdir(parents=True, exist_ok=True)

    adv_docs = list(advisories)
    vex_docs = list(vex_documents or [])

    adv_years = {doc.relpath.split("/", 1)[0] for doc in adv_docs if "/" in doc.relpath}
    vex_years = {doc.relpath.split("/", 1)[0] for doc in vex_docs if "/" in doc.relpath}

    _write_track(root / "advisories", adv_docs)
    if vex_docs or vex_documents is not None:
        _write_track(root / "vex", vex_docs)

    meta = provider_metadata(
        advisory_years=adv_years,
        vex_years=vex_years,
        base_url=base_url,
        last_updated=datetime.now(timezone.utc),
    )
    _write_json(root / "provider-metadata.json", meta)
    logger.info("Wrote provider-metadata.json under %s", root)
    return root


async def load_advisory_documents() -> list[TreeDocument]:
    generator = RockySACSAFGenerator()
    advisories = (
        await Advisory.filter(published_at__not_isnull=True)
        .prefetch_related("cves", "fixes", "packages", "red_hat_advisory")
        .order_by("name")
    )
    out = []
    for advisory in advisories:
        released = advisory.rocky_published_at or advisory.published_at
        changed = advisory.updated_at or released
        out.append(
            TreeDocument(
                relpath=advisory_relpath(advisory.name),
                document=generator.generate(advisory),
                changed_at=changed,
                released_at=released,
            )
        )
    return out


async def load_vex_documents() -> list[TreeDocument]:
    """Load all CVE VEX documents with batched DB reads (no per-CVE queries)."""
    generator = VexCSAFGenerator()

    all_rows = await CveProductStatus.all().prefetch_related(
        "supported_product"
    )
    if not all_rows:
        return []

    by_cve: dict[str, list] = {}
    advisory_ids: set[int] = set()
    for row in all_rows:
        if not row.cve:
            continue
        by_cve.setdefault(row.cve, []).append(row)
        if row.status == "fixed" and row.advisory_id:
            advisory_ids.add(row.advisory_id)

    packages_by_advisory_id: dict[int, list] = {}
    if advisory_ids:
        packages = await AdvisoryPackage.filter(
            advisory_id__in=list(advisory_ids)
        )
        for pkg in packages:
            packages_by_advisory_id.setdefault(pkg.advisory_id, []).append(pkg)

    nvd_by_cve = {}
    nvd_rows = await NvdCve.filter(cve_id__in=list(by_cve.keys()))
    for nvd in nvd_rows:
        nvd_by_cve[nvd.cve_id] = nvd

    cve_rows_by_adv: dict[int, list] = {}
    if advisory_ids:
        advisories = await Advisory.filter(
            id__in=list(advisory_ids)
        ).prefetch_related("cves")
        for adv in advisories:
            cve_rows_by_adv[adv.id] = list(adv.cves)

    out = []
    for cve in sorted(by_cve.keys()):
        rows = by_cve[cve]
        entries = entries_from_cve_statuses(rows, packages_by_advisory_id)
        if not entries:
            continue

        nvd = nvd_by_cve.get(cve)
        description = nvd.description if nvd else None
        scores = [nvd] if nvd else []
        for row in rows:
            if not row.advisory_id:
                continue
            for cve_row in cve_rows_by_adv.get(row.advisory_id, []):
                if cve_row.cve == cve:
                    scores.append(cve_row)

        doc = generator.generate(
            cve, entries, scores=scores, description=description
        )
        changed = max(
            (
                row.updated_at or row.created_at
                for row in rows
                if row.updated_at or row.created_at
            ),
            default=datetime.now(timezone.utc),
        )
        released = min(
            (row.created_at for row in rows if row.created_at),
            default=changed,
        )
        out.append(
            TreeDocument(
                relpath=vex_relpath(cve),
                document=doc,
                changed_at=changed,
                released_at=released,
            )
        )
    logger.info("Prepared %d VEX documents", len(out))
    return out


async def write_csaf_tree(
    out_dir: str,
    db_url: Optional[str] = None,
    *,
    include_vex: bool = True,
    base_url: Optional[str] = None,
    prefix: str = "",
    close_db: bool = True,
) -> Path:
    """Load Apollo DB and write a full CSAF provider tree."""
    owns_db = False
    if db_url:
        await Tortoise.init(
            db_url=db_url, modules={"models": ["apollo.db"]}
        )
        owns_db = True

    try:
        advisories = await load_advisory_documents()
        vex_docs = await load_vex_documents() if include_vex else []
        return write_tree_documents(
            out_dir,
            advisories=advisories,
            vex_documents=vex_docs if include_vex else None,
            base_url=base_url,
            prefix=prefix,
        )
    finally:
        if owns_db and close_db:
            await Tortoise.close_connections()


def main():
    parser = argparse.ArgumentParser(
        description="Write Apollo CSAF provider tree (SA + VEX)"
    )
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument(
        "--db-url",
        default=os.environ.get("APOLLO_DB_URL"),
        help="Tortoise DB URL (or APOLLO_DB_URL)",
    )
    parser.add_argument(
        "--prefix",
        default="",
        help="Optional path prefix under --out (e.g. csaf/v2)",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=(
            "Canonical public base URL for provider-metadata directory_url "
            "entries (default: Apollo CSAF API base)"
        ),
    )
    parser.add_argument(
        "--no-vex",
        action="store_true",
        help="Write advisories track only",
    )
    args = parser.parse_args()
    if not args.db_url:
        parser.error("--db-url or APOLLO_DB_URL is required")
    root = asyncio.run(
        write_csaf_tree(
            args.out,
            args.db_url,
            include_vex=not args.no_vex,
            base_url=args.base_url,
            prefix=args.prefix,
        )
    )
    print(root)


if __name__ == "__main__":
    main()
