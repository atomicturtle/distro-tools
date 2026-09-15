"""Sync NVD enrichment for CVE IDs already in Apollo.

Preferred (prototype on db1)::

    source ~/apollo/.env
    cd ~/apollo/distro-tools
    ENV=production DB_USER=apollo \\
      PYTHONPATH=. ~/apollo/venv/bin/python -m apollo.nvd.cli \\
      --from-vuls-db --only-missing

Falls back to NIST NVD API when ``--from-vuls-db`` is omitted
(requires ``NVD_API_KEY`` for useful rate limits).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import List, Optional

from tortoise import Tortoise

from common.info import Info
from common.database import Database


async def _run(args: argparse.Namespace) -> int:
    Info(os.environ.get("APOLLO_INFO_NAME", "apollo2"))
    db = Database(initialize=True)
    await db.init(["apollo.db"])

    if args.from_vuls_db:
        from apollo.nvd.vuls_sync import sync_from_vuls_db

        counts = await sync_from_vuls_db(
            db_path=args.vuls_db,
            helper=args.helper,
            limit=args.limit,
            only_missing=args.only_missing,
        )
    else:
        from apollo.nvd.sync import sync_known_cves

        counts = await sync_known_cves(
            limit=args.limit,
            only_missing=args.only_missing,
            only_missing_dates=args.only_missing_dates,
            api_key=args.api_key or os.environ.get("NVD_API_KEY"),
            sleep_seconds=args.sleep,
        )
    print(counts)
    await Tortoise.close_connections()
    return 0 if counts.get("errors", 0) == 0 else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--from-vuls-db",
        action="store_true",
        help="Import from local vuls2 BoltDB instead of NIST API",
    )
    parser.add_argument(
        "--vuls-db",
        default=os.environ.get("VULS_DB", "/var/lib/vuls/vuls.db"),
        help="Path to vuls.db (default: /var/lib/vuls/vuls.db)",
    )
    parser.add_argument(
        "--helper",
        default=os.environ.get(
            "VULSDB_NVD_EXPORT",
            os.path.join(
                os.path.dirname(__file__),
                "vulsdb_export",
                "vulsdb-nvd-export",
            ),
        ),
        help="Path to vulsdb-nvd-export binary",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max CVE IDs to fetch this run",
    )
    parser.add_argument(
        "--only-missing",
        action="store_true",
        help="Skip CVE IDs already present in nvd_cves",
    )
    parser.add_argument(
        "--only-missing-dates",
        action="store_true",
        help="Only NIST-refresh rows that already exist but lack published_at",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="NVD API key (NIST path only; default: NVD_API_KEY env)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=None,
        help="Seconds between NVD API requests (NIST path only)",
    )
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
