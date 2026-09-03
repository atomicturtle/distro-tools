"""Sync NVD data for CVE IDs already in Apollo.

Usage (on db1)::

    source ~/apollo/.env
    cd ~/apollo/distro-tools
    PYTHONPATH=. ~/apollo/venv/bin/python -m apollo.nvd.cli \\
      --only-missing --limit 50

Requires ``NVD_API_KEY`` for useful rate limits (optional but recommended).
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

    from apollo.nvd.sync import sync_known_cves

    counts = await sync_known_cves(
        limit=args.limit,
        only_missing=args.only_missing,
        api_key=args.api_key or os.environ.get("NVD_API_KEY"),
        sleep_seconds=args.sleep,
    )
    print(counts)
    await Tortoise.close_connections()
    return 0 if counts.get("errors", 0) == 0 else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
        "--api-key",
        default=None,
        help="NVD API key (default: NVD_API_KEY env)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=None,
        help="Seconds between NVD requests",
    )
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
