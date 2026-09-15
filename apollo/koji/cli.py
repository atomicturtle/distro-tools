"""Backfill Rocky Koji completion times onto cloned advisories.

    source ~/apollo/.env
    cd ~/apollo/distro-tools
    ENV=production DB_USER=apollo \\
      PYTHONPATH=. ~/apollo/venv/bin/python -m apollo.koji.cli \\
      --name RLSA-2026:9693
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

    from apollo.koji.sync import sync_rocky_published_at

    counts = await sync_rocky_published_at(
        name=args.name,
        limit=args.limit,
        only_missing=not args.refresh,
        sleep_seconds=args.sleep,
        hub=args.hub,
    )
    print(counts)
    await Tortoise.close_connections()
    return 0 if counts.get("errors", 0) == 0 else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", help="Single advisory name (e.g. RLSA-2026:9693)")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Re-query Koji even when rocky_published_at is already set",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.05,
        help="Seconds between Koji XML-RPC calls",
    )
    parser.add_argument(
        "--hub",
        default=os.environ.get("KOJI_HUB"),
        help="Koji hub URL (default: https://koji.rockylinux.org/kojihub)",
    )
    args = parser.parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
