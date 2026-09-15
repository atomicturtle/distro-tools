"""Fill ``advisories.rocky_published_at`` from Rocky Koji build completion."""

from __future__ import annotations

import time
from typing import Any, Optional

from apollo.db import Advisory
from apollo.koji.client import KojiClient
from apollo.koji.nvr import rpm_nvras_from_nevras, source_nvrs_from_nevras


def _nevras(advisory: Advisory) -> list[str]:
    return [pkg.nevra for pkg in advisory.packages if getattr(pkg, "nevra", None)]


def lookup_completion(
    client: KojiClient,
    nevras: list[str],
    cache: dict[str, Optional[Any]],
    sleep_seconds: float = 0.05,
) -> Optional[Any]:
    times = []
    for nvr in source_nvrs_from_nevras(nevras):
        if nvr not in cache:
            cache[nvr] = client.completion_for_nvr(nvr)
            if sleep_seconds:
                time.sleep(sleep_seconds)
        stamp = cache[nvr]
        if stamp is not None:
            times.append(stamp)
    # Use the latest completion: modular advisories often reuse older
    # companion builds; min() made "Rocky published" predate the fix NVR.
    if times:
        return max(times)
    for nvra in rpm_nvras_from_nevras(nevras)[:4]:
        key = f"rpm:{nvra}"
        if key not in cache:
            cache[key] = client.completion_for_rpm(nvra)
            if sleep_seconds:
                time.sleep(sleep_seconds)
        stamp = cache[key]
        if stamp is not None:
            times.append(stamp)
    if times:
        return max(times)
    return None


async def sync_rocky_published_at(
    *,
    name: Optional[str] = None,
    limit: Optional[int] = None,
    only_missing: bool = True,
    sleep_seconds: float = 0.05,
    hub: Optional[str] = None,
) -> dict[str, int]:
    query = Advisory.all()
    if name:
        query = query.filter(name=name)
    if only_missing:
        query = query.filter(rocky_published_at=None)
    query = query.order_by("-published_at")
    if limit is not None:
        query = query.limit(limit)

    ids = await query.values_list("id", flat=True)
    client = KojiClient(hub=hub)
    cache: dict[str, Optional[Any]] = {}
    counts = {"candidates": 0, "updated": 0, "missing": 0, "errors": 0}

    batch_size = 25
    for offset in range(0, len(ids), batch_size):
        batch_ids = ids[offset:offset + batch_size]
        advisories = await Advisory.filter(id__in=batch_ids).prefetch_related(
            "packages"
        )
        by_id = {advisory.id: advisory for advisory in advisories}
        for advisory_id in batch_ids:
            advisory = by_id.get(advisory_id)
            if advisory is None:
                continue
            counts["candidates"] += 1
            try:
                stamp = lookup_completion(
                    client,
                    _nevras(advisory),
                    cache,
                    sleep_seconds=sleep_seconds,
                )
            except Exception:
                counts["errors"] += 1
                continue
            if stamp is None:
                counts["missing"] += 1
                continue
            advisory.rocky_published_at = stamp
            await advisory.save(update_fields=["rocky_published_at"])
            counts["updated"] += 1
    return counts
