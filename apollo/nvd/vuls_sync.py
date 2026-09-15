"""Import NVD enrichment from a local vuls2 ``vuls.db`` via vulsdb-nvd-export."""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable, Optional

from apollo.db import NvdCve
from apollo.nvd.sync import known_cve_ids, upsert_nvd_row


DEFAULT_VULS_DB = "/var/lib/vuls/vuls.db"
DEFAULT_HELPER = os.environ.get(
    "VULSDB_NVD_EXPORT",
    str(Path(__file__).resolve().parent / "vulsdb_export" / "vulsdb-nvd-export"),
)


def _parse_ts(raw: Any) -> Optional[datetime.datetime]:
    if raw is None:
        return None
    if isinstance(raw, datetime.datetime):
        return raw
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def row_from_export(obj: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Map one exporter NDJSON object to NvdCve upsert fields.

    Returns None when the CVE is missing from vuls.db or the helper errored.
    """
    if obj.get("missing") or obj.get("error"):
        return None
    cve_id = obj.get("cve_id")
    if not cve_id:
        return None
    refs = obj.get("refs")
    cpes = obj.get("cpes")
    return {
        "cve_id": cve_id,
        "description": obj.get("description"),
        "cvss_v2_score": obj.get("cvss_v2_score"),
        "cvss_v2_vector": obj.get("cvss_v2_vector"),
        "cvss_v3_score": obj.get("cvss_v3_score"),
        "cvss_v3_vector": obj.get("cvss_v3_vector"),
        "cvss_v4_score": obj.get("cvss_v4_score"),
        "cvss_v4_vector": obj.get("cvss_v4_vector"),
        "cwe": obj.get("cwe"),
        "refs": refs if refs else None,
        "epss_score": obj.get("epss_score"),
        "epss_percentile": obj.get("epss_percentile"),
        "exploit_maturity": obj.get("exploit_maturity"),
        "exploit_count": int(obj.get("exploit_count") or 0),
        "kev_listed": bool(obj.get("kev_listed")),
        "kev_date_added": _parse_ts(obj.get("kev_date_added")),
        "kev_due_date": _parse_ts(obj.get("kev_due_date")),
        "kev_ransomware": obj.get("kev_ransomware"),
        "cpes": cpes if cpes else None,
        "published_at": _parse_ts(obj.get("published_at")),
        "last_modified_at": _parse_ts(obj.get("last_modified_at")),
    }


async def sync_from_vuls_db(
    *,
    db_path: str = DEFAULT_VULS_DB,
    helper: str = DEFAULT_HELPER,
    limit: Optional[int] = None,
    only_missing: bool = False,
    cve_ids: Optional[Iterable[str]] = None,
) -> dict:
    """Pipe known CVE IDs through ``vulsdb-nvd-export`` and upsert rows."""
    if cve_ids is None:
        ids = await known_cve_ids()
    else:
        ids = sorted({c for c in cve_ids if c})

    if only_missing:
        have = set(await NvdCve.all().values_list("cve_id", flat=True))
        ids = [c for c in ids if c not in have]
    if limit is not None:
        ids = ids[:limit]

    counts = {
        "candidates": len(ids),
        "upserted": 0,
        "missing": 0,
        "errors": 0,
    }
    if not ids:
        return counts

    helper_path = Path(helper)
    if not helper_path.is_file():
        raise FileNotFoundError(
            f"vulsdb-nvd-export not found at {helper_path}; "
            "build apollo/nvd/vulsdb_export and scp the binary"
        )
    if not Path(db_path).is_file():
        raise FileNotFoundError(f"vuls.db not found at {db_path}")

    # Feed IDs from a tempfile so the OS streams stdin while we drain stdout
    # (writing the full list into a pipe before reading deadlocks).
    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="nvd-cve-ids-",
        suffix=".txt",
        delete=True,
    ) as idfile:
        for cve_id in ids:
            idfile.write(cve_id + "\n")
        idfile.flush()
        idfile.seek(0)

        proc = subprocess.Popen(
            [str(helper_path), "-db", db_path],
            stdin=idfile,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdout is not None

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                counts["errors"] += 1
                continue
            if obj.get("error"):
                counts["errors"] += 1
                continue
            if obj.get("missing"):
                counts["missing"] += 1
                continue
            fields = row_from_export(obj)
            if fields is None:
                counts["missing"] += 1
                continue
            await upsert_nvd_row(fields)
            counts["upserted"] += 1

        stderr = proc.stderr.read() if proc.stderr else ""
        rc = proc.wait()
        if rc != 0:
            raise RuntimeError(
                f"vulsdb-nvd-export exited {rc}: {stderr.strip()[:500]}"
            )
    return counts
