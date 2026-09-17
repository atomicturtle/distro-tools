"""Build RH-shaped CSAF track archives (tar.zst + sha256 + archive_latest)."""

from __future__ import annotations

import hashlib
import logging
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _maybe_sign(archive: Path) -> Optional[Path]:
    fingerprint = (
        os.environ.get("APOLLO_CSAF_GPG_FINGERPRINT")
        or os.environ.get("APOLLO_CSAF_GPG_KEY")
        or ""
    ).strip()
    if not fingerprint:
        return None
    asc = Path(str(archive) + ".asc")
    cmd = ["gpg", "--batch", "--yes"]
    cmd.extend(["--local-user", fingerprint])
    cmd.extend(
        ["--detach-sign", "--armor", "-o", str(asc), str(archive)]
    )
    subprocess.run(cmd, check=True)
    logger.info("Signed %s -> %s", archive.name, asc.name)
    return asc


def build_track_archive(track_dir: Path, track_name: str) -> Optional[Path]:
    """Archive year directories under a track into tar.zst + sidecars.

    Returns the archive path, or None if there is nothing to pack.
    """
    track_dir = Path(track_dir)
    if not track_dir.is_dir():
        return None

    year_dirs = sorted(
        p.name
        for p in track_dir.iterdir()
        if p.is_dir() and p.name.isdigit() and len(p.name) == 4
    )
    if not year_dirs:
        logger.warning("No year directories under %s; skipping archive", track_dir)
        return None

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    archive_name = f"csaf_{track_name}_{day}.tar.zst"
    archive_path = track_dir / archive_name

    # Replace same-day archive if re-run.
    if archive_path.exists():
        archive_path.unlink()

    # EL8 tar 1.30 has no --zstd; -I zstd works with the zstd CLI.
    cmd = [
        "tar",
        "-I",
        "zstd",
        "-cf",
        str(archive_path),
        "-C",
        str(track_dir),
        "--exclude=*.tar.zst",
        "--exclude=*.tar.zst.sha256",
        "--exclude=*.tar.zst.asc",
        "--exclude=archive_latest.txt",
        *year_dirs,
    ]
    # Also include index/changes/releases/deletions for a self-contained dump.
    for meta in ("index.txt", "changes.csv", "releases.csv", "deletions.csv"):
        if (track_dir / meta).is_file():
            cmd.append(meta)

    subprocess.run(cmd, check=True)
    digest = _sha256_file(archive_path)
    sha_path = Path(str(archive_path) + ".sha256")
    sha_path.write_text(f"{digest}  {archive_name}\n", encoding="utf-8")
    (track_dir / "archive_latest.txt").write_text(
        f"{archive_name}\n", encoding="utf-8"
    )
    _maybe_sign(archive_path)
    logger.info(
        "Wrote %s (%d years, sha256=%s…)",
        archive_path,
        len(year_dirs),
        digest[:12],
    )
    return archive_path


def build_provider_archives(tree_root: Path) -> dict:
    """Build archives for advisories/ and vex/ under a CSAF tree root."""
    root = Path(tree_root)
    results = {}
    for track in ("advisories", "vex"):
        path = build_track_archive(root / track, track)
        results[track] = str(path) if path else None
    return results
