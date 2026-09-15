"""Map Apollo advisory NEVRAs to Koji source NVRs."""

from __future__ import annotations

from typing import Iterable, Optional

from apollo.rpm_helpers import parse_nevra


def nvr_from_nevra(nevra: str) -> Optional[tuple[str, str]]:
    """Return ``(nvr, arch)`` or None if the NEVRA cannot be parsed."""
    try:
        parsed = parse_nevra(nevra)
    except ValueError:
        return None
    nvr = f"{parsed['name']}-{parsed['version']}-{parsed['release']}"
    return nvr, parsed["arch"]


def source_nvrs_from_nevras(nevras: Iterable[str]) -> list[str]:
    """Prefer ``.src`` NEVRAs (Koji build NVR). Else unique binary NVRs."""
    src: set[str] = set()
    binaries: set[str] = set()
    for nevra in nevras:
        parsed = nvr_from_nevra(nevra)
        if parsed is None:
            continue
        nvr, arch = parsed
        if arch == "src":
            src.add(nvr)
        else:
            binaries.add(nvr)
    return sorted(src if src else binaries)


def rpm_nvras_from_nevras(nevras: Iterable[str]) -> list[str]:
    """Binary N-V-R.arch keys for ``getRPM`` when no ``.src`` row exists."""
    out: set[str] = set()
    for nevra in nevras:
        parsed = nvr_from_nevra(nevra)
        if parsed is None:
            continue
        nvr, arch = parsed
        if arch == "src":
            continue
        out.add(f"{nvr}.{arch}")
    return sorted(out)
