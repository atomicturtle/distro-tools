"""
NVRA matching helpers for RH → Rocky advisory cloning.

Matching order:
1. Exact cleaned NVRA (handled by callers via dict lookup) **plus**
   ``lowest_compatible_pkgs``. Cleaning strips ``.el10_0`` / ``.el8_10``
   and ``.module+el8.Y.0+build``, so several Rocky rebuilds share a key.
   Callers must keep **one** XML package per (name, arch): the lowest EVR
   that is still >= the RH fixed EVR on the same dist major. Attaching
   every module stream makes clone fidelity report the newest (el8.10)
   even when vault still has the shipped el8.5 rebuild.
   Point-release tags on the same major may differ: Rocky ships RH
   ``el8_6`` openssl as ``el8_10`` (RLSA-2024:7848).
2. Prefix match (Rocky .rocky.* rebuild suffix on the same NVR), with a
   '.' boundary so release ``80`` does not match ``8``, plus EVR >= when
   package XML is available.
3. EVR >= : same name+arch+**version** and dist **major**, Rocky release
   at least the RH fixed release. A later upstream version (``openssl``
   1.1.1k → 3.0.1, firefox 128 → 140) is a later RLSA, not this one.
   If both releases carry a point-release tag (``el10_0`` vs ``el10_2``,
   ``el9_7`` vs ``el9_8``) and the dist-stripped release differs, do not
   alias: that maps kernel ``55.18.1.el10_0`` onto current ``211.el10_2``.
   Same stripped NVR with a later Rocky ``el8_10`` tag is the exact-key
   path (openssl ``el8_6`` → ``el8_10``). Unstamped Rocky ``el9`` may
   still satisfy RH ``el9_2``.

(3) covers Rocky rebuilds of the same NVR with a newer release string,
which the prefix matcher cannot see.
"""

from __future__ import annotations

import re
from xml.etree import ElementTree as ET

from apollo.rpm_helpers import evr_gte, label_compare, parse_dist_version, parse_nevra

COMMON_NS = "http://linux.duke.edu/metadata/common"
_DIST_TAG_RE = re.compile(r"\.el\d+(?:_\d+|)")
_MODULE_DIST_RE = re.compile(r"\.module.+$")


def _dist_compatible(rh_release: str, rocky_release: str) -> bool:
    """Same RHEL major. Point-release tags on that major may differ.

    Rocky rebuilds RH ``el8_6`` openssl as ``el8_10``. Later upstream
    versions are rejected by the EVR version pin, not by dist minor.
    Unparseable majors stay compatible so older tagging still clones.
    """
    rh = parse_dist_version(rh_release)
    rocky = parse_dist_version(rocky_release)
    if rh["major"] is None or rocky["major"] is None:
        return True
    return rh["major"] == rocky["major"]


def _release_without_dist(release: str) -> str:
    return _MODULE_DIST_RE.sub("", _DIST_TAG_RE.sub("", release))


def _evr_alias_point_release_ok(rh_release: str, rocky_release: str) -> bool:
    """True when EVR>= may jump from RH's point-release to Rocky's.

    Kernel ``55.18.1.el10_0`` must not alias ``211.16.1.el10_2`` just
    because both are ``6.12.0`` on EL10. Unstamped Rocky ``el9`` (no
    minor) may still satisfy RH ``el9_2``. Same stripped release with a
    later ``el8_10`` tag is allowed here but normally hits the exact key.
    """
    rh = parse_dist_version(rh_release)
    rocky = parse_dist_version(rocky_release)
    if rh["minor"] is None or rocky["minor"] is None:
        return True
    if rh["minor"] == rocky["minor"]:
        return True
    return _release_without_dist(rh_release) == _release_without_dist(rocky_release)


def pkg_dist_compatible_with_rh(rh_nevra: str, pkg: ET.Element) -> bool:
    """True when Rocky package XML dist is compatible with the RH NEVRA.

    Callers must use this on exact cleaned-key hits. Unparseable RH NEVRA
    or package XML without a release is not a match.
    """
    try:
        adv = parse_nevra(rh_nevra)
    except ValueError:
        return False
    evr = _pkg_evr(pkg)
    if evr is None:
        return False
    return _dist_compatible(adv["release"], evr[2])


def _pkg_name_arch(pkg: ET.Element) -> tuple[str, str] | None:
    name_el = pkg.find(f"{{{COMMON_NS}}}name")
    arch_el = pkg.find(f"{{{COMMON_NS}}}arch")
    if name_el is None or arch_el is None or not name_el.text or not arch_el.text:
        return None
    return (name_el.text, arch_el.text)


def lowest_compatible_pkgs(
    rh_nevra: str,
    pkgs: list[ET.Element],
) -> list[ET.Element]:
    """One Rocky XML package per (name, arch): lowest EVR >= RH.

    Cleaning collapses ``python2-attrs-17.4.0-10.module+el8.5.0+…`` and
    ``…module+el8.10.0+…`` onto the same key. Dist-major compatibility
    alone would attach both; fidelity then reports the newer stream.
    """
    try:
        adv = parse_nevra(rh_nevra)
    except ValueError:
        return []

    best: dict[tuple[str, str], tuple[tuple[str, str, str], ET.Element]] = {}
    for pkg in pkgs:
        if not pkg_dist_compatible_with_rh(rh_nevra, pkg):
            continue
        evr = _pkg_evr(pkg)
        if evr is None:
            continue
        if evr[1] != adv["version"]:
            continue
        if not evr_gte(
            evr[0], evr[1], evr[2],
            adv["epoch"], adv["version"], adv["release"],
        ):
            continue
        key = _pkg_name_arch(pkg)
        if key is None:
            continue
        prev = best.get(key)
        if prev is None or label_compare(
            evr[0], evr[1], evr[2], prev[0][0], prev[0][1], prev[0][2]
        ) < 0:
            best[key] = (evr, pkg)
    return [item[1] for item in best.values()]


def _pkg_evr(pkg: ET.Element) -> tuple[str, str, str] | None:
    version_tree = pkg.find(f"{{{COMMON_NS}}}version")
    if version_tree is None:
        return None
    ver = version_tree.attrib.get("ver")
    rel = version_tree.attrib.get("rel")
    if ver is None or rel is None:
        return None
    return (
        version_tree.attrib.get("epoch", "0"),
        ver,
        rel,
    )


def _is_rebuild_prefix(pkg_nvr: str, cleaned_nvr: str) -> bool:
    """
    True when pkg_nvr is cleaned_nvr or cleaned_nvr plus a dotted suffix.

    Requires a '.' boundary so release ``80`` does not prefix-match ``8``.
    """
    if pkg_nvr == cleaned_nvr:
        return True
    return pkg_nvr.startswith(cleaned_nvr + ".")


def find_nvra_alias(
    advisory_cleaned: str,
    name_pkgs: list[str],
    *,
    advisory_nevra: str | None = None,
    raw_pkg_nvras: dict[str, list] | None = None,
) -> str | None:
    """
    Map a cleaned advisory NVRA to a cleaned repo NVRA.

    Prefer a rebuild-prefix (.rocky) hit that still satisfies EVR >= when
    package XML is available. Otherwise pick the lowest Rocky EVR that is
    still >= the RH fixed EVR (same **version**, arch, and dist major).
    """
    cleaned_parts = advisory_cleaned.rsplit(".", 1)
    if len(cleaned_parts) != 2:
        return None
    cleaned_nvr, cleaned_arch = cleaned_parts

    adv = None
    if advisory_nevra:
        try:
            adv = parse_nevra(advisory_nevra)
        except ValueError:
            adv = None

    for pkg_nvra in name_pkgs:
        pkg_parts = pkg_nvra.rsplit(".", 1)
        if len(pkg_parts) != 2:
            continue
        pkg_nvr, pkg_arch = pkg_parts
        if pkg_arch != cleaned_arch:
            continue
        if not _is_rebuild_prefix(pkg_nvr, cleaned_nvr):
            continue
        # When we can, reject rebuild prefixes that are still older than RH
        # fixed or that jumped to another dist major.
        if adv is not None and raw_pkg_nvras:
            pkgs = raw_pkg_nvras.get(pkg_nvra) or []
            if pkgs:
                evr = _pkg_evr(pkgs[0])
                if evr is not None:
                    if not _dist_compatible(adv["release"], evr[2]):
                        continue
                    if not evr_gte(
                        evr[0], evr[1], evr[2],
                        adv["epoch"], adv["version"], adv["release"],
                    ):
                        continue
        return pkg_nvra

    if adv is None or not raw_pkg_nvras:
        return None

    candidates: list[tuple[str, str, str, str]] = []
    for pkg_nvra in name_pkgs:
        pkg_parts = pkg_nvra.rsplit(".", 1)
        if len(pkg_parts) != 2:
            continue
        _, pkg_arch = pkg_parts
        if pkg_arch != cleaned_arch:
            continue

        pkgs = raw_pkg_nvras.get(pkg_nvra) or []
        if not pkgs:
            continue
        evr = _pkg_evr(pkgs[0])
        if evr is None:
            continue
        epoch, ver, rel = evr
        if ver != adv["version"]:
            continue
        if not _dist_compatible(adv["release"], rel):
            continue
        if not _evr_alias_point_release_ok(adv["release"], rel):
            continue
        if evr_gte(epoch, ver, rel, adv["epoch"], adv["version"], adv["release"]):
            candidates.append((epoch, ver, rel, pkg_nvra))

    if not candidates:
        return None

    # Lowest satisfying Rocky EVR (closest fixed-in package).
    best = candidates[0]
    for cand in candidates[1:]:
        if label_compare(cand[0], cand[1], cand[2], best[0], best[1], best[2]) < 0:
            best = cand
    return best[3]
