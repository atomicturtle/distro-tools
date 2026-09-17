"""Package URL (purl) computation for CSAF product_identification_helper.

Format: ``pkg:rpm/rockylinux/{name}@{version}-{release}?arch={arch}[&epoch={epoch}]``

Adapted from CEM ``publication/purl.py`` at CEM_BASELINE tip; namespace is
``rockylinux`` instead of ``ciq``.
"""

import logging
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)

PURL_NAMESPACE = "rockylinux"

VALID_RPM_ARCHES = frozenset({
    "x86_64",
    "i686",
    "i386",
    "aarch64",
    "ppc64le",
    "s390x",
    "riscv64",
    "noarch",
    "src",
})


def compute_purl(
    name: str,
    version: str,
    release: str,
    arch: str,
    epoch: str = "0",
) -> str:
    if arch not in VALID_RPM_ARCHES:
        logger.warning(
            "Unexpected arch %r for package %s; purl may be invalid",
            arch,
            name,
        )

    qualifiers = [f"arch={quote(arch, safe='')}"]
    if epoch and epoch != "0":
        qualifiers.append(f"epoch={quote(epoch, safe='')}")
    qs = "&".join(qualifiers)
    return (
        f"pkg:rpm/{PURL_NAMESPACE}/{quote(name, safe='')}@"
        f"{version}-{release}?{qs}"
    )


def purl_from_nevra(nevra: str) -> Optional[str]:
    """Parse NEVRA and return a purl, or None if unparseable.

    Accepts ``name-epoch:version-release.arch`` or ``name-version-release.arch``.
    """
    module_sep = nevra.find("::")
    if module_sep != -1:
        nevra = nevra[:module_sep]

    arch_dot = nevra.rfind(".")
    if arch_dot == -1:
        return None
    arch = nevra[arch_dot + 1 :]
    name_epoch_ver_rel = nevra[:arch_dot]

    rel_dash = name_epoch_ver_rel.rfind("-")
    if rel_dash == -1:
        return None
    release = name_epoch_ver_rel[rel_dash + 1 :]
    name_epoch_ver = name_epoch_ver_rel[:rel_dash]

    epoch_colon = name_epoch_ver.find(":")
    if epoch_colon != -1:
        ver_dash = name_epoch_ver.rfind("-", 0, epoch_colon)
        if ver_dash == -1:
            return None
        name = name_epoch_ver[:ver_dash]
        epoch = name_epoch_ver[ver_dash + 1 : epoch_colon]
        version = name_epoch_ver[epoch_colon + 1 :]
    else:
        ver_dash = name_epoch_ver.rfind("-")
        if ver_dash == -1:
            return None
        name = name_epoch_ver[:ver_dash]
        epoch = "0"
        version = name_epoch_ver[ver_dash + 1 :]

    if not all([name, version, release, arch]):
        return None

    return compute_purl(name, version, release, arch, epoch)
