"""Rocky Linux publisher metadata for export formats.

Adapted from CEM publication/attribution.py with Rocky branding.
RH source-credit helpers are inlined so this package does not depend on
apollo.server (avoids a Bazel cycle with route modules).
"""

import os
from typing import Optional

SOURCE_VENDOR = "Red Hat"
LICENSE_NAME = "CC BY 4.0"
SOURCE_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
RED_HAT_ERRATA_BASE_URL = "https://access.redhat.com/errata"

COMPANY_NAME = "Rocky Enterprise Software Foundation"
COMPANY_LEGAL_NAME = "Rocky Enterprise Software Foundation"
FROMSTR = "releng@rockylinux.org"
UI_ERRATA_BASE = "https://errata.rockylinux.org"
CVE_URL_BASE = "https://access.redhat.com/security/cve"

# Override on research hosts so provider-metadata directory_url points at the
# static tree (e.g. https://apollo.research.atomicorp.com/csaf/v2).
CSAF_BASE_URL = os.environ.get(
    "APOLLO_CSAF_BASE_URL",
    "https://apollo.build.resf.org/api/v3/csaf",
).rstrip("/")
OPENVEX_BASE_URL = os.environ.get(
    "APOLLO_OPENVEX_BASE_URL",
    "https://apollo.build.resf.org/api/v3/vex",
).rstrip("/")

PUBLISHER = {
    "category": "vendor",
    "name": "Rocky Enterprise Software Foundation",
    "namespace": "https://rockylinux.org",
    "issuing_authority": "Rocky Linux Security Team",
}


def red_hat_errata_url(red_hat_advisory_name: str) -> str:
    return f"{RED_HAT_ERRATA_BASE_URL}/{red_hat_advisory_name}"


def rights_line(year: int, red_hat_advisory_name: Optional[str] = None) -> str:
    if red_hat_advisory_name:
        url = red_hat_errata_url(red_hat_advisory_name)
        return (
            f"Copyright {year} {COMPANY_NAME}. "
            f"Advisory content derived from {SOURCE_VENDOR} "
            f"{red_hat_advisory_name} ({url}), © {SOURCE_VENDOR}, Inc., "
            f"used under {LICENSE_NAME} ({SOURCE_LICENSE_URL}), "
            f"with modifications."
        )
    return f"Copyright {year} {COMPANY_LEGAL_NAME}"


def sa_distribution_text() -> str:
    return (
        f"Copyright (c) {COMPANY_LEGAL_NAME}. Advisory content is derived "
        f"from {SOURCE_VENDOR} advisories "
        f"({RED_HAT_ERRATA_BASE_URL}/), "
        f"(C) {SOURCE_VENDOR}, Inc., used under "
        f"{LICENSE_NAME} ({SOURCE_LICENSE_URL}); "
        f"modified by {COMPANY_NAME}."
    )


def vex_distribution_text() -> str:
    return (
        f"Copyright (c) {COMPANY_LEGAL_NAME}. VEX content describes Rocky "
        f"Linux product status for CVEs, derived in part from "
        f"{SOURCE_VENDOR} data under {LICENSE_NAME}."
    )


def legal_disclaimer_note() -> dict:
    return {
        "category": "legal_disclaimer",
        "text": (
            "This content is licensed under the Creative Commons "
            f"Attribution 4.0 International License "
            f"({SOURCE_LICENSE_URL})."
        ),
    }


def tlp_block() -> dict:
    return {"label": "WHITE"}
