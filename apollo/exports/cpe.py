"""Rocky Linux CPE helpers for CSAF product_tree.

Apollo does not use CEM's repo-anchored CPE schema. Platform CPEs follow the
common Rocky/RHEL OS pattern used by scanners:

  cpe:2.3:o:rocky:rocky_linux:{major}:*:*:*:*:*:{arch}:*
"""

from __future__ import annotations

import re
from typing import Optional

_PRODUCT_MAJOR = re.compile(r"Rocky Linux (\d+)")


def rocky_major_from_product_name(product_name: str) -> Optional[int]:
    match = _PRODUCT_MAJOR.search(product_name or "")
    if not match:
        return None
    return int(match.group(1))


def compute_rocky_platform_cpe(major: int, arch: str = "*") -> str:
    """Return a Rocky OS CPE 2.3 string for a major version and arch."""
    if not major:
        raise ValueError("major is required for Rocky CPE")
    hw = arch if arch else "*"
    return f"cpe:2.3:o:rocky:rocky_linux:{major}:*:*:*:*:*:{hw}:*"
