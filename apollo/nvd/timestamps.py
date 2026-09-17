"""Parse NVD / vuls timestamps into aware UTC datetimes."""

from __future__ import annotations

import datetime
import re
from typing import Any, Optional

# Go's encoding/json emits RFC3339 with variable-length fractional seconds
# (e.g. ".7Z", ".36Z"). Python 3.9 fromisoformat only accepts 0 or 3–6 digits.
_TS_RE = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?P<frac>\.\d+)?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})?$"
)


def parse_ts(raw: Any) -> Optional[datetime.datetime]:
    """Parse an ISO-8601 / RFC3339 timestamp; return None on empty or invalid."""
    if raw is None:
        return None
    if isinstance(raw, datetime.datetime):
        return raw
    if not isinstance(raw, str) or not raw:
        return None

    s = raw.strip()
    m = _TS_RE.match(s)
    if m:
        head = m.group("head").replace(" ", "T")
        frac = m.group("frac") or ""
        if frac:
            digits = (frac[1:] + "000000")[:6]
            frac = "." + digits
        tz = m.group("tz") or ""
        if tz == "Z":
            tz = "+00:00"
        elif len(tz) == 5 and tz[0] in "+-":
            # +0000 → +00:00
            tz = f"{tz[:3]}:{tz[3:]}"
        s = head + frac + tz

    try:
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt
