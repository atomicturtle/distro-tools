"""Safe same-origin redirect helpers."""

from __future__ import annotations

from urllib.parse import urlparse


def safe_relative_redirect(url: str | None, fallback: str = "/") -> str:
    """Return a same-origin relative path, or fallback for open-redirect attempts."""
    if not url:
        return fallback

    candidate = url.strip()
    if not candidate:
        return fallback

    # Protocol-relative and absolute URLs are never safe as open redirects.
    if candidate.startswith("//") or "\\" in candidate:
        return fallback

    parsed = urlparse(candidate)
    if parsed.scheme or parsed.netloc:
        return fallback

    if not candidate.startswith("/"):
        return fallback

    return candidate
