"""Shared helpers to reject private/metadata HTTP(S) fetch targets."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import List
from urllib.parse import urlparse

_URL_PATTERN = re.compile(r"^https?://.+")
_BLOCKED_HOST_SUFFIXES = (".localhost", ".local")
_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
    }
)


class UnsafeURLError(ValueError):
    """Raised when a URL must not be fetched."""


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_host_ips(host: str) -> List[ipaddress._BaseAddress]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return [literal]

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURLError("URL hostname could not be resolved") from exc

    addresses = []
    seen = set()
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = ipaddress.ip_address(sockaddr[0])
        key = str(ip)
        if key not in seen:
            seen.add(key)
            addresses.append(ip)
    if not addresses:
        raise UnsafeURLError("URL hostname could not be resolved")
    return addresses


def assert_safe_http_url(url: str, field_name: str = "URL") -> str:
    """Validate and return a trimmed http(s) URL that is safe to fetch.

    Checks scheme/hostname and blocks localhost, metadata, and hosts that
    resolve to private, loopback, link-local, or similarly reserved addresses.
    Call this again for every redirect hop before following it.
    """
    if not url or not url.strip():
        raise UnsafeURLError(f"{field_name} is required")

    trimmed_url = url.strip()
    if not _URL_PATTERN.match(trimmed_url):
        raise UnsafeURLError(f"{field_name} must start with http:// or https://")

    parsed = urlparse(trimmed_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURLError(
            f"{field_name} must be a valid http(s) URL with a hostname"
        )

    host = parsed.hostname.lower().rstrip(".")
    if host in _BLOCKED_HOSTS or any(
        host.endswith(suffix) for suffix in _BLOCKED_HOST_SUFFIXES
    ):
        raise UnsafeURLError(
            f"{field_name} must not target localhost or metadata endpoints"
        )

    for ip in _resolve_host_ips(host):
        if _is_blocked_ip(ip):
            raise UnsafeURLError(
                f"{field_name} must not target private or link-local addresses"
            )

    return trimmed_url
