"""Minimal X-Forwarded-* helpers for older Starlette builds."""

from __future__ import annotations


class ForwardedProtoMiddleware:
    """Set ASGI scope scheme from X-Forwarded-Proto when present.

    Starlette <0.24 has no ProxyHeadersMiddleware. For Apollo behind Apache TLS
    termination this is enough for SessionMiddleware https_only cookies.
    """

    def __init__(self, app, trusted_hosts="*"):  # pylint: disable=unused-argument
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = {
                key.decode("latin-1").lower(): value.decode("latin-1")
                for key, value in scope.get("headers", [])
            }
            forwarded = headers.get("x-forwarded-proto")
            if forwarded:
                proto = forwarded.split(",")[0].strip().lower()
                if proto in ("http", "https"):
                    scope = dict(scope)
                    scope["scheme"] = proto
        await self.app(scope, receive, send)


try:
    from starlette.middleware.proxy_headers import (  # type: ignore
        ProxyHeadersMiddleware as ProxyHeadersMiddleware,
    )
except ImportError:  # pragma: no cover - exercised on Starlette 0.22 (db1)
    ProxyHeadersMiddleware = ForwardedProtoMiddleware
