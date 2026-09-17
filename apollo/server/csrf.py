"""Session CSRF helpers for Apollo HTML admin forms."""

from __future__ import annotations

import re
import secrets
from typing import Iterable, Optional
from urllib.parse import parse_qs

from fastapi import Request
from starlette.responses import PlainTextResponse

CSRF_SESSION_KEY = "csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_PROTECTED_PREFIXES = (
    "/admin",
    "/profile",
    "/red_hat",
    "/login/setup",
    "/logout",
)
_MULTIPART_TOKEN = re.compile(
    rb'name="csrf_token"\s*(?:; ?filename="[^"]*")?\s*\r\n(?:[^\r\n]+:[^\r\n]*\r\n)*\r\n([^\r\n]*)'
)


def ensure_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def _extract_submitted_token(request: Request, form_token: str | None) -> str | None:
    header = request.headers.get(CSRF_HEADER)
    if header:
        return header
    return form_token


def csrf_tokens_match(expected: str | None, submitted: str | None) -> bool:
    if not expected or not submitted:
        return False
    if len(expected) != len(submitted):
        return False
    return secrets.compare_digest(expected, submitted)


def token_from_body(content_type: str, body: bytes) -> Optional[str]:
    """Pull csrf_token from a buffered form body without consuming the ASGI stream."""
    if not body:
        return None
    ctype = (content_type or "").lower()
    if "application/x-www-form-urlencoded" in ctype:
        parsed = parse_qs(body.decode("latin-1"), keep_blank_values=True)
        values = parsed.get(CSRF_FORM_FIELD) or []
        return values[0] if values else None
    if "multipart/form-data" in ctype:
        match = _MULTIPART_TOKEN.search(body)
        if match:
            return match.group(1).decode("latin-1")
    return None


def _path_is_protected(path: str, prefixes: Iterable[str]) -> bool:
    return any(path.startswith(prefix) for prefix in prefixes)


class CSRFMiddleware:
    """Require CSRF token on unsafe methods under HTML admin surfaces.

    Pure ASGI middleware so the request body can be replayed to downstream
    Form() handlers (BaseHTTPMiddleware would consume it). Body buffering is
    limited to protected unsafe requests.
    """

    def __init__(
        self,
        app,
        protected_prefixes: Iterable[str] = _PROTECTED_PREFIXES,
    ):
        self.app = app
        self.protected_prefixes = tuple(protected_prefixes)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "")
        needs_csrf = method not in _SAFE_METHODS and _path_is_protected(
            path, self.protected_prefixes
        )

        if not needs_csrf:
            request = Request(scope, receive)
            ensure_csrf_token(request)
            await self.app(scope, receive, send)
            return

        chunks = []
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.request":
                chunks.append(message.get("body", b""))
                more_body = message.get("more_body", False)
            elif message["type"] == "http.disconnect":
                await self.app(scope, receive, send)
                return
            else:
                more_body = False
        body = b"".join(chunks)
        replayed = {"done": False}

        async def receive_replay():
            if not replayed["done"]:
                replayed["done"] = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        request = Request(scope, receive_replay)
        ensure_csrf_token(request)
        form_token = token_from_body(request.headers.get("content-type", ""), body)
        submitted = _extract_submitted_token(request, form_token)
        expected = request.session.get(CSRF_SESSION_KEY)
        if not csrf_tokens_match(expected, submitted):
            response = PlainTextResponse(
                "CSRF token missing or invalid", status_code=403
            )
            await response(scope, receive_replay, send)
            return

        replayed["done"] = False
        await self.app(scope, receive_replay, send)
