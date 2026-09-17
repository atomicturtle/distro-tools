"""Session CSRF helpers for Apollo HTML admin forms."""

from __future__ import annotations

import secrets
from typing import Iterable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse, Response

CSRF_SESSION_KEY = "csrf_token"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER = "x-csrf-token"

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_PROTECTED_PREFIXES = ("/admin", "/profile", "/red_hat")


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
    return secrets.compare_digest(expected, submitted)


class CSRFMiddleware(BaseHTTPMiddleware):
    """Require CSRF token on unsafe methods under HTML admin surfaces."""

    def __init__(
        self,
        app,
        protected_prefixes: Iterable[str] = _PROTECTED_PREFIXES,
    ):
        super().__init__(app)
        self.protected_prefixes = tuple(protected_prefixes)

    async def dispatch(self, request: Request, call_next) -> Response:
        ensure_csrf_token(request)

        if request.method in _SAFE_METHODS:
            return await call_next(request)

        path = request.url.path
        if not any(path.startswith(prefix) for prefix in self.protected_prefixes):
            return await call_next(request)

        form_token = None
        content_type = request.headers.get("content-type", "")
        if (
            "application/x-www-form-urlencoded" in content_type
            or "multipart/form-data" in content_type
        ):
            form = await request.form()
            form_token = form.get(CSRF_FORM_FIELD)

        submitted = _extract_submitted_token(request, form_token)
        expected = request.session.get(CSRF_SESSION_KEY)
        if not csrf_tokens_match(expected, submitted):
            return PlainTextResponse("CSRF token missing or invalid", status_code=403)

        return await call_next(request)
