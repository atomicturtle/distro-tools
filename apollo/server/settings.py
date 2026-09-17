import os
import secrets
import time
from typing import Mapping, Optional
from dataclasses import dataclass

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from apollo.db import Settings
from apollo.server.utils import is_admin_user

SECRET_KEY = "secret-key"
OIDC_PROVIDER_NAME = "oidc-provider-name"
OIDC_PROVIDER = "oidc-provider"
OIDC_CLIENT_ID = "oidc-client-id"
OIDC_CLIENT_SECRET = "oidc-client-secret"
OIDC_ADMIN_ROLE = "oidc-admin-role"
OIDC_ELEVATED_ROLE = "oidc-elevated-role"
RH_MATCH_STALE = "rh-match-stale"
DISABLE_SERVING_RH_ADVISORIES = "disable-serving-rh-advisories"
UI_URL = "ui-url"
COMPANY_NAME = "company-name"
MANAGING_EDITOR = "managing-editor"


def _read_secret_file(path: str, *, retries: int = 5, delay: float = 0.02) -> Optional[str]:
    """Read a non-empty secret, retrying briefly for concurrent writers."""
    for attempt in range(retries):
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as handle:
            existing = handle.read().strip()
        if existing:
            return existing
        if attempt + 1 < retries:
            time.sleep(delay)
    raise RuntimeError(f"session secret file {path} exists but is empty")


def load_session_secret(
    environ: Optional[Mapping[str, str]] = None,
    persist_path: Optional[str] = None,
) -> str:
    """Return the cookie-signing secret at import time (no database).

    SessionMiddleware must be registered before the ASGI app starts, so this
    cannot wait for an async Settings lookup. Prefer APOLLO_SECRET_KEY, then
    SECRET_KEY, then APOLLO_SECRET_KEY_FILE / persist_path. If none are set,
    generate a 32-byte hex secret and publish it atomically so restarts keep
    sessions. Never fall back to a hardcoded shared default.
    """
    env = environ if environ is not None else os.environ
    for key in ("APOLLO_SECRET_KEY", "SECRET_KEY"):
        value = (env.get(key) or "").strip()
        if value:
            return value

    path = persist_path
    if path is None:
        path = (env.get("APOLLO_SECRET_KEY_FILE") or "").strip()
    if not path:
        path = os.path.join(os.getcwd(), ".apollo_session_secret")

    existing = _read_secret_file(path)
    if existing:
        return existing

    value = secrets.token_hex(32)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    tmp_path = f"{path}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(tmp_path, path)
        except FileExistsError:
            raced = _read_secret_file(path)
            if raced:
                return raced
            raise RuntimeError(f"session secret file {path} exists but is empty")
        finally:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise
    return value


async def get_setting(name: str) -> Optional[str]:
    setting = await Settings.filter(name=name).get_or_none()
    if setting is None:
        return None
    return setting.value


async def get_setting_bool(name: str) -> Optional[bool]:
    setting = await Settings.filter(name=name).get_or_none()
    if setting is None:
        return None
    return setting.value == "True"


async def should_serve_red_hat_advisories(request: Request) -> bool:
    setting = await get_setting_bool(DISABLE_SERVING_RH_ADVISORIES)
    admin_user = await is_admin_user(request)

    if setting and not admin_user:
        return False

    return True


@dataclass
class SettingsContext:
    serve_rh_advisories: bool
    is_admin: bool


class SettingsMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        should_serve_rh_advisories = await should_serve_red_hat_advisories(
            request
        )

        request.state.settings = SettingsContext(
            serve_rh_advisories=should_serve_rh_advisories,
            is_admin=await is_admin_user(request),
        )

        return await call_next(request)
