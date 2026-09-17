import os

from tortoise import Tortoise

Tortoise.init_models(["apollo.db"], "models")  # noqa # pylint: disable=wrong-import-position

from fastapi import FastAPI, Request, Depends
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.proxy_headers import ProxyHeadersMiddleware
from fastapi_pagination import add_pagination

from apollo.server.routes.advisories import router as advisories_router
from apollo.server.routes.statistics import router as statistics_router
from apollo.server.routes.login import router as login_router
from apollo.server.routes.logout import router as logout_router
from apollo.server.routes.profile import router as profile_router
from apollo.server.routes.admin_index import router as admin_index_router
from apollo.server.routes.admin_users import router as admin_users_router
from apollo.server.routes.admin_api_keys import router as admin_api_keys_router
from apollo.server.routes.admin_workflows import router as admin_workflows_router
from apollo.server.routes.admin_supported_products import router as admin_supported_products_router
from apollo.server.routes.red_hat_advisories import router as red_hat_advisories_router
from apollo.server.routes.api_advisories import router as api_advisories_router
from apollo.server.routes.api_updateinfo import router as api_updateinfo_router
from apollo.server.routes.api_red_hat import router as api_red_hat_router
from apollo.server.routes.api_compat import router as api_compat_router
from apollo.server.routes.api_osv import router as api_osv_router
from apollo.server.routes.api_workflows import router as api_workflows_router
from apollo.server.routes.api_keys import router as api_keys_router
from apollo.server.routes.api_cve_status import router as api_cve_status_router
from apollo.server.routes.api_vex import router as api_vex_router
from apollo.server.routes.api_nvd import router as api_nvd_router
from apollo.server.settings import (
    SECRET_KEY,
    SettingsMiddleware,
    get_setting,
    load_session_secret,
)
from apollo.server.utils import admin_user_scheme, user_scheme, templates
from apollo.server.csrf import CSRFMiddleware
from apollo.server.redirects import safe_relative_redirect
from apollo.db import Settings

from common.info import Info
from common.logger import Logger
from common.database import Database
from common.temporal import Temporal
from common.fastapi import StaticFilesSym, RenderErrorTemplateException

_IS_PRODUCTION = os.environ.get("ENV", "development").lower() == "production"

app = FastAPI(
    docs_url=None if _IS_PRODUCTION else "/docs",
    redoc_url=None if _IS_PRODUCTION else "/redoc",
    openapi_url=None if _IS_PRODUCTION else "/openapi.json",
)

# Global Temporal client instance
temporal_client = None

app.mount(
    "/static",
    StaticFilesSym(directory="apollo/server/static"),
    name="static",
)
app.mount(
    "/assets",
    StaticFilesSym(directory="apollo/server/assets"),
    name="assets",
)

app.add_middleware(SettingsMiddleware)

# Session/CSRF/proxy must be registered before the ASGI app starts. add_middleware
# is LIFO, so the last call is outermost: ProxyHeaders -> Session -> CSRF -> Settings.
_SESSION_SECRET = load_session_secret()
app.add_middleware(CSRFMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=_SESSION_SECRET,
    max_age=60 * 60 * 24 * 7,  # 1 week
    same_site="lax",
    https_only=_IS_PRODUCTION,
)
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")

app.include_router(advisories_router)
app.include_router(statistics_router, prefix="/statistics")
app.include_router(login_router, prefix="/login")
app.include_router(logout_router, prefix="/logout")
app.include_router(
    profile_router,
    prefix="/profile",
    dependencies=[Depends(user_scheme)],
)
app.include_router(
    admin_index_router,
    prefix="/admin",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(
    admin_users_router,
    prefix="/admin/users",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(
    admin_api_keys_router,
    prefix="/admin/api-keys",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(
    admin_workflows_router,
    prefix="/admin",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(
    admin_supported_products_router,
    prefix="/admin/supported-products",
    dependencies=[Depends(admin_user_scheme)]
)
app.include_router(red_hat_advisories_router, prefix="/red_hat")
app.include_router(api_advisories_router, prefix="/api/v3/advisories")
app.include_router(api_updateinfo_router, prefix="/api/v3/updateinfo")
app.include_router(api_red_hat_router, prefix="/api/v3/red_hat")
app.include_router(api_compat_router, prefix="/v2/advisories")
app.include_router(api_osv_router, prefix="/api/v3/osv")
app.include_router(api_cve_status_router, prefix="/api/v3/cves")
app.include_router(api_vex_router, prefix="/api/v3/vex")
app.include_router(api_nvd_router, prefix="/api/v3/nvd")
app.include_router(api_workflows_router, prefix="/api/v3/workflows")
app.include_router(api_keys_router, prefix="/api/v3/keys")

Info("apollo2")
Logger()
Database(True, app, ["apollo.db"])


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Peridot Apollo",
        version="0.1.0",
        description="Apollo Errata Management",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://apollo.build.resf.org/assets/pd-logo-np.svg"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

add_pagination(app)


@app.get("/_/healthz")
async def health():
    return {"status": "ok"}


@app.get("/_/set_color")
async def set_color(request: Request):
    valid_colors = ["dark", "light"]
    color = request.query_params.get("color")
    redirect_to = safe_relative_redirect(request.headers.get("referer"))
    response = RedirectResponse(redirect_to)

    # First check if the color is valid
    # If valid, set the color in the cookie, then
    # redirect back to referrer
    if color in valid_colors:
        response.set_cookie("color", color, samesite="lax")

    return response


@app.exception_handler(404)
async def not_found_handler(request, exc):  # pylint: disable=unused-argument
    if request.url.path.startswith("/api"
                                  ) or request.url.path.startswith("/v2"):
        return JSONResponse({"error": "Not found"}, status_code=404)
    return await render_template_exception_handler(request, None)


@app.exception_handler(RenderErrorTemplateException)
async def render_template_exception_handler(
    request: Request, exc: RenderErrorTemplateException
):
    if request.url.path.startswith("/api"
                                  ) or request.url.path.startswith("/v2"):
        return JSONResponse(
            {"error": exc.msg if exc and exc.msg else "Not found"},
            status_code=exc.status_code if exc and exc.status_code else 404,
        )
    return templates.TemplateResponse(
        "error.jinja", {
            "request": request,
            "message": exc.msg if exc and exc.msg else "Page not found",
        },
        status_code=exc.status_code if exc and exc.status_code else 404
    )


@app.on_event("startup")
async def startup():
    global temporal_client

    # Keep Settings.secret-key populated for operators; signing uses _SESSION_SECRET.
    if not await get_setting(SECRET_KEY):
        await Settings.create(name=SECRET_KEY, value=_SESSION_SECRET)

    # Initialize Temporal client for workflow management
    temporal = Temporal(True)
    await temporal.connect()
    temporal_client = temporal