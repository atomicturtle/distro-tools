import os

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

router = APIRouter(tags=["non-api"])

_IS_PRODUCTION = os.environ.get("ENV", "development").lower() == "production"


@router.post("/")
async def logout(request: Request):
    request.session.clear()
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie(
        "session",
        path="/",
        httponly=True,
        samesite="lax",
        secure=_IS_PRODUCTION,
    )
    return response
