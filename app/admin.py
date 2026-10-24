"""Admin web pages: sign in with ``IMAGE_CHECKER_ADMIN_PASSWORD`` and
issue or revoke the API keys clients (the bot) use."""

from __future__ import annotations

import asyncio
import hmac
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import engine, keys

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def _ts(value: int | None) -> str:
    if not value:
        return "-"
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


templates.env.filters["ts"] = _ts


def admin_password() -> str:
    pw = os.getenv("IMAGE_CHECKER_ADMIN_PASSWORD", "")
    if not pw:
        raise RuntimeError("환경 변수가 필요합니다: IMAGE_CHECKER_ADMIN_PASSWORD")
    return pw


def _csrf(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = request.session["csrf"] = secrets.token_urlsafe(24)
    return token


def _check_csrf(request: Request, token: str) -> None:
    if not hmac.compare_digest(token.encode(), _csrf(request).encode()):
        raise HTTPException(status_code=403, detail="CSRF 토큰이 맞지 않아요.")


def _signed_in(request: Request) -> bool:
    return request.session.get("admin") is True


def _require_admin(request: Request, csrf: str) -> None:
    if not _signed_in(request):
        raise HTTPException(status_code=403)
    _check_csrf(request, csrf)


@router.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    return RedirectResponse("/admin", status_code=303)


@router.get("/admin/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request, error: int = 0):
    return templates.TemplateResponse(
        request, "login.html", {"csrf": _csrf(request), "error": bool(error)}
    )


@router.post("/admin/login", include_in_schema=False)
async def login(request: Request, password: str = Form(...), csrf: str = Form("")):
    _check_csrf(request, csrf)
    if not hmac.compare_digest(password.encode(), admin_password().encode()):
        await asyncio.sleep(1)  # slows down password guessing
        return RedirectResponse("/admin/login?error=1", status_code=303)
    request.session.clear()  # new session id on sign-in
    request.session["admin"] = True
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/logout", include_in_schema=False)
async def logout(request: Request, csrf: str = Form("")):
    _check_csrf(request, csrf)
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)


@router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    if not _signed_in(request):
        return RedirectResponse("/admin/login", status_code=303)
    key_rows, blacklist, pending = await asyncio.gather(
        asyncio.to_thread(keys.list_keys),
        asyncio.to_thread(engine.list_blacklist),
        asyncio.to_thread(engine.list_pending_reports, 500),
    )
    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "csrf": _csrf(request),
            "keys": key_rows,
            # Shown once, right after issuing; popped so a reload hides it.
            "new_key": request.session.pop("new_key", None),
            "blacklist_count": len(blacklist),
            "pending_count": len(pending),
        },
    )


@router.post("/admin/keys", include_in_schema=False)
async def issue_key(request: Request, name: str = Form(...), csrf: str = Form("")):
    _require_admin(request, csrf)
    name = name.strip()[:60]
    if not name:
        raise HTTPException(status_code=400, detail="키 이름을 입력해 주세요.")
    raw = await asyncio.to_thread(keys.create_key, name)
    request.session["new_key"] = {"name": name, "key": raw}
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/keys/{key_id}/revoke", include_in_schema=False)
async def revoke_key(request: Request, key_id: int, csrf: str = Form("")):
    _require_admin(request, csrf)
    await asyncio.to_thread(keys.revoke_key, key_id)
    return RedirectResponse("/admin", status_code=303)
