"""HTTP API of the image-spam-checker service.

The Discord bot (and its web panel) talk to this instead of loading
OpenCV and the blacklist database themselves. Every route except
``/health`` needs ``Authorization: Bearer $IMAGE_CHECKER_API_KEY``.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import re
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from app import engine

REPORT_THRESHOLD = 5
# Discord caps attachments well below this; it only keeps a runaway upload
# from filling memory.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024
_HASH_RE = re.compile(r"[0-9a-f]{64}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    _api_key()  # refuse to boot without a key
    # Builds perceptual hashes and ORB features for every blacklisted
    # image, so keep it off the event loop.
    await asyncio.to_thread(engine.load_cache)
    yield


app = FastAPI(title="image-spam-checker", lifespan=lifespan)


def _api_key() -> str:
    key = os.getenv("IMAGE_CHECKER_API_KEY", "").strip()
    if not key:
        raise RuntimeError("환경 변수가 필요합니다: IMAGE_CHECKER_API_KEY")
    return key


def require_token(request: Request) -> None:
    expected = _api_key()
    got = request.headers.get("authorization", "")
    if not hmac.compare_digest(got.encode(), f"Bearer {expected}".encode()):
        raise HTTPException(status_code=401, detail="invalid token")


def _hash(hash_hex: str) -> str:
    if not _HASH_RE.fullmatch(hash_hex):
        raise HTTPException(status_code=404)
    return hash_hex


async def _read_upload(file: UploadFile) -> bytes:
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="image too large")
    return data


@app.get("/health")
async def health() -> dict:
    return {"ok": True}


@app.post("/v1/match", dependencies=[Depends(require_token)])
async def match(image: UploadFile) -> dict:
    """Hash of the blacklisted image ``image`` matches, or null."""
    data = await _read_upload(image)
    return {"hash": await asyncio.to_thread(engine.match_image, data)}


def _submit_report(
    data: bytes, reporter_id: str, filename: str, jump_url: str
) -> dict:
    h = engine.compute_hash_bytes(data)
    if engine.match_image(data):
        return {"status": "blocked", "hash": h}
    if not engine.record_report(h, reporter_id):
        return {"status": "duplicate", "hash": h}
    engine.save_report_image(h, data, filename, jump_url)
    if engine.get_report_count(h) >= REPORT_THRESHOLD:
        engine.add_to_blacklist(h, added_by=reporter_id, source="auto_report", data=data)
        return {"status": "auto_blocked", "hash": h}
    return {"status": "recorded", "hash": h}


@app.post("/v1/reports", dependencies=[Depends(require_token)])
async def report(
    image: UploadFile,
    reporter_id: str = Form(...),
    filename: str = Form(""),
    jump_url: str = Form(""),
) -> dict:
    """One user's report of one image.

    ``status`` is ``blocked`` (already on the blacklist), ``duplicate``
    (this user reported it before), ``recorded`` or ``auto_blocked`` (this
    report was the ``REPORT_THRESHOLD``-th and promoted it).
    """
    data = await _read_upload(image)
    return await asyncio.to_thread(_submit_report, data, reporter_id, filename, jump_url)


@app.get("/v1/reports/pending", dependencies=[Depends(require_token)])
async def pending(limit: int = 50) -> list[dict]:
    rows = await asyncio.to_thread(engine.list_pending_reports, max(1, min(limit, 500)))
    for r in rows:
        r["has_image"] = r.pop("data") is not None
    return rows


@app.get("/v1/images/{hash_hex}", dependencies=[Depends(require_token)])
async def stored_image(hash_hex: str) -> Response:
    found = await asyncio.to_thread(engine.get_report_image, _hash(hash_hex))
    if not found:
        raise HTTPException(status_code=404)
    data, filename = found
    # Header values are latin-1 only; the bot only needs the extension.
    ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
    return Response(
        data,
        media_type="application/octet-stream",
        headers={"X-Filename-Ext": ext.encode("ascii", "ignore").decode()[:8]},
    )


class BlockBody(BaseModel):
    added_by: str = ""
    source: str = "manual"


@app.get("/v1/blacklist", dependencies=[Depends(require_token)])
async def blacklist() -> list[dict]:
    return await asyncio.to_thread(engine.list_blacklist)


@app.put("/v1/blacklist/{hash_hex}", dependencies=[Depends(require_token)])
async def block(hash_hex: str, body: BlockBody) -> dict:
    added = await asyncio.to_thread(
        engine.add_to_blacklist, _hash(hash_hex), body.added_by, body.source
    )
    return {"added": added}


@app.delete("/v1/blacklist/{hash_hex}", dependencies=[Depends(require_token)])
async def unblock(hash_hex: str) -> dict:
    return {"removed": await asyncio.to_thread(engine.remove_from_blacklist, _hash(hash_hex))}
