"""HTTP layer: auth, report flow with auto-promotion, block/unblock, stored images."""

import io
import os
import tempfile

os.environ["IMAGE_CHECKER_DATA_DIR"] = tempfile.mkdtemp()
os.environ["IMAGE_CHECKER_ADMIN_PASSWORD"] = "admin-pw"

from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from app import keys
from app.main import app

AUTH = {"Authorization": f"Bearer {keys.create_key('test')}"}


def _png(seed: int) -> bytes:
    import random

    rnd = random.Random(seed)
    img = Image.new("RGB", (200, 150), (rnd.randrange(256), 0, 0))
    d = ImageDraw.Draw(img)
    for _ in range(20):
        x, y = rnd.randrange(200), rnd.randrange(150)
        d.ellipse((x, y, x + 60, y + 50), fill=tuple(rnd.randrange(256) for _ in range(3)))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _report(c, data, uid):
    return c.post(
        "/v1/reports",
        headers=AUTH,
        files={"image": ("a.png", data, "image/png")},
        data={"reporter_id": str(uid), "filename": "a.png", "jump_url": "https://x"},
    ).json()


def test_requires_token():
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200
        assert c.get("/v1/blacklist").status_code == 401
        assert c.get("/v1/blacklist", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_five_reports_block_and_match():
    data = _png(1)
    with TestClient(app) as c:
        for uid in range(1, 5):
            assert _report(c, data, uid)["status"] == "recorded"
        assert _report(c, data, 1)["status"] == "duplicate"
        assert _report(c, data, 5)["status"] == "auto_blocked"
        assert _report(c, data, 6)["status"] == "blocked"

        files = {"image": ("b.png", data, "image/png")}
        h = c.post("/v1/match", headers=AUTH, files=files).json()["hash"]
        assert h and len(h) == 64
        miss = c.post("/v1/match", headers=AUTH, files={"image": ("c.png", _png(2), "image/png")})
        assert miss.json()["hash"] is None

        assert c.delete(f"/v1/blacklist/{h}", headers=AUTH).json() == {"removed": True}
        assert c.post("/v1/match", headers=AUTH, files=files).json()["hash"] is None


def test_pending_image_and_manual_block():
    data = _png(3)
    with TestClient(app) as c:
        h = _report(c, data, 1)["hash"]
        row = next(r for r in c.get("/v1/reports/pending", headers=AUTH).json() if r["hash"] == h)
        assert row["count"] == 1 and row["has_image"] is True and "data" not in row

        img = c.get(f"/v1/images/{h}", headers=AUTH)
        assert img.content == data and img.headers["x-filename-ext"] == "png"
        assert c.get(f"/v1/images/{'0' * 64}", headers=AUTH).status_code == 404
        assert c.get("/v1/images/not-a-hash", headers=AUTH).status_code == 404

        r = c.put(f"/v1/blacklist/{h}", headers=AUTH, json={"added_by": "9", "source": "web_admin"})
        assert r.json() == {"added": True}
        assert h not in {p["hash"] for p in c.get("/v1/reports/pending", headers=AUTH).json()}
        assert h in {b["hash"] for b in c.get("/v1/blacklist", headers=AUTH).json()}


def test_refuses_to_start_without_admin_password(monkeypatch):
    import pytest

    monkeypatch.delenv("IMAGE_CHECKER_ADMIN_PASSWORD")
    with pytest.raises(RuntimeError, match="IMAGE_CHECKER_ADMIN_PASSWORD"):
        with TestClient(app):
            pass
