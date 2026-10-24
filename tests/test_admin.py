"""Admin page: password sign-in, issuing a key shown once, revoking it, CSRF."""

import os
import re
import tempfile

os.environ.setdefault("IMAGE_CHECKER_DATA_DIR", tempfile.mkdtemp())
os.environ["IMAGE_CHECKER_ADMIN_PASSWORD"] = "admin-pw"

from fastapi.testclient import TestClient

from app.main import app


def _csrf(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def _sign_in(c) -> str:
    token = _csrf(c.get("/admin/login").text)
    r = c.post("/admin/login", data={"password": "admin-pw", "csrf": token})
    assert r.url.path == "/admin"
    return _csrf(r.text)


def test_dashboard_needs_sign_in_and_rejects_wrong_password():
    with TestClient(app) as c:
        r = c.get("/admin", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/admin/login"
        token = _csrf(c.get("/admin/login").text)
        r = c.post("/admin/login", data={"password": "wrong", "csrf": token})
        assert "비밀번호가 맞지 않아요" in r.text
        assert c.get("/admin", follow_redirects=False).status_code == 303


def test_issue_use_and_revoke_key():
    with TestClient(app) as c:
        csrf = _sign_in(c)
        page = c.post("/admin/keys", data={"name": "디스코드 봇", "csrf": csrf}).text
        raw = re.search(r"<code>(isc_[^<]+)</code>", page).group(1)
        assert "디스코드 봇" in page
        assert raw not in c.get("/admin").text  # shown only once

        auth = {"Authorization": f"Bearer {raw}"}
        assert c.get("/v1/blacklist", headers=auth).status_code == 200

        key_id = re.search(r'/admin/keys/(\d+)/revoke', c.get("/admin").text).group(1)
        c.post(f"/admin/keys/{key_id}/revoke", data={"csrf": csrf})
        assert c.get("/v1/blacklist", headers=auth).status_code == 401
        assert "폐기됨" in c.get("/admin").text


def test_actions_need_session_and_csrf():
    with TestClient(app) as c:
        assert c.post("/admin/keys", data={"name": "x", "csrf": ""}).status_code == 403
        _sign_in(c)
        assert c.post("/admin/keys", data={"name": "x", "csrf": "bad"}).status_code == 403
        assert c.post("/admin/logout", data={"csrf": "bad"}).status_code == 403
