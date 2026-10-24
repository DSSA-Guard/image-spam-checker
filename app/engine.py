"""Image blacklist engine of the image-spam-checker service.

Images match by exact SHA-256, by perceptual hash (re-encodes, resizes)
or by ORB feature matching when they share at least 60% of either image
(crops, captions, collages) — see ``match_image``.

Persists a bot-wide list of image content hashes that should be rejected
by the bot's automod, plus a separate ``reports`` table that lets users flag
new images via the bot's ``이미지 신고`` context menu. When a hash accumulates
five distinct reporters, the data layer auto-promotes it into the
blacklist (source = ``auto_report``) so the next on_message check rejects
it without waiting for owner action.

Stored in one SQLite file under ``IMAGE_CHECKER_DATA_DIR``. A single in-memory set (``_cache``) backs the
hot-path lookup in ``is_blacklisted`` — that function performs a
lock-free set membership check, so automod message processing never
blocks on the DB. Cache invalidation is the caller's job for writes
(``add_to_blacklist``/``remove_from_blacklist`` mutate the set in
place); ``load_cache`` rehydrates from disk.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

from PIL import Image

try:
    import cv2
    import numpy as np
except ImportError:  # partial matching is skipped without OpenCV
    cv2 = None

logger = logging.getLogger(__name__)


_DB_DIR = Path(os.getenv("IMAGE_CHECKER_DATA_DIR", "data"))
_DB_FILE = _DB_DIR / "image_blacklist.sqlite3"

# ``threading.Lock`` gates schema setup and the full cache rebuild. Per-row
# writes don't take the lock — SQLite serialises them with the
# ``busy_timeout`` PRAGMA and the in-memory cache mutations are atomic
# under the GIL.
_lock = threading.Lock()
_initialized = False

# Hot-path membership set. Reads from ``is_blacklisted`` go straight to this
# without locking. Replaced wholesale by ``load_cache`` once at boot (or
# on first lazy load) and then mutated in place by add/remove.
_cache: set[str] = set()
_cache_loaded: bool = False

# sha256 -> 64-bit dHash of blacklisted images. SHA-256 only catches
# byte-identical files; a copy-paste, screenshot, resize or re-encode of the
# same picture changes every byte, so ``match_image`` also compares these
# perceptual hashes by Hamming distance.
_phash_cache: dict[str, int] = {}

# Bits (out of 64) two dHashes may differ by and still count as the same
# picture. Re-encodes and resizes land around 0-4.
PHASH_MAX_DISTANCE = 6

# sha256 -> ORB features of blacklisted images, for catching crops and
# images pasted into a bigger one (meme captions, collages), which change
# the whole-image dHash. See ``_partial_ratio``.
_feature_cache: dict[str, tuple] = {}

# Block when the region two images share covers at least this much of
# either one.
PARTIAL_MATCH_RATIO = 0.6
# Blacklisted images are shrunk to _ORB_SIDE. Incoming ones keep twice the
# size and more features, so a banned picture pasted small into a collage
# still gets enough keypoints of its own.
_ORB_SIDE = 512
_ORB_FEATURES = 500
_ORB_NEW_SIDE = 1024
_ORB_NEW_FEATURES = 2000
_MIN_INLIERS = 20
_CELL = 16  # pixel-check grid, in px of the shrunk image


def _connect() -> sqlite3.Connection:
    # ``check_same_thread=False`` is required because the cog runs reads
    # from a different thread than the one that loaded the cog. Writes
    # are short and SQLite's built-in locking keeps them consistent.
    return sqlite3.connect(_DB_FILE, check_same_thread=False, timeout=5.0)


def init() -> None:
    """Create the schema (idempotent). Safe to call from any thread."""
    global _initialized
    if _initialized:
        return
    with _lock:
        if _initialized:
            return
        _DB_DIR.mkdir(parents=True, exist_ok=True)
        conn = _connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS blacklist (
                    hash TEXT PRIMARY KEY,
                    added_at INTEGER,
                    added_by TEXT,
                    source TEXT
                );

                CREATE TABLE IF NOT EXISTS reports (
                    hash TEXT NOT NULL,
                    reporter_id TEXT NOT NULL,
                    reported_at INTEGER,
                    PRIMARY KEY (hash, reporter_id)
                );

                CREATE INDEX IF NOT EXISTS idx_reports_hash ON reports(hash);

                -- First reporter's copy of the image, so the owner can see
                -- what was reported. ``data`` is NULL when the file was too
                -- big to keep (the jump link still points at the original).
                CREATE TABLE IF NOT EXISTS report_images (
                    hash TEXT PRIMARY KEY,
                    data BLOB,
                    filename TEXT,
                    jump_url TEXT
                );
                """
            )
            cols = {r[1] for r in conn.execute("PRAGMA table_info(blacklist)")}
            if "phash" not in cols:
                conn.execute("ALTER TABLE blacklist ADD COLUMN phash TEXT")
            conn.commit()
        finally:
            conn.close()
        _initialized = True


def load_cache() -> None:
    """Rehydrate the in-memory blacklist from disk.

    Called once at cog load. Subsequent calls are cheap no-ops thanks to
    the ``_cache_loaded`` double-check. The cache assignment is a single
    ``set()`` rebind, so concurrent readers from ``is_blacklisted`` will
    see either the old set or the new set, never a half-built one.
    """
    global _cache, _phash_cache, _feature_cache, _cache_loaded
    init()
    with _lock:
        if _cache_loaded:
            return
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT b.hash, b.phash, i.data FROM blacklist b "
                "LEFT JOIN report_images i ON i.hash = b.hash"
            ).fetchall()
            phashes: dict[str, int] = {}
            features: dict[str, tuple] = {}
            for h, ph, data in rows:
                if ph is None and data:
                    # Rows blacklisted before perceptual hashing existed.
                    ph_int = compute_phash(data)
                    if ph_int is not None:
                        ph = f"{ph_int:016x}"
                        conn.execute(
                            "UPDATE blacklist SET phash = ? WHERE hash = ?", (ph, h)
                        )
                if ph:
                    phashes[h] = int(ph, 16)
                ph_int = phashes.get(h)
                dup = ph_int is not None and any(
                    (ph_int ^ phashes[o]).bit_count() <= PHASH_MAX_DISTANCE
                    for o in features
                    if o in phashes
                )
                feat = compute_features(data) if data and not dup else None
                if feat is not None:
                    features[h] = feat[:3]
            conn.commit()
        finally:
            conn.close()
        _cache = {r[0] for r in rows}
        _phash_cache = phashes
        _feature_cache = features
        _cache_loaded = True


def compute_hash_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of raw attachment bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_phash(data: bytes) -> int | None:
    """64-bit difference hash (dHash) of an image, or None if undecodable.

    Survives re-encoding, resizing and format changes, which SHA-256 does
    not. Near-flat images (almost no bits set, or almost all) are rejected
    because their dHash says nothing about the picture and would match
    every other plain image. CPU-bound — call via ``asyncio.to_thread``.
    """
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.draft("L", (64, 64))  # JPEG: decode at reduced size
            small = img.convert("L").resize((9, 8), Image.LANCZOS)
    except Exception:
        return None
    px = small.tobytes()  # mode "L": one byte per pixel
    bits = 0
    for row in range(8):
        for col in range(8):
            left = px[row * 9 + col]
            right = px[row * 9 + col + 1]
            bits = (bits << 1) | (left > right)
    if not 8 <= bits.bit_count() <= 56:
        return None
    return bits


def _has_near_duplicate(ph: int | None, phashes: dict[str, int]) -> bool:
    """Whether a blacklisted image with features looks the same as ``ph``."""
    if ph is None:
        return False
    return any(
        (ph ^ other).bit_count() <= PHASH_MAX_DISTANCE
        for h, other in phashes.items()
        if h in _feature_cache
    )


def _gray_thumb(data: bytes, side: int = _ORB_SIDE):
    with Image.open(io.BytesIO(data)) as img:
        img.draft("L", (side, side))
        gray = img.convert("L")
    gray.thumbnail((side, side))
    return np.asarray(gray)


def compute_features(
    data: bytes, side: int = _ORB_SIDE, nfeatures: int = _ORB_FEATURES
) -> tuple | None:
    """(keypoint xy, ORB descriptors, (w, h), gray image) or None.

    None when OpenCV is missing, the image is undecodable, or it has too
    little texture to match reliably (those still go through SHA-256 and
    dHash). CPU-bound — call via ``asyncio.to_thread``.
    """
    if cv2 is None:
        return None
    try:
        arr = _gray_thumb(data, side)
    except Exception:
        return None
    kps, desc = cv2.ORB_create(nfeatures=nfeatures).detectAndCompute(arr, None)
    if desc is None or len(kps) < _MIN_INLIERS:
        return None
    pts = np.float32([k.pt for k in kps])
    return pts, desc, (arr.shape[1], arr.shape[0]), arr


def _homography(src, dst):
    """Banned -> new image homography from matched points, or None."""
    if len(src) < _MIN_INLIERS:
        return None
    H, mask = cv2.findHomography(src, dst, cv2.RANSAC, 5.0)
    if H is None or int(mask.sum()) < _MIN_INLIERS:
        return None
    return H


def _cells(a):
    c = _CELL
    gh, gw = a.shape[0] // c, a.shape[1] // c
    return a[: gh * c, : gw * c].reshape(gh, c, gw, c).swapaxes(1, 2).reshape(gh, gw, c * c)


def _partial_ratio(new_arr, banned_arr, H) -> float:
    """Share of the larger-covered image that really matches, 0..1.

    Matched keypoints alone overstate overlap: one shared logo yields a
    homography that maps the whole banned image onto the new one. So the
    banned image is warped into the new one's frame and compared cell by
    cell; only cells whose pixels agree count. The matched area is then
    measured against both images, so a crop (new ⊂ banned) and a paste
    (banned ⊂ new) both qualify.
    """
    hn, wn = new_arr.shape
    hb, wb = banned_arr.shape
    corners = np.float32([[0, 0], [wb, 0], [wb, hb], [0, hb]]).reshape(1, 4, 2)
    proj = cv2.perspectiveTransform(corners, H)[0]
    if not cv2.isContourConvex(proj):
        return 0.0
    scale = cv2.contourArea(proj) / (wb * hb)  # banned area -> new area
    if not 0.01 < scale < 100:
        return 0.0
    warped = cv2.warpPerspective(banned_arr, H, (wn, hn))
    inside = cv2.warpPerspective(np.full_like(banned_arr, 255), H, (wn, hn))
    a = _cells(new_arr).astype(np.float32)
    b = _cells(warped).astype(np.float32)
    if a.size == 0:
        return 0.0
    covered = _cells(inside).min(axis=2) == 255
    ma, mb = a.mean(2), b.mean(2)
    sa, sb = a.std(2), b.std(2)
    ncc = (
        (a - ma[..., None]) * (b - mb[..., None])
    ).mean(2) / (sa * sb + 1e-6)
    flat = (sa < 8) & (sb < 8)
    same = covered & np.where(flat, np.abs(ma - mb) < 20, ncc > 0.5)
    area = float(same.sum()) * _CELL * _CELL
    grid_area = a.shape[0] * a.shape[1] * _CELL * _CELL
    return min(1.0, max(area / grid_area, area / scale / (wb * hb)))


def _match_partial(data: bytes) -> str | None:
    items = list(_feature_cache.items())
    if not items:
        return None
    new = compute_features(data, _ORB_NEW_SIDE, _ORB_NEW_FEATURES)
    if new is None:
        return None
    # One brute-force pass against every blacklisted image's descriptors at
    # once; only images with enough matches go on to the costlier checks.
    descs = np.vstack([f[1] for _, f in items])
    owner = np.concatenate([np.full(len(f[1]), i) for i, (_, f) in enumerate(items)])
    start = np.concatenate([[0], np.cumsum([len(f[1]) for _, f in items])[:-1]])
    pairs: dict[int, list[tuple[int, int]]] = {}
    for m in cv2.BFMatcher(cv2.NORM_HAMMING).knnMatch(new[1], descs, k=2):
        if not m:
            continue
        # Lowe ratio test. Near-duplicate blacklisted copies would cancel
        # each other out here, which is why only one of them keeps features.
        if len(m) == 2 and m[0].distance >= 0.75 * m[1].distance:
            continue
        i = int(owner[m[0].trainIdx])
        pairs.setdefault(i, []).append((m[0].trainIdx - start[i], m[0].queryIdx))
    for i, idx in sorted(pairs.items(), key=lambda kv: -len(kv[1])):
        if len(idx) < _MIN_INLIERS:
            break
        bh, banned = items[i]
        H = _homography(
            banned[0][[b for b, _ in idx]], new[0][[n for _, n in idx]]
        )
        if H is None:
            continue
        found = get_report_image(bh)
        if not found:
            continue
        try:
            banned_arr = _gray_thumb(found[0])
        except Exception:
            continue
        if _partial_ratio(new[3], banned_arr, H) >= PARTIAL_MATCH_RATIO:
            return bh
    return None


def match_image(data: bytes) -> str | None:
    """SHA-256 of the blacklisted image ``data`` matches, or None.

    Exact SHA-256 first, then the nearest perceptual hash within
    ``PHASH_MAX_DISTANCE``, then a partial match (crop or paste) covering
    ``PARTIAL_MATCH_RATIO`` of either image. CPU-bound — call via
    ``asyncio.to_thread``.
    """
    h = compute_hash_bytes(data)
    if is_blacklisted(h):
        return h
    ph = compute_phash(data) if _phash_cache else None
    if ph is not None:
        best, best_dist = None, PHASH_MAX_DISTANCE + 1
        for bh, bph in list(_phash_cache.items()):
            dist = (ph ^ bph).bit_count()
            if dist < best_dist:
                best, best_dist = bh, dist
        if best:
            return best
    return _match_partial(data)


def is_blacklisted(hash_hex: str) -> bool:
    """Hot-path lookup. Triggers a lazy cache load on first use.

    Deliberately lock-free on the read path so the automod's per-message
    check stays cheap. The first call in a fresh process pays the DB
    cost; every subsequent call is a set membership test.
    """
    if not _cache_loaded:
        load_cache()
    return hash_hex in _cache


def add_to_blacklist(
    hash_hex: str,
    added_by: str = "",
    source: str = "manual",
    data: bytes | None = None,
) -> bool:
    """Insert a hash into the blacklist. Returns True iff it was new.

    ``data`` is the image itself, used for the perceptual hash; when it is
    omitted the stored report copy is used if there is one. Without either
    only byte-identical copies get caught.

    Also updates the in-memory cache on success so the next automod
    check sees the new entry without a reload.
    """
    init()
    if data is None:
        found = get_report_image(hash_hex)
        data = found[0] if found else None
    ph = compute_phash(data) if data else None
    # A near-identical copy that already has features covers this one; two
    # sets of the same keypoints would fail each other's ratio test.
    feat = (
        compute_features(data)
        if data and not _has_near_duplicate(ph, _phash_cache)
        else None
    )
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO blacklist (hash, added_at, added_by, source, phash) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                hash_hex,
                int(time.time()),
                added_by,
                source,
                f"{ph:016x}" if ph is not None else None,
            ),
        )
        conn.commit()
        added = cur.rowcount > 0
    finally:
        conn.close()
    if added:
        _cache.add(hash_hex)
        if ph is not None:
            _phash_cache[hash_hex] = ph
        if feat is not None:
            _feature_cache[hash_hex] = feat[:3]
    return added


def remove_from_blacklist(hash_hex: str) -> bool:
    """Delete a hash from the blacklist and wipe its report rows.

    The report wipe is intentional: once an image is no longer
    blacklisted, fresh reports against it should be re-countable from
    zero. Returns True iff the blacklist row actually existed.
    """
    init()
    conn = _connect()
    try:
        # Clear report rows first so a future re-report cycle starts at 0.
        conn.execute("DELETE FROM reports WHERE hash = ?", (hash_hex,))
        conn.execute("DELETE FROM report_images WHERE hash = ?", (hash_hex,))
        cur = conn.execute("DELETE FROM blacklist WHERE hash = ?", (hash_hex,))
        conn.commit()
        removed = cur.rowcount > 0
    finally:
        conn.close()
    # ``discard`` instead of ``remove`` so an unknown hash is a no-op here
    # even if the row was already gone (e.g. concurrent owner action).
    _cache.discard(hash_hex)
    _phash_cache.pop(hash_hex, None)
    _feature_cache.pop(hash_hex, None)
    return removed


def list_blacklist() -> list[dict]:
    """Return all blacklist rows, newest first."""
    init()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT hash, added_at, added_by, source, phash FROM blacklist "
            "ORDER BY added_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def record_report(hash_hex: str, reporter_id: int) -> bool:
    """Record one user's report against a hash.

    Returns True if this is a fresh report (caller should re-read the
    count and possibly auto-promote to the blacklist). Returns False if
    the same user has already reported this hash.
    """
    init()
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO reports (hash, reporter_id, reported_at) "
            "VALUES (?, ?, ?)",
            (hash_hex, str(reporter_id), int(time.time())),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_report_count(hash_hex: str) -> int:
    """Number of distinct reporters for a given hash."""
    init()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM reports WHERE hash = ?", (hash_hex,)
        ).fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


# Discord's bot upload cap is 10MB per message; anything larger can't be
# re-sent to the owner anyway, so only the jump link is kept.
MAX_STORED_IMAGE_BYTES = 8 * 1024 * 1024


def save_report_image(
    hash_hex: str, data: bytes, filename: str, jump_url: str
) -> None:
    """Keep the first reported copy of an image. Later calls are no-ops."""
    init()
    conn = _connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO report_images (hash, data, filename, jump_url) "
            "VALUES (?, ?, ?, ?)",
            (
                hash_hex,
                data if len(data) <= MAX_STORED_IMAGE_BYTES else None,
                filename,
                jump_url,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_pending_reports(limit: int) -> list[dict]:
    """Reported hashes not yet blacklisted, most recently reported first.

    Each row: hash, count, last_reported_at, data, filename, jump_url
    (the image columns are None for reports made before images were kept).
    """
    init()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT r.hash, COUNT(*) AS count, MAX(r.reported_at) AS last_reported_at, "
            "i.data, i.filename, i.jump_url "
            "FROM reports r LEFT JOIN report_images i ON i.hash = r.hash "
            "WHERE r.hash NOT IN (SELECT hash FROM blacklist) "
            "GROUP BY r.hash ORDER BY last_reported_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_report_image(hash_hex: str) -> tuple[bytes, str] | None:
    """(data, filename) of the stored copy, or None if nothing was kept."""
    init()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT data, filename FROM report_images WHERE hash = ? AND data IS NOT NULL",
            (hash_hex,),
        ).fetchone()
        return (row[0], row[1] or "") if row else None
    finally:
        conn.close()
