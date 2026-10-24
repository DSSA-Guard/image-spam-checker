"""Image blacklist engine of the image-spam-checker service.

Images match by exact SHA-256, by perceptual hash (dHash for re-encodes
and resizes, Meta's PDQ for the same plus rotations and flips) or by ORB
feature matching when they share at least 60% of either image
(crops, captions, collages) — see ``match_image``. Every image the service
keeps (reported or blacklisted) also gets MD5, SHA-1, SHA-512, SHA3-256 and
BLAKE2b digests in ``image_digests``, so hashes from other tools or shared
abuse lists can be looked up with ``find_by_digest``.

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
import re
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

try:
    import numpy as np
    import pdqhash
except ImportError:  # PDQ matching is skipped without it
    pdqhash = None

try:
    import faiss
except ImportError:  # ORB search falls back to chunked brute force
    faiss = None

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

# sha256 -> 256-bit PDQ hash of blacklisted images. PDQ is Meta's open
# perceptual hash, the format hash-sharing programs exchange. It is
# sturdier than the 64-bit dHash and, hashing an incoming image in all
# eight rotations/flips, also catches rotated or mirrored copies.
_pdq_cache: dict[str, int] = {}

# Meta's recommended values: hashes within 31 of 256 bits are the same
# picture, and hashes with quality below 50 (near-flat images) are noise.
PDQ_MAX_DISTANCE = 31
PDQ_MIN_QUALITY = 50
# PDQ shrinks to 64x64 internally; hashing a pre-shrunk copy keeps a huge
# upload from allocating gigabytes of float buffers.
_PDQ_SIDE = 1024

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

# Up to this many descriptor rows (~40 blacklisted images) the ORB index is
# an exact scan. Past it, an IVF index clusters the rows and each query
# descriptor only scans its _ORB_NPROBE nearest clusters.
_ORB_FLAT_ROWS = 20_000
_ORB_NPROBE = 4
# OpenCV's matcher refuses 2**18 or more train rows in one call.
_BF_CHUNK = 200_000


# Algorithms kept per image besides SHA-256, which stays the primary key.
# Column name -> hashlib constructor name.
DIGEST_ALGORITHMS = {
    "md5": "md5",
    "sha1": "sha1",
    "sha512": "sha512",
    "sha3_256": "sha3_256",
    "blake2b": "blake2b",
}
_DIGEST_HEX_LEN = {
    c: hashlib.new(a).digest_size * 2
    for c, a in {"sha256": "sha256", **DIGEST_ALGORITHMS}.items()
}
_HEX_RE = re.compile(r"[0-9a-f]+")


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

                -- Other digests of every image the service has seen the
                -- bytes of, keyed by its SHA-256. See ``DIGEST_ALGORITHMS``.
                CREATE TABLE IF NOT EXISTS image_digests (
                    sha256 TEXT PRIMARY KEY,
                    md5 TEXT,
                    sha1 TEXT,
                    sha512 TEXT,
                    sha3_256 TEXT,
                    blake2b TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_digests_md5 ON image_digests(md5);
                CREATE INDEX IF NOT EXISTS idx_digests_sha1 ON image_digests(sha1);
                CREATE INDEX IF NOT EXISTS idx_digests_sha512 ON image_digests(sha512);
                CREATE INDEX IF NOT EXISTS idx_digests_sha3_256 ON image_digests(sha3_256);
                CREATE INDEX IF NOT EXISTS idx_digests_blake2b ON image_digests(blake2b);
                """
            )
            cols = {r[1] for r in conn.execute("PRAGMA table_info(blacklist)")}
            if "phash" not in cols:
                conn.execute("ALTER TABLE blacklist ADD COLUMN phash TEXT")
            # 64 hex chars; '' when computed but too low quality to use.
            if "pdq" not in cols:
                conn.execute("ALTER TABLE blacklist ADD COLUMN pdq TEXT")
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
    global _cache, _phash_cache, _pdq_cache, _feature_cache, _cache_loaded
    init()
    with _lock:
        if _cache_loaded:
            return
        conn = _connect()
        try:
            # Stored images from before digests were kept.
            for h, data in conn.execute(
                "SELECT i.hash, i.data FROM report_images i "
                "LEFT JOIN image_digests d ON d.sha256 = i.hash "
                "WHERE i.data IS NOT NULL AND d.sha256 IS NULL"
            ).fetchall():
                _insert_digests(conn, h, data)
            rows = conn.execute(
                "SELECT b.hash, b.phash, b.pdq, i.data FROM blacklist b "
                "LEFT JOIN report_images i ON i.hash = b.hash"
            ).fetchall()
            phashes: dict[str, int] = {}
            pdqs: dict[str, int] = {}
            features: dict[str, tuple] = {}
            for h, ph, pdq, data in rows:
                if pdq is None and data and pdqhash is not None:
                    # Rows blacklisted before PDQ was added.
                    pdq_int = compute_pdq(data)
                    pdq = f"{pdq_int:064x}" if pdq_int is not None else ""
                    conn.execute("UPDATE blacklist SET pdq = ? WHERE hash = ?", (pdq, h))
                if pdq:
                    pdqs[h] = int(pdq, 16)
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
        _pdq_cache = pdqs
        _feature_cache = features
        if cv2 is not None:
            _orb_index.rebuild({h: f[1] for h, f in features.items()})
        _cache_loaded = True


def compute_hash_bytes(data: bytes) -> str:
    """Return the lowercase hex SHA-256 of raw attachment bytes."""
    return hashlib.sha256(data).hexdigest()


def compute_digests(data: bytes) -> dict[str, str]:
    """Hex digests of raw bytes: ``sha256`` plus every ``DIGEST_ALGORITHMS``."""
    out = {"sha256": compute_hash_bytes(data)}
    for col, algo in DIGEST_ALGORITHMS.items():
        out[col] = hashlib.new(algo, data).hexdigest()
    return out


def _insert_digests(conn: sqlite3.Connection, hash_hex: str, data: bytes) -> None:
    digests = compute_digests(data)
    if digests["sha256"] != hash_hex:
        # Callers may pass a hash that isn't these bytes' SHA-256 (tests,
        # hand-typed hashes); storing it would link unrelated digests.
        return
    cols = ["sha256", *DIGEST_ALGORITHMS]
    conn.execute(
        f"INSERT OR IGNORE INTO image_digests ({', '.join(cols)}) "
        f"VALUES ({', '.join('?' * len(cols))})",
        [digests[c] for c in cols],
    )


def find_by_digest(value: str) -> dict[str, str] | None:
    """Stored digests of the image whose digest (any algorithm) is ``value``.

    The algorithm is told apart by length. SHA-256 and SHA3-256 share 64 hex
    characters, as do SHA-512 and BLAKE2b at 128, so both columns are tried.
    """
    value = value.strip().lower()
    if not _HEX_RE.fullmatch(value):
        return None
    cols = [c for c, n in _DIGEST_HEX_LEN.items() if n == len(value)]
    if not cols:
        return None
    init()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        where = " OR ".join(f"{c} = ?" for c in cols)
        row = conn.execute(
            f"SELECT * FROM image_digests WHERE {where} LIMIT 1", [value] * len(cols)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


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


def _pdq_hashes(data: bytes, dihedral: bool = False) -> list[int]:
    """PDQ hash of ``data`` (all eight rotations/flips if ``dihedral``),
    or [] when PDQ is unavailable, the image undecodable or too flat."""
    if pdqhash is None:
        return []
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.draft("RGB", (_PDQ_SIDE, _PDQ_SIDE))
            rgb = img.convert("RGB")
        rgb.thumbnail((_PDQ_SIDE, _PDQ_SIDE))
        arr = np.asarray(rgb)
        if dihedral:
            vectors, quality = pdqhash.compute_dihedral(arr)
        else:
            vector, quality = pdqhash.compute(arr)
            vectors = [vector]
    except Exception:
        return []
    if quality < PDQ_MIN_QUALITY:
        return []
    # Bits come most significant first, so this is the usual 64-hex PDQ form.
    return [int("".join("1" if b else "0" for b in v), 2) for v in vectors]


def compute_pdq(data: bytes) -> int | None:
    """256-bit PDQ hash of an image, or None (see ``_pdq_hashes``).

    Format it with ``f"{h:064x}"`` to compare with PDQ hashes from other
    tools. CPU-bound — call via ``asyncio.to_thread``.
    """
    hashes = _pdq_hashes(data)
    return hashes[0] if hashes else None


def _match_pdq(data: bytes) -> str | None:
    """Blacklisted image nearest to any rotation/flip of ``data`` by PDQ."""
    if not _pdq_cache:
        return None
    candidates = _pdq_hashes(data, dihedral=True)
    best, best_dist = None, PDQ_MAX_DISTANCE + 1
    for bh, bpdq in list(_pdq_cache.items()):
        for q in candidates:
            dist = (q ^ bpdq).bit_count()
            if dist < best_dist:
                best, best_dist = bh, dist
    return best


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


class _OrbIndex:
    """Nearest-neighbour search over every blacklisted image's ORB descriptors.

    Brute force against all of them costs time in proportion to the
    blacklist (~2s per incoming image at 1,000 blacklisted images), so the
    descriptors live in a faiss index, built in ``load_cache`` and grown in
    place. A removed image's rows stay in the index and are dropped from
    results; the next ``rebuild`` (at restart) leaves them out and
    re-clusters for the current size. Without faiss, search falls back to
    OpenCV brute force in chunks.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owners: list[str | None] = []  # block -> hash, None once removed
        self._descs: list = []  # block -> its descriptors
        self._block_of: dict[str, int] = {}
        self._starts = None  # block -> first row
        self._rows = 0
        self._index = None
        self._bf_all = None  # stacked descriptors for the brute-force fallback

    def __len__(self) -> int:
        return len(self._block_of)

    def rebuild(self, descs: dict[str, object]) -> None:
        with self._lock:
            self._owners = list(descs)
            self._descs = [np.ascontiguousarray(d) for d in descs.values()]
            self._block_of = {h: i for i, h in enumerate(self._owners)}
            sizes = [len(d) for d in self._descs]
            self._starts = np.cumsum([0] + sizes)[:-1].astype(np.int64)
            self._rows = sum(sizes)
            self._build()

    def _build(self) -> None:
        self._index = self._bf_all = None
        n = self._rows
        if faiss is None or n == 0:
            return
        stacked = np.vstack(self._descs)
        if n <= _ORB_FLAT_ROWS:
            index = faiss.IndexBinaryFlat(256)
        else:
            nlist = min(4096, max(64, n // 1000))
            index = faiss.IndexBinaryIVF(faiss.IndexBinaryFlat(256), 256, nlist)
            # k-means needs ~39 points per cluster; more only slows training.
            pick = np.random.default_rng(0).choice(n, min(n, nlist * 39), replace=False)
            index.train(stacked[np.sort(pick)])
            index.nprobe = _ORB_NPROBE
        index.add(stacked)
        self._index = index

    def add(self, hash_hex: str, desc) -> None:
        with self._lock:
            if hash_hex in self._block_of:
                return
            desc = np.ascontiguousarray(desc)
            self._block_of[hash_hex] = len(self._owners)
            self._owners.append(hash_hex)
            self._descs.append(desc)
            start = np.array([self._rows], np.int64)
            self._starts = start if self._starts is None else np.concatenate([self._starts, start])
            self._rows += len(desc)
            self._bf_all = None
            flat = isinstance(self._index, faiss.IndexBinaryFlat) if faiss else False
            if faiss is not None and (self._index is None or (flat and self._rows > _ORB_FLAT_ROWS)):
                self._build()  # first image, or outgrew the exact scan
            elif self._index is not None:
                self._index.add(desc)

    def remove(self, hash_hex: str) -> None:
        with self._lock:
            block = self._block_of.pop(hash_hex, None)
            if block is not None:
                self._owners[block] = None

    def search(self, query) -> dict[str, list[tuple[int, int]]]:
        """Blacklisted hash -> [(its descriptor idx, query descriptor idx)]
        for every query descriptor whose nearest neighbour passes Lowe's
        ratio test."""
        with self._lock:
            if not self._block_of:
                return {}
            if self._index is not None:
                D, I = self._index.search(np.ascontiguousarray(query), 2)
            else:
                D, I = self._brute_force(query)
            # Lowe ratio test. Near-duplicate blacklisted copies would cancel
            # each other out here, which is why only one of them keeps features.
            ok = (I[:, 0] >= 0) & ((I[:, 1] < 0) | (D[:, 0] < 0.75 * D[:, 1]))
            rows = I[ok, 0]
            blocks = np.searchsorted(self._starts, rows, side="right") - 1
            local = rows - self._starts[blocks]
            owners = self._owners
        pairs: dict[str, list[tuple[int, int]]] = {}
        for b, li, qi in zip(blocks.tolist(), local.tolist(), np.nonzero(ok)[0].tolist()):
            h = owners[b]
            if h is not None:
                pairs.setdefault(h, []).append((li, qi))
        return pairs

    def _brute_force(self, query):
        if self._bf_all is None:
            self._bf_all = np.vstack(self._descs)
        D = np.full((len(query), 2), np.inf)
        I = np.full((len(query), 2), -1, np.int64)
        matcher = cv2.BFMatcher(cv2.NORM_HAMMING)
        for start in range(0, len(self._bf_all), _BF_CHUNK):
            chunk = self._bf_all[start : start + _BF_CHUNK]
            for m in matcher.knnMatch(query, chunk, k=2):
                for x in m:
                    q, d, r = x.queryIdx, x.distance, x.trainIdx + start
                    if d < D[q, 0]:
                        D[q, 1], I[q, 1] = D[q, 0], I[q, 0]
                        D[q, 0], I[q, 0] = d, r
                    elif d < D[q, 1]:
                        D[q, 1], I[q, 1] = d, r
        return D, I


_orb_index = _OrbIndex()


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
    if not len(_orb_index):
        return None
    new = compute_features(data, _ORB_NEW_SIDE, _ORB_NEW_FEATURES)
    if new is None:
        return None
    # One index lookup for all query descriptors; only images with enough
    # matches go on to the costlier checks.
    pairs = _orb_index.search(new[1])
    for bh, idx in sorted(pairs.items(), key=lambda kv: -len(kv[1])):
        if len(idx) < _MIN_INLIERS:
            break
        banned = _feature_cache.get(bh)
        if banned is None:
            continue
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
    ``PHASH_MAX_DISTANCE``, then the nearest PDQ hash of any rotation or
    flip within ``PDQ_MAX_DISTANCE``, then a partial match (crop or paste) covering
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
    return _match_pdq(data) or _match_partial(data)


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
    pdq = compute_pdq(data) if data else None
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
            "INSERT OR IGNORE INTO blacklist "
            "(hash, added_at, added_by, source, phash, pdq) VALUES (?, ?, ?, ?, ?, ?)",
            (
                hash_hex,
                int(time.time()),
                added_by,
                source,
                f"{ph:016x}" if ph is not None else None,
                f"{pdq:064x}" if pdq is not None else ("" if data and pdqhash else None),
            ),
        )
        if data:
            _insert_digests(conn, hash_hex, data)
        conn.commit()
        added = cur.rowcount > 0
    finally:
        conn.close()
    if added:
        _cache.add(hash_hex)
        if ph is not None:
            _phash_cache[hash_hex] = ph
        if pdq is not None:
            _pdq_cache[hash_hex] = pdq
        if feat is not None:
            _feature_cache[hash_hex] = feat[:3]
            _orb_index.add(hash_hex, feat[1])
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
        conn.execute("DELETE FROM image_digests WHERE sha256 = ?", (hash_hex,))
        cur = conn.execute("DELETE FROM blacklist WHERE hash = ?", (hash_hex,))
        conn.commit()
        removed = cur.rowcount > 0
    finally:
        conn.close()
    # ``discard`` instead of ``remove`` so an unknown hash is a no-op here
    # even if the row was already gone (e.g. concurrent owner action).
    _cache.discard(hash_hex)
    _phash_cache.pop(hash_hex, None)
    _pdq_cache.pop(hash_hex, None)
    _feature_cache.pop(hash_hex, None)
    _orb_index.remove(hash_hex)
    return removed


_DIGEST_COLS = ", ".join(f"d.{c}" for c in DIGEST_ALGORITHMS)


def list_blacklist() -> list[dict]:
    """Return all blacklist rows, newest first, with their stored digests
    (None for hashes blocked without the image)."""
    init()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            f"SELECT b.hash, b.added_at, b.added_by, b.source, b.phash, NULLIF(b.pdq, '') AS pdq, {_DIGEST_COLS} "
            "FROM blacklist b LEFT JOIN image_digests d ON d.sha256 = b.hash "
            "ORDER BY b.added_at DESC"
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
    """Keep the first reported copy of an image and its digests. Later
    calls are no-ops. Digests are kept even when the file is too big."""
    init()
    conn = _connect()
    try:
        _insert_digests(conn, hash_hex, data)
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

    Each row: hash, count, last_reported_at, data, filename, jump_url and
    the ``DIGEST_ALGORITHMS`` columns (None for reports made before images
    or digests were kept).
    """
    init()
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT r.hash, COUNT(*) AS count, MAX(r.reported_at) AS last_reported_at, "
            f"i.data, i.filename, i.jump_url, {_DIGEST_COLS} "
            "FROM reports r LEFT JOIN report_images i ON i.hash = r.hash "
            "LEFT JOIN image_digests d ON d.sha256 = r.hash "
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
