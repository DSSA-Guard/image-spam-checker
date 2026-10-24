"""Image reports: the owner's pending list keeps the image and drops blacklisted hashes."""

import os
import tempfile

os.environ["IMAGE_CHECKER_DATA_DIR"] = tempfile.mkdtemp()

from app import engine as ib


def test_pending_reports_show_image_and_hide_blacklisted():
    ib.record_report("a" * 64, 1)
    ib.record_report("a" * 64, 2)
    ib.save_report_image("a" * 64, b"img", "x.png", "https://discord.com/x")
    ib.save_report_image("a" * 64, b"other", "y.png", "")  # first copy wins
    ib.record_report("b" * 64, 1)  # pre-feature report: no stored image

    rows = {r["hash"]: r for r in ib.list_pending_reports(10)}
    assert rows["a" * 64]["count"] == 2
    assert rows["a" * 64]["data"] == b"img"
    assert rows["b" * 64]["data"] is None

    ib.add_to_blacklist("a" * 64)
    assert "a" * 64 not in {r["hash"] for r in ib.list_pending_reports(10)}

    ib.remove_from_blacklist("a" * 64)  # wipes reports and the stored image
    assert "a" * 64 not in {r["hash"] for r in ib.list_pending_reports(10)}


def test_oversized_image_keeps_only_link():
    ib.record_report("c" * 64, 1)
    ib.save_report_image("c" * 64, b"0" * (ib.MAX_STORED_IMAGE_BYTES + 1), "big.png", "u")
    row = next(r for r in ib.list_pending_reports(10) if r["hash"] == "c" * 64)
    assert row["data"] is None and row["jump_url"] == "u"


def _photo(seed: int, size=(320, 240), fmt="PNG", quality=90) -> bytes:
    import io
    import random

    from PIL import Image, ImageDraw

    rnd = random.Random(seed)
    img = Image.new("RGB", size, (rnd.randrange(256), 0, 0))
    draw = ImageDraw.Draw(img)
    for _ in range(25):
        x, y = rnd.randrange(size[0]), rnd.randrange(size[1])
        draw.ellipse(
            (x, y, x + rnd.randrange(20, 120), y + rnd.randrange(20, 120)),
            fill=tuple(rnd.randrange(256) for _ in range(3)),
        )
    buf = io.BytesIO()
    img.save(buf, fmt, quality=quality)
    return buf.getvalue()


def _reencode(data: bytes, size=None, fmt="JPEG") -> bytes:
    import io

    from PIL import Image

    img = Image.open(io.BytesIO(data)).convert("RGB")
    if size:
        img = img.resize(size)
    buf = io.BytesIO()
    img.save(buf, fmt, quality=70)
    return buf.getvalue()


def test_reencoded_or_resized_copy_is_still_caught():
    original = _photo(1)
    h = ib.compute_hash_bytes(original)
    ib.add_to_blacklist(h, source="auto_report", data=original)

    assert ib.match_image(original) == h
    # Copy-paste / screenshot / resize change every byte, so SHA-256 alone missed these.
    for copy in (_reencode(original), _reencode(original, (160, 120), "PNG"), _reencode(original, (800, 600))):
        assert ib.compute_hash_bytes(copy) != h
        assert ib.match_image(copy) == h

    assert ib.match_image(_photo(2)) is None
    ib.remove_from_blacklist(h)
    assert ib.match_image(_reencode(original)) is None


def test_web_block_uses_stored_report_copy_for_perceptual_hash():
    original = _photo(3)
    h = ib.compute_hash_bytes(original)
    ib.record_report(h, 1)
    ib.save_report_image(h, original, "x.png", "")
    ib.add_to_blacklist(h, source="web_admin")  # no data passed, like the admin panel
    assert ib.match_image(_reencode(original)) == h


def test_flat_images_have_no_perceptual_hash():
    import io

    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (100, 100), (255, 255, 255)).save(buf, "PNG")
    assert ib.compute_phash(buf.getvalue()) is None
    assert ib.compute_phash(b"not an image") is None



def _scene(seed: int, size=(640, 480)):
    import random

    from PIL import Image, ImageDraw

    rnd = random.Random(seed)
    img = Image.new("RGB", size, tuple(rnd.randrange(256) for _ in range(3)))
    draw = ImageDraw.Draw(img)
    for _ in range(60):
        x, y = rnd.randrange(size[0]), rnd.randrange(size[1])
        pts = [(x + rnd.randrange(-60, 60), y + rnd.randrange(-60, 60)) for _ in range(rnd.randrange(3, 6))]
        draw.polygon(pts, fill=tuple(rnd.randrange(256) for _ in range(3)))
    for _ in range(15):
        text = "".join(rnd.choice("ABCXYZ0123") for _ in range(6))
        draw.text((rnd.randrange(size[0]), rnd.randrange(size[1])), text, fill=(0, 0, 0))
    return img


def _jpeg(img) -> bytes:
    import io

    buf = io.BytesIO()
    img.convert("RGB").save(buf, "JPEG", quality=80)
    return buf.getvalue()


def _block(img) -> str:
    data = _jpeg(img)
    h = ib.compute_hash_bytes(data)
    ib.record_report(h, 1)
    ib.save_report_image(h, data, "x.jpg", "")
    ib.add_to_blacklist(h, source="auto_report", data=data)
    return h


def test_partial_copies_covering_60_percent_are_caught():
    from PIL import Image, ImageDraw

    banned = _scene(1)
    h = _block(banned)
    for other in range(500, 505):  # unrelated entries must not drown the match
        _block(_scene(other))
    _block(banned.resize((600, 450)))  # a second blacklisted copy of the same picture
    w, hgt = banned.size

    crop = banned.crop((0, 0, int(w * 0.6), int(hgt * 0.6)))
    caption = Image.new("RGB", (w, int(hgt * 1.4)), "white")
    caption.paste(banned, (0, int(hgt * 0.4)))
    ImageDraw.Draw(caption).text((20, 20), "WHEN YOU SEE IT", fill="black")
    collage = _scene(50, (1280, 960))
    collage.paste(banned, (0, 0))
    for copy in (crop, caption, collage, banned.rotate(10, expand=True)):
        assert ib.match_image(_jpeg(copy)) == h

    def half_and_half(frac):
        mixed = _scene(77)
        mixed.paste(banned.crop((0, 0, int(w * frac), hgt)), (0, 0))
        return _jpeg(mixed)

    assert ib.match_image(half_and_half(0.7)) == h
    assert ib.match_image(half_and_half(0.5)) is None

    shared_logo = _scene(3)
    shared_logo.paste(banned.crop((200, 150, 400, 300)), (50, 50))  # ~10% in common
    assert ib.match_image(_jpeg(shared_logo)) is None
    for seed in range(100, 110):
        assert ib.match_image(_jpeg(_scene(seed))) is None


def test_images_keep_digests_of_every_algorithm():
    import hashlib

    data = _photo(7)
    h = ib.compute_hash_bytes(data)
    ib.record_report(h, 1)
    ib.save_report_image(h, data, "d.png", "")

    want = {
        "sha256": h,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "sha3_256": hashlib.sha3_256(data).hexdigest(),
        "blake2b": hashlib.blake2b(data).hexdigest(),
    }
    assert ib.compute_digests(data) == want
    for value in want.values():
        assert ib.find_by_digest(value.upper()) == want
    assert ib.find_by_digest("0" * 32) is None
    assert ib.find_by_digest("not hex") is None

    pending = next(r for r in ib.list_pending_reports(10) if r["hash"] == h)
    assert pending["md5"] == want["md5"]

    ib.add_to_blacklist(h)
    row = next(r for r in ib.list_blacklist() if r["hash"] == h)
    assert row["sha1"] == want["sha1"] and row["blake2b"] == want["blake2b"]

    ib.remove_from_blacklist(h)
    assert ib.find_by_digest(want["md5"]) is None


def test_digests_skip_mismatched_hash():
    ib.save_report_image("e" * 64, b"img", "x.png", "")
    assert ib.find_by_digest("e" * 64) is None
    assert ib.find_by_digest(ib.compute_digests(b"img")["md5"]) is None
