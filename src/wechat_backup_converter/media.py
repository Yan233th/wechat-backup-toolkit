from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .crypto import CHUNK_SIZE, unpad_pkcs7
from .index import MediaObject


def detect_media_format(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg", "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif", "gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", "webp"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12].strip()
        return ("quicktime", "mov") if brand.startswith(b"qt") else ("mp4", "mp4")
    if data.startswith(b"#!SILK_V3") or (
        len(data) > 1 and data[0] == 2 and data[1:].startswith(b"#!SILK_V3")
    ):
        return "silk", "silk"
    if data.startswith(b"#!AMR"):
        return "amr", "amr"
    if data[:4].lower() == b"wxgf":
        return "wechat-wxgf", "wxgf"
    if len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE0 == 0xE0:
        return "mpeg-audio", "mp3"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole-compound-document", "ole"
    if data.startswith(b"OggS"):
        return "ogg", "ogg"
    if data.startswith(b"%PDF"):
        return "pdf", "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "zip", "zip"
    trimmed = data.strip()
    if trimmed:
        try:
            lower = trimmed[:256].decode("utf-8", "strict").lower()
        except UnicodeDecodeError:
            return "binary", "bin"
        if lower.startswith(("<!doctype html", "<html")) or any(
            token in lower for token in ("<div", "<object", "<p>", "<br")
        ):
            return "html", "html"
        if lower.startswith(("<?xml", "<msg", "<appmsg")):
            return "xml", "xml"
        if lower.startswith(("{", "[")):
            return "json-or-text", "json"
        return "text", "txt"
    return "binary", "bin"


def select_media_objects(
    mode: str,
    media_limit: int,
    media_order: list[MediaObject],
    media_types: dict[int, set[int]],
) -> list[MediaObject]:
    if mode == "all":
        return list(media_order)
    if mode != "sample":
        return []
    selected: dict[int, MediaObject] = {}
    by_id = {item.media_id: item for item in media_order}
    for media_type in sorted({value for values in media_types.values() for value in values}):
        candidates = [
            by_id[media_id] for media_id, values in media_types.items() if media_type in values
        ]
        if candidates:
            best = min(candidates, key=lambda item: (item.encrypted_size, item.media_id))
            selected[best.media_id] = best
    for item in sorted(media_order, key=lambda value: (value.encrypted_size, value.media_id)):
        if len(selected) >= media_limit:
            break
        selected[item.media_id] = item
    return [selected[media_id] for media_id in sorted(selected)][:media_limit]


def prepare_media_root(path: Path) -> Path:
    path = path.expanduser().resolve()
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
    elif not path.is_dir():
        raise ValueError(f"media output is not a directory: {path}")
    elif any(path.iterdir()):
        raise ValueError(f"refusing to use non-empty media directory {path}")
    os.chmod(path, 0o700)
    return path


def decrypt_one_media(
    key: bytes,
    files: dict[str, BinaryIO],
    obj: MediaObject,
    media_root: Path | None,
    write_file: bool,
) -> dict[str, object]:
    if obj.encrypted_size <= 0 or obj.encrypted_size % 16:
        raise ValueError(f"invalid encrypted size {obj.encrypted_size}")
    output = None
    partial_path: Path | None = None
    directory: Path | None = None
    if write_file:
        assert media_root is not None
        directory = media_root / f"{obj.media_id // 1000:05d}"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        partial_path = directory / f"{obj.media_id:08d}.partial"
        output = partial_path.open("xb")
        os.chmod(partial_path, 0o600)
    ok = False
    try:
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        tail = b""
        header = bytearray()
        digest = hashlib.sha256()
        plaintext_size = 0
        processed = 0

        def emit(data: bytes) -> None:
            nonlocal plaintext_size
            if not data:
                return
            if len(header) < 4096:
                header.extend(data[: 4096 - len(header)])
            digest.update(data)
            if output is not None:
                output.write(data)
            plaintext_size += len(data)

        for segment in obj.segments:
            source = files[segment.container]
            source.seek(segment.offset)
            remaining = segment.length
            while remaining:
                chunk = source.read(min(CHUNK_SIZE, remaining))
                if len(chunk) != min(CHUNK_SIZE, remaining):
                    raise ValueError(f"truncated media container {segment.container}")
                if len(chunk) % 16:
                    raise ValueError("media chunk is not AES block aligned")
                plain = decryptor.update(chunk)
                combined = tail + plain
                if len(combined) > 16:
                    emit(combined[:-16])
                    tail = combined[-16:]
                else:
                    tail = combined
                remaining -= len(chunk)
                processed += len(chunk)
        if decryptor.finalize():
            raise ValueError("unexpected buffered AES plaintext")
        tail = unpad_pkcs7(tail)
        emit(tail)
        if processed != obj.encrypted_size:
            raise ValueError(f"processed {processed} bytes, expected {obj.encrypted_size}")
        format_name, extension = detect_media_format(bytes(header))
        result: dict[str, object] = {
            "plaintext_size": plaintext_size,
            "detected_format": format_name,
            "plaintext_sha256": digest.hexdigest(),
            "output_path": None,
            "extraction_status": "verified",
        }
        if output is not None:
            output.flush()
            os.fsync(output.fileno())
            output.close()
            output = None
            assert directory is not None and partial_path is not None
            final_path = directory / f"{obj.media_id:08d}.{extension}"
            if final_path.exists():
                raise FileExistsError(f"refusing to overwrite {final_path}")
            partial_path.rename(final_path)
            result["output_path"] = str(final_path.relative_to(media_root).as_posix())
            result["extraction_status"] = "extracted"
        ok = True
        return result
    finally:
        if output is not None:
            output.close()
        if not ok and partial_path is not None:
            partial_path.unlink(missing_ok=True)
