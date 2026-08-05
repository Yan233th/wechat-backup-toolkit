from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .archive import BackupPaths
from .crypto import decrypt_ecb_slot
from .index import BackupIndex, load_index
from .media import decrypt_one_media
from .proto import parse_message, parse_segment, validate_message_media


@dataclass(frozen=True)
class VerificationResult:
    conversations: int
    text_segments: int
    messages: int
    media_objects: int
    encrypted_media_bytes: int
    plaintext_media_bytes: int
    media_formats: dict[str, int]


def _verify_text(paths: BackupPaths, index: BackupIndex, key: bytes) -> int:
    message_count = 0
    with paths.text.open("rb") as source:
        for number, segment in enumerate(index.text_segments, 1):
            plaintext = decrypt_ecb_slot(source, segment.offset, segment.length, key)
            _, raw_messages = parse_segment(plaintext)
            for ordinal, raw in enumerate(raw_messages):
                message = parse_message(raw)
                message_count += 1
                label = f"segment {segment.row_id} message {ordinal}"
                validate_message_media(message, label)
                for identifier in message.media_paths:
                    if identifier is None or identifier not in index.by_identifier:
                        raise ValueError(f"{label}: unknown media identifier {identifier!r}")
            if number % 250 == 0 or number == len(index.text_segments):
                print(
                    f"verify text: {number}/{len(index.text_segments)} segments, "
                    f"{message_count} messages",
                    flush=True,
                )
    return message_count


def _verify_media(
    paths: BackupPaths, index: BackupIndex, key: bytes
) -> tuple[int, int, Counter[str]]:
    files = {name: path.open("rb") for name, path in paths.media.items()}
    encrypted_bytes = 0
    plaintext_bytes = 0
    formats: Counter[str] = Counter()
    try:
        for number, media in enumerate(index.media_order, 1):
            result = decrypt_one_media(key, files, media, None, False)
            encrypted_bytes += media.encrypted_size
            plaintext_bytes += int(result["plaintext_size"])
            formats[str(result["detected_format"])] += 1
            if number % 500 == 0 or number == len(index.media_order):
                print(f"verify media: {number}/{len(index.media_order)} objects", flush=True)
    finally:
        for file in files.values():
            file.close()
    return encrypted_bytes, plaintext_bytes, formats


def verify_backup(paths: BackupPaths, decrypted_index: Path, key: bytes) -> VerificationResult:
    index = load_index(decrypted_index, paths, require_media=True)
    print(
        f"index: {len(index.conversations)} conversations, "
        f"{len(index.text_segments)} text segments, {len(index.media)} media objects"
    )
    message_count = _verify_text(paths, index, key[:16])
    encrypted_bytes, plaintext_bytes, formats = _verify_media(paths, index, key[:16])
    result = VerificationResult(
        conversations=len(index.conversations),
        text_segments=len(index.text_segments),
        messages=message_count,
        media_objects=len(index.media),
        encrypted_media_bytes=encrypted_bytes,
        plaintext_media_bytes=plaintext_bytes,
        media_formats=dict(sorted(formats.items())),
    )
    print(
        "verified: "
        f"{result.text_segments} text segments, {result.messages} messages, "
        f"{result.media_objects} media objects"
    )
    print(
        f"media bytes: encrypted={result.encrypted_media_bytes}, "
        f"plaintext={result.plaintext_media_bytes}"
    )
    return result
