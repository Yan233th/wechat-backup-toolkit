import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from wechat_backup_converter.index import MediaObject, MediaRecord, MediaSegment
from wechat_backup_converter.media import decrypt_one_media, detect_media_format


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\xff\xd8\xff\x00", ("jpeg", "jpg")),
        (b"\x89PNG\r\n\x1a\nrest", ("png", "png")),
        (b"\x02#!SILK_V3rest", ("silk", "silk")),
        (b"wxgf\x13\x00rest", ("wechat-wxgf", "wxgf")),
        (b"\xff\xfb\x90\x64", ("mpeg-audio", "mp3")),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ("ole-compound-document", "ole")),
        (b"title<div><object></object></div>\x00", ("html", "html")),
    ],
)
def test_detect_media_format(data: bytes, expected: tuple[str, str]) -> None:
    assert detect_media_format(data) == expected


def test_decrypt_media_across_containers(tmp_path) -> None:
    key = b"0123456789abcdef"
    plain = b"\xff\xd8\xff\xe0test-cross-container"
    padding = 16 - len(plain) % 16
    padded = plain + bytes([padding]) * padding
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    paths = [tmp_path / "BAK_0_MEDIA", tmp_path / "BAK_1_MEDIA"]
    paths[0].write_bytes(ciphertext[:16])
    paths[1].write_bytes(ciphertext[16:])
    files = {path.name: path.open("rb") for path in paths}
    record = MediaRecord(1, 1, 1, 1, "", "talker", "identifier")
    obj = MediaObject(
        media_id=1,
        record=record,
        containers=["BAK_0_MEDIA", "BAK_1_MEDIA"],
        encrypted_size=len(ciphertext),
        segments=[
            MediaSegment(1, "1", 0, 16, len(ciphertext), 0, "BAK_0_MEDIA"),
            MediaSegment(2, "1", 16, len(ciphertext) - 16, len(ciphertext), 0, "BAK_1_MEDIA"),
        ],
    )
    try:
        result = decrypt_one_media(key, files, obj, None, False)
    finally:
        for file in files.values():
            file.close()
    assert result["plaintext_size"] == len(plain)
    assert result["detected_format"] == "jpeg"
    assert result["plaintext_sha256"] == hashlib.sha256(plain).hexdigest()
