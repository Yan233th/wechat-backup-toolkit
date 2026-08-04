from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from wechat_backup_converter.crypto import (
    HMAC_SIZE,
    IV_SIZE,
    PAGE_SIZE,
    RESERVE_SIZE,
    SALT_SIZE,
    USABLE_SIZE,
    decrypt_sqlcipher3,
    derive_sqlcipher_keys,
    page_hmac,
)


def _encrypt_fixture(key: bytes, plaintext_pages: list[bytes]) -> bytes:
    salt = bytes(range(SALT_SIZE))
    first_page = salt + bytes(PAGE_SIZE - SALT_SIZE)
    encryption_key, hmac_key = derive_sqlcipher_keys(key, first_page)
    encrypted_pages: list[bytes] = []
    for page_number, plaintext in enumerate(plaintext_pages, 1):
        iv = bytes((page_number + offset) % 256 for offset in range(IV_SIZE))
        source = plaintext[SALT_SIZE:USABLE_SIZE] if page_number == 1 else plaintext[:USABLE_SIZE]
        encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(source) + encryptor.finalize()
        prefix = salt + ciphertext if page_number == 1 else ciphertext
        page = bytearray(prefix + iv + bytes(HMAC_SIZE) + bytes(RESERVE_SIZE - IV_SIZE - HMAC_SIZE))
        digest = page_hmac(hmac_key, bytes(page), page_number)
        page[USABLE_SIZE + IV_SIZE : USABLE_SIZE + IV_SIZE + HMAC_SIZE] = digest
        encrypted_pages.append(bytes(page))
    return b"".join(encrypted_pages)


def test_sqlcipher3_authentication_and_decryption(tmp_path: Path) -> None:
    key = b"0123456789abcdef0123456789abcdef"
    pages = []
    for page_number in (1, 2):
        page = bytearray(PAGE_SIZE)
        if page_number == 1:
            page[:SALT_SIZE] = b"SQLite format 3\x00"
        for offset in range(SALT_SIZE if page_number == 1 else 0, USABLE_SIZE):
            page[offset] = (page_number * 17 + offset) % 256
        pages.append(bytes(page))
    encrypted = tmp_path / "Backup.db"
    decrypted = tmp_path / "Backup.decrypted.db"
    encrypted.write_bytes(_encrypt_fixture(key, pages))
    assert decrypt_sqlcipher3(encrypted, decrypted, key) == 2
    assert decrypted.read_bytes() == b"".join(pages)


def test_sqlcipher3_rejects_wrong_key(tmp_path: Path) -> None:
    key = b"0123456789abcdef0123456789abcdef"
    page = bytearray(PAGE_SIZE)
    page[:SALT_SIZE] = b"SQLite format 3\x00"
    encrypted = tmp_path / "Backup.db"
    encrypted.write_bytes(_encrypt_fixture(key, [bytes(page)]))
    with pytest.raises(ValueError, match="HMAC validation failed"):
        decrypt_sqlcipher3(encrypted, tmp_path / "wrong.db", b"x" * 32)
