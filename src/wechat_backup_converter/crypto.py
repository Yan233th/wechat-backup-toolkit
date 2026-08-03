from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PAGE_SIZE = 4096
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
HMAC_SIZE = 20
RESERVE_SIZE = 48
USABLE_SIZE = PAGE_SIZE - RESERVE_SIZE
CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def derive_sqlcipher_keys(passphrase: bytes, first_page: bytes) -> tuple[bytes, bytes]:
    if len(passphrase) != KEY_SIZE:
        raise ValueError("backup key must be exactly 32 literal bytes")
    if len(first_page) != PAGE_SIZE:
        raise ValueError("invalid SQLCipher page")
    encryption_key = _pbkdf2_sha1(passphrase, first_page[:SALT_SIZE], 64000, KEY_SIZE)
    hmac_salt = bytes(value ^ 0x3A for value in first_page[:SALT_SIZE])
    hmac_key = _pbkdf2_sha1(encryption_key, hmac_salt, 2, KEY_SIZE)
    return encryption_key, hmac_key


def _pbkdf2_sha1(password: bytes, salt: bytes, iterations: int, length: int) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=length,
        salt=salt,
        iterations=iterations,
    ).derive(password)


def page_hmac(hmac_key: bytes, page: bytes, page_number: int) -> bytes:
    if len(page) != PAGE_SIZE:
        raise ValueError("invalid SQLCipher page size")
    if page_number == 1:
        data = page[SALT_SIZE : SALT_SIZE + PAGE_SIZE - SALT_SIZE - RESERVE_SIZE + IV_SIZE]
    else:
        data = page[: PAGE_SIZE - RESERVE_SIZE + IV_SIZE]
    return hmac.new(hmac_key, data + page_number.to_bytes(4, "little"), hashlib.sha1).digest()


def _decrypt_sqlcipher_page(encryption_key: bytes, page: bytes, page_number: int) -> bytes:
    ciphertext = page[SALT_SIZE:USABLE_SIZE] if page_number == 1 else page[:USABLE_SIZE]
    iv = page[USABLE_SIZE : USABLE_SIZE + IV_SIZE]
    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    output = bytearray(PAGE_SIZE)
    if page_number == 1:
        output[:SALT_SIZE] = b"SQLite format 3\x00"
        output[SALT_SIZE : SALT_SIZE + len(plaintext)] = plaintext
    else:
        output[: len(plaintext)] = plaintext
    return bytes(output)


def decrypt_sqlcipher3(input_path: Path, output_path: Path, passphrase: bytes) -> int:
    size = input_path.stat().st_size
    if size <= 0 or size % PAGE_SIZE:
        raise ValueError(f"encrypted database size is not a positive multiple of {PAGE_SIZE}")
    page_count = size // PAGE_SIZE
    with input_path.open("rb") as source:
        first_page = source.read(PAGE_SIZE)
        encryption_key, hmac_key = derive_sqlcipher_keys(passphrase, first_page)
        source.seek(0)
        for page_number in range(1, page_count + 1):
            page = source.read(PAGE_SIZE)
            if len(page) != PAGE_SIZE:
                raise ValueError(f"truncated SQLCipher page {page_number}")
            expected = page[USABLE_SIZE + IV_SIZE : USABLE_SIZE + IV_SIZE + HMAC_SIZE]
            actual = page_hmac(hmac_key, page, page_number)
            if not hmac.compare_digest(actual, expected):
                raise ValueError(f"SQLCipher HMAC validation failed at page {page_number}")

        source.seek(0)
        with output_path.open("wb") as output:
            for page_number in range(1, page_count + 1):
                page = source.read(PAGE_SIZE)
                output.write(_decrypt_sqlcipher_page(encryption_key, page, page_number))
            output.flush()
            os.fsync(output.fileno())
    os.chmod(output_path, 0o600)
    return page_count


def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("empty PKCS#7 input")
    padding = data[-1]
    if padding < 1 or padding > block_size or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("invalid AES/PKCS#7 padding")
    return data[:-padding]


def decrypt_ecb_slot(source, offset: int, length: int, key: bytes) -> bytes:
    if length <= 0 or length % 16:
        raise ValueError(f"invalid AES-ECB slot length {length}")
    source.seek(offset)
    decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    parts: list[bytes] = []
    remaining = length
    while remaining:
        chunk = source.read(min(CHUNK_SIZE, remaining))
        if len(chunk) == 0:
            raise ValueError("truncated encrypted slot")
        if len(chunk) % 16:
            raise ValueError("encrypted slot chunk is not AES block aligned")
        parts.append(decryptor.update(chunk))
        remaining -= len(chunk)
    parts.append(decryptor.finalize())
    return unpad_pkcs7(b"".join(parts))
