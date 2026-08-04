import pytest

from wechat_backup_converter.crypto import _pbkdf2_sha1, unpad_pkcs7


@pytest.mark.parametrize(
    ("iterations", "expected"),
    [
        (1, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        (2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        (4096, "4b007901b765489abead49d926f721d065a429c1"),
    ],
)
def test_pbkdf2_sha1_vectors(iterations: int, expected: str) -> None:
    assert _pbkdf2_sha1(b"password", b"salt", iterations, 20).hex() == expected


def test_pkcs7_unpadding() -> None:
    assert unpad_pkcs7(b"hello world" + bytes([5]) * 5) == b"hello world"
    with pytest.raises(ValueError, match="padding"):
        unpad_pkcs7(b"invalid padding!")
