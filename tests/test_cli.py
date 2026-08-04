from wechat_backup_converter.cli import _parse_key_record


def test_parse_key_record() -> None:
    assert (
        _parse_key_record("Header\n  Key: 0123456789abcdef0123456789abcdef\n")
        == "0123456789abcdef0123456789abcdef"
    )


def test_parse_raw_key() -> None:
    assert (
        _parse_key_record("0123456789abcdef0123456789abcdef\n")
        == "0123456789abcdef0123456789abcdef"
    )
