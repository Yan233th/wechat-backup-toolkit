from wechat_backup_converter.cli import _parse_key_record, build_parser


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


def test_convert_media_choices_exclude_verify() -> None:
    parser = build_parser()
    args = parser.parse_args(["convert", "--input", "backup", "--media", "all"])
    assert args.command == "convert"
    assert args.media == "all"


def test_verify_is_a_separate_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["verify", "--input", "backup"])
    assert args.command == "verify"
    assert not hasattr(args, "output")
