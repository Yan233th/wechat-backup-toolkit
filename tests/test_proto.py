from wechat_backup_converter.proto import parse_message, parse_proto


def test_parse_proto_varint_and_bytes() -> None:
    fields = parse_proto(bytes([0x08, 0x96, 0x01, 0x12, 0x03]) + b"abc")
    assert fields[0].value == 150
    assert fields[1].value == b"abc"


def test_empty_repeated_fields_are_arrays() -> None:
    message = parse_message(bytes([0x08, 0x01]))
    assert message.media_paths == []
    assert message.media_types == []
    assert message.unknown_fields_json == "[]"


def test_parse_message_media_fields() -> None:
    etl = bytes([0x0A, 0x03]) + b"id1"
    etm = bytes([0x08, 0x09])
    raw = bytes([0x08, 0x01, 0x50, 0x01, 0x5A, len(etl)]) + etl
    raw += bytes([0x62, len(etm)]) + etm
    message = parse_message(raw)
    assert message.msg_type == 1
    assert message.media_paths == ["id1"]
    assert message.media_types == [9]
