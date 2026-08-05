import sqlite3
from pathlib import Path

import pytest

from wechat_backup_converter.export import _publish_output, initialize_output
from wechat_backup_converter.proto import parse_message, validate_message_media


def test_publish_new_output(tmp_path: Path) -> None:
    partial = tmp_path / "partial.db"
    output = tmp_path / "output.db"
    partial.write_bytes(b"new")
    assert _publish_output(partial, output, False) is None
    assert output.read_bytes() == b"new"


def test_publish_overwrite_keeps_backup(tmp_path: Path) -> None:
    partial = tmp_path / "partial.db"
    output = tmp_path / "output.db"
    partial.write_bytes(b"new")
    output.write_bytes(b"old")
    backup = _publish_output(partial, output, True)
    assert backup is not None
    assert output.read_bytes() == b"new"
    assert backup.read_bytes() == b"old"


def test_publish_refuses_overwrite(tmp_path: Path) -> None:
    partial = tmp_path / "partial.db"
    output = tmp_path / "output.db"
    partial.write_bytes(b"new")
    output.write_bytes(b"old")
    with pytest.raises(FileExistsError):
        _publish_output(partial, output, False)
    assert partial.read_bytes() == b"new"
    assert output.read_bytes() == b"old"


def test_message_media_count_must_match_paths() -> None:
    message = parse_message(bytes([0x50, 0x01]))
    with pytest.raises(ValueError, match="media_count=1, paths=0"):
        validate_message_media(message, "message 7")


def test_message_schema_contains_only_translated_fields() -> None:
    db = sqlite3.connect(":memory:")
    initialize_output(db)
    columns = {row[1] for row in db.execute("PRAGMA table_info(messages)")}
    assert {
        "raw_proto",
        "unknown_fields_json",
        "embedded_data",
        "embedded_declared_length",
        "embedded_data_length",
        "embedded_media_type",
    }.isdisjoint(columns)
