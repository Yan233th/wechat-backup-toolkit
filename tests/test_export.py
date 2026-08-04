from pathlib import Path

import pytest

from wechat_backup_converter.export import _publish_output


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
