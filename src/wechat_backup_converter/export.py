from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from .archive import BackupPaths
from .crypto import decrypt_ecb_slot, sha256_file
from .index import BackupIndex, TextSegment, load_index
from .media import decrypt_one_media, prepare_media_root, select_media_objects
from .proto import ParsedMessage, parse_message, parse_segment


@dataclass
class ExportConfig:
    output: Path
    media_mode: str
    media_dir: Path | None
    media_limit: int
    compact: bool
    overwrite: bool


def _iso_utc8(seconds: int) -> str:
    zone = timezone(timedelta(hours=8))
    return datetime.fromtimestamp(seconds, zone).isoformat()


def _connect_output(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA temp_store=MEMORY")
    db.execute("PRAGMA foreign_keys=OFF")
    return db


def initialize_output(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE export_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE backup_info (
          id INTEGER PRIMARY KEY CHECK(id=1), account_id TEXT, device_id TEXT,
          start_time INTEGER, end_time INTEGER, start_time_iso TEXT, end_time_iso TEXT,
          manufacturer TEXT, model TEXT, platform TEXT, platform_version TEXT,
          client_version INTEGER, device_value INTEGER
        );
        CREATE TABLE conversations (
          talker TEXT PRIMARY KEY, end_time INTEGER, total_size INTEGER, nickname TEXT,
          reserved0 INTEGER, reserved1 INTEGER, reserved2 TEXT, reserved3 TEXT,
          start_time INTEGER, reserved5 TEXT
        );
        CREATE TABLE name_map (talker_id INTEGER PRIMARY KEY, username TEXT NOT NULL);
        CREATE TABLE segments (
          source_rowid INTEGER PRIMARY KEY, talker_id INTEGER, start_time INTEGER,
          end_time INTEGER, source_offset INTEGER, encrypted_length INTEGER,
          username TEXT, status INTEGER, reserved1 INTEGER, file_path TEXT,
          segment_id TEXT, reserved2 TEXT, reserved3 TEXT, declared_count INTEGER,
          parsed_count INTEGER, padding_length INTEGER
        );
        CREATE TABLE messages (
          id INTEGER PRIMARY KEY, segment_rowid INTEGER NOT NULL,
          ordinal_in_segment INTEGER NOT NULL, msg_type INTEGER,
          from_username TEXT, to_username TEXT, content TEXT, status INTEGER,
          create_time INTEGER, create_time_ms INTEGER, msg_server_id INTEGER,
          msg_seq INTEGER, flag INTEGER, legacy_server_id INTEGER, field2_text TEXT,
          field8_text TEXT, media_count INTEGER, media_paths_json TEXT,
          media_types_json TEXT, embedded_declared_length INTEGER,
          embedded_data_length INTEGER, embedded_media_type INTEGER,
          embedded_data BLOB, unknown_fields_json TEXT, raw_proto BLOB,
          UNIQUE(segment_rowid, ordinal_in_segment)
        );
        CREATE TABLE media (
          media_id INTEGER PRIMARY KEY, identifier TEXT NOT NULL UNIQUE,
          talker_id INTEGER, talker TEXT, msg_segment_id INTEGER, server_id INTEGER,
          source_md5 TEXT, first_container TEXT NOT NULL, containers_json TEXT NOT NULL,
          first_source_offset INTEGER NOT NULL, encrypted_size INTEGER NOT NULL,
          segment_count INTEGER NOT NULL, media_type_codes_json TEXT,
          plaintext_size INTEGER, detected_format TEXT, output_path TEXT,
          plaintext_sha256 TEXT, extraction_status TEXT NOT NULL DEFAULT 'indexed'
        );
        CREATE TABLE media_segments (
          media_id INTEGER NOT NULL, ordinal INTEGER NOT NULL, source_rowid INTEGER NOT NULL,
          container TEXT NOT NULL, source_offset INTEGER NOT NULL, inner_offset INTEGER NOT NULL,
          length INTEGER NOT NULL, total_length INTEGER NOT NULL,
          PRIMARY KEY(media_id, ordinal)
        );
        CREATE TABLE message_media (
          message_id INTEGER NOT NULL, ordinal INTEGER NOT NULL, media_id INTEGER NOT NULL,
          media_type INTEGER, identifier TEXT NOT NULL,
          PRIMARY KEY(message_id, ordinal)
        );
        """
    )


def seed_output(
    db: sqlite3.Connection,
    index: BackupIndex,
    paths: BackupPaths,
    key_hash: str,
    config: ExportConfig,
) -> None:
    metadata = {
        "format": "wechat-pc-backup-export-python-v1",
        "converter_version": "0.1.0",
        "exported_at_utc": datetime.now(UTC).isoformat(),
        "source_backup_db_sha256": sha256_file(paths.backup_db),
        "source_text_sha256": sha256_file(paths.text),
        "backup_key_sha256": key_hash,
        "backup_key_stored": "false",
        "message_proto": "com.tencent.mm.protocal.protobuf.je/jd",
        "media_mode": config.media_mode,
        "compact": str(config.compact).lower(),
    }
    db.executemany("INSERT INTO export_meta(key,value) VALUES (?,?)", sorted(metadata.items()))
    info = index.metadata
    db.execute(
        "INSERT INTO backup_info VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            info.account_id,
            info.device_id,
            info.start_time,
            info.end_time,
            _iso_utc8(info.start_time),
            _iso_utc8(info.end_time),
            info.manufacturer,
            info.model,
            info.platform,
            info.platform_version,
            info.client_version,
            info.device_value,
        ),
    )
    db.executemany(
        "INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            (
                item.talker,
                item.end_time,
                item.total_size,
                item.nickname,
                item.reserved0,
                item.reserved1,
                item.reserved2,
                item.reserved3,
                item.start_time,
                item.reserved5,
            )
            for item in index.conversations
        ],
    )
    db.executemany("INSERT INTO name_map VALUES (?,?)", sorted(index.names.items()))
    for obj in index.media.values():
        db.execute(
            """INSERT INTO media(media_id,identifier,talker_id,talker,msg_segment_id,server_id,
            source_md5,first_container,containers_json,first_source_offset,encrypted_size,segment_count)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                obj.media_id,
                obj.record.identifier,
                obj.record.talker_id,
                obj.record.talker,
                obj.record.msg_segment_id,
                obj.record.server_id,
                obj.record.source_md5,
                obj.first_container,
                json.dumps(obj.containers, separators=(",", ":")),
                obj.first_offset,
                obj.encrypted_size,
                len(obj.segments),
            ),
        )
        db.executemany(
            "INSERT INTO media_segments VALUES (?,?,?,?,?,?,?,?)",
            [
                (
                    obj.media_id,
                    ordinal,
                    segment.row_id,
                    segment.container,
                    segment.offset,
                    segment.inner_offset,
                    segment.length,
                    segment.total_length,
                )
                for ordinal, segment in enumerate(obj.segments)
            ],
        )


def _decrypt_text_segment(source, segment: TextSegment, key: bytes) -> bytes:
    return decrypt_ecb_slot(source, segment.offset, segment.length, key)


def _message_values(message: ParsedMessage, compact: bool) -> tuple[object, ...]:
    return (
        message.msg_type,
        message.from_username,
        message.to_username,
        message.content,
        message.status,
        message.create_time,
        message.create_time_ms,
        message.msg_server_id,
        message.msg_seq,
        message.flag,
        message.legacy_server_id,
        message.field2_text,
        message.field8_text,
        message.media_count,
        message.media_paths_json,
        message.media_types_json,
        message.embedded_declared_length,
        message.embedded_data_length,
        message.embedded_media_type,
        None if compact else message.embedded_data,
        message.unknown_fields_json,
        None if compact else message.raw,
    )


def export_text(
    db: sqlite3.Connection,
    text_path: Path,
    key: bytes,
    index: BackupIndex,
    compact: bool,
) -> tuple[int, dict[int, set[int]]]:
    media_types: dict[int, set[int]] = {}
    message_id = 0
    with text_path.open("rb") as source:
        for number, segment in enumerate(index.text_segments, 1):
            plaintext = _decrypt_text_segment(source, segment, key)
            padding_length = segment.length - len(plaintext)
            declared, raw_messages = parse_segment(plaintext)
            db.execute(
                "INSERT INTO segments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    segment.row_id,
                    segment.talker_id,
                    segment.start_time,
                    segment.end_time,
                    segment.offset,
                    segment.length,
                    segment.username,
                    segment.status,
                    segment.reserved1,
                    segment.file_path,
                    segment.segment_id,
                    segment.reserved2,
                    segment.reserved3,
                    declared,
                    len(raw_messages),
                    padding_length,
                ),
            )
            for ordinal, raw in enumerate(raw_messages):
                message = parse_message(raw)
                message_id += 1
                db.execute(
                    """INSERT INTO messages(id,segment_rowid,ordinal_in_segment,msg_type,from_username,
                    to_username,content,status,create_time,create_time_ms,msg_server_id,msg_seq,flag,
                    legacy_server_id,field2_text,field8_text,media_count,media_paths_json,media_types_json,
                    embedded_declared_length,embedded_data_length,embedded_media_type,embedded_data,
                    unknown_fields_json,raw_proto) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        message_id,
                        segment.row_id,
                        ordinal,
                        *_message_values(message, compact),
                    ),
                )
                if len(message.media_paths) != len(message.media_types):
                    raise ValueError(f"message {message_id}: media path/type lengths differ")
                for media_ordinal, identifier in enumerate(message.media_paths):
                    if identifier is None or identifier not in index.by_identifier:
                        raise ValueError(
                            f"message {message_id} references unknown media identifier {identifier!r}"
                        )
                    media_id = index.by_identifier[identifier]
                    media_type = message.media_types[media_ordinal]
                    db.execute(
                        "INSERT INTO message_media VALUES (?,?,?,?,?)",
                        (message_id, media_ordinal, media_id, media_type, identifier),
                    )
                    media_types.setdefault(media_id, set()).add(media_type)
            if number % 250 == 0 or number == len(index.text_segments):
                print(
                    f"text: {number}/{len(index.text_segments)} segments, {message_id} messages",
                    flush=True,
                )
    return message_id, media_types


def update_media_types(db: sqlite3.Connection, media_types: dict[int, set[int]]) -> None:
    for media_id, values in media_types.items():
        db.execute(
            "UPDATE media SET media_type_codes_json=? WHERE media_id=?",
            (json.dumps(sorted(values), separators=(",", ":")), media_id),
        )


def process_media(
    db: sqlite3.Connection,
    paths: BackupPaths,
    key: bytes,
    index: BackupIndex,
    mode: str,
    media_limit: int,
    media_dir: Path | None,
    media_types: dict[int, set[int]],
) -> None:
    if mode == "none":
        return
    selected = select_media_objects(mode, media_limit, index.media_order, media_types)
    if not selected:
        raise ValueError("media mode requested, but no media objects were selected")
    write_files = mode in {"sample", "all"}
    root = prepare_media_root(media_dir) if write_files and media_dir else None
    if write_files and root is None:
        raise ValueError("media output directory is required for sample/all")
    if root is not None:
        db.execute("INSERT OR REPLACE INTO export_meta VALUES ('media_root',?)", (str(root),))
    files = {name: path.open("rb") for name, path in paths.media.items()}
    try:
        block = key
        print(f"media: mode={mode}, processing {len(selected)}/{len(index.media)} objects")
        for number, obj in enumerate(selected, 1):
            result = decrypt_one_media(block, files, obj, root, write_files)
            db.execute(
                """UPDATE media SET plaintext_size=?,detected_format=?,output_path=?,
                plaintext_sha256=?,extraction_status=? WHERE media_id=?""",
                (
                    result["plaintext_size"],
                    result["detected_format"],
                    result["output_path"],
                    result["plaintext_sha256"],
                    result["extraction_status"],
                    obj.media_id,
                ),
            )
            if number % 500 == 0 or number == len(selected):
                print(f"media: {number}/{len(selected)} objects", flush=True)
    finally:
        for file in files.values():
            file.close()


def finalize_output(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE INDEX messages_time_idx ON messages(create_time,create_time_ms);
        CREATE INDEX messages_talker_idx ON messages(from_username,to_username);
        CREATE INDEX messages_type_idx ON messages(msg_type);
        CREATE INDEX message_media_media_idx ON message_media(media_id);
        CREATE TABLE message_type_counts AS
          SELECT msg_type,COUNT(*) AS message_count FROM messages GROUP BY msg_type ORDER BY message_count DESC;
        ANALYZE;
        """
    )
    result = db.execute("PRAGMA integrity_check").fetchone()[0]
    if result != "ok":
        raise ValueError(f"output SQLite integrity_check: {result}")


def _unused_backup_path(output: Path) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    base = Path(f"{output}.backup-{stamp}")
    candidate = base
    for attempt in range(1000):
        if not candidate.exists():
            return candidate
        candidate = Path(f"{base}-{attempt + 1}")
    raise RuntimeError("could not allocate output backup path")


def _publish_output(partial: Path, output: Path, overwrite: bool) -> Path | None:
    if output.exists():
        if not output.is_file():
            raise ValueError(f"refusing to replace non-regular path {output}")
        if not overwrite:
            raise FileExistsError(f"refusing to overwrite {output}")
        backup = _unused_backup_path(output)
        output.rename(backup)
        try:
            partial.rename(output)
        except Exception:
            backup.rename(output)
            raise
        return backup
    partial.rename(output)
    return None


def convert_backup(
    config: ExportConfig,
    paths: BackupPaths,
    decrypted_index: Path,
    key: bytes,
    key_hash: str,
) -> Path:
    output = config.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not output.is_file():
        raise ValueError(f"refusing to replace non-regular path {output}")
    if output.exists() and not config.overwrite:
        raise FileExistsError(f"refusing to overwrite {output}")
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.partial-", dir=output.parent, delete=False
    ) as partial_file:
        partial = Path(partial_file.name)
    os.chmod(partial, 0o600)
    db: sqlite3.Connection | None = None
    try:
        index = load_index(decrypted_index, paths, config.media_mode != "none")
        print(
            f"backup: internal start={index.metadata.start_time} end={index.metadata.end_time}, device={index.metadata.manufacturer} {index.metadata.model} {index.metadata.platform} {index.metadata.platform_version}"
        )
        print(
            f"index: {len(index.conversations)} conversations, {len(index.text_segments)} text segments, {len(index.media)} media objects"
        )
        db = _connect_output(partial)
        initialize_output(db)
        seed_output(db, index, paths, key_hash, config)
        message_count, media_types = export_text(db, paths.text, key[:16], index, config.compact)
        update_media_types(db, media_types)
        process_media(
            db,
            paths,
            key[:16],
            index,
            config.media_mode,
            config.media_limit,
            config.media_dir,
            media_types,
        )
        finalize_output(db)
        db.commit()
        db.close()
        db = None
        backup = _publish_output(partial, output, config.overwrite)
        if backup:
            print(f"previous output backup: {backup}")
        print(f"output: {output}")
        print(f"messages: {message_count}; media index: {len(index.media)}")
        return output
    except Exception:
        if db is not None:
            db.close()
        partial.unlink(missing_ok=True)
        raise
