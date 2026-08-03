from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path

from .archive import BackupPaths
from .proto import decode_text, first_bytes, first_varint, parse_proto


@dataclass
class BackupMetadata:
    account_id: str | None
    device_id: str | None
    start_time: int
    end_time: int
    manufacturer: str | None
    model: str | None
    platform: str | None
    platform_version: str | None
    client_version: int
    device_value: int


@dataclass
class Conversation:
    talker: str
    end_time: int
    total_size: int
    nickname: str
    reserved0: int
    reserved1: int
    reserved2: str
    reserved3: str
    start_time: int
    reserved5: str


@dataclass
class TextSegment:
    row_id: int
    talker_id: int
    start_time: int
    end_time: int
    offset: int
    length: int
    username: str
    status: int
    reserved1: int
    file_path: str
    segment_id: str
    reserved2: str
    reserved3: str


@dataclass
class MediaRecord:
    media_id: int
    talker_id: int
    msg_segment_id: int
    server_id: int
    source_md5: str
    talker: str
    identifier: str


@dataclass
class MediaSegment:
    row_id: int
    map_key: str
    inner_offset: int
    length: int
    total_length: int
    offset: int
    container: str


@dataclass
class MediaObject:
    media_id: int
    record: MediaRecord
    segments: list[MediaSegment] = field(default_factory=list)
    first_container: str = ""
    containers: list[str] = field(default_factory=list)
    encrypted_size: int = 0
    first_offset: int = 0


@dataclass
class BackupIndex:
    metadata: BackupMetadata
    conversations: list[Conversation]
    names: dict[int, str]
    text_segments: list[TextSegment]
    media: dict[int, MediaObject]
    media_order: list[MediaObject]
    by_identifier: dict[str, int]


def _connect_readonly(path: Path) -> sqlite3.Connection:
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    return sqlite3.connect(uri, uri=True)


def load_backup_metadata(db: sqlite3.Connection) -> BackupMetadata:
    (blob,) = db.execute("SELECT Buf FROM Config WHERE Key='100000'").fetchone()
    fields = parse_proto(blob)
    device_fields = parse_proto(first_bytes(fields, 5) or b"")
    return BackupMetadata(
        account_id=decode_text(first_bytes(fields, 1)),
        device_id=decode_text(first_bytes(fields, 2)),
        start_time=first_varint(fields, 3),
        end_time=first_varint(fields, 4),
        manufacturer=decode_text(first_bytes(device_fields, 2)),
        model=decode_text(first_bytes(device_fields, 3)),
        platform=decode_text(first_bytes(device_fields, 4)),
        platform_version=decode_text(first_bytes(device_fields, 5)),
        client_version=first_varint(device_fields, 6),
        device_value=first_varint(device_fields, 7),
    )


def _load_conversations(db: sqlite3.Connection) -> list[Conversation]:
    rows = db.execute(
        """SELECT COALESCE(talker,''),COALESCE(EndTime,0),COALESCE(TotalSize,0),
        COALESCE(NickName,''),COALESCE(Reserved0,0),COALESCE(Reserved1,0),
        COALESCE(Reserved2,''),COALESCE(Reserved3,''),COALESCE(StartTime,0),
        COALESCE(Reserved5,'') FROM Session"""
    )
    return [Conversation(*row) for row in rows]


def _load_names(db: sqlite3.Connection) -> dict[int, str]:
    return {
        int(row[0]): row[1] for row in db.execute("SELECT rowid,COALESCE(UsrName,'') FROM Name2ID")
    }


def _load_text_segments(db: sqlite3.Connection, text_path: Path) -> list[TextSegment]:
    rows = db.execute(
        """SELECT rowid,COALESCE(talkerId,0),COALESCE(StartTime,0),COALESCE(EndTime,0),
        COALESCE(OffSet,0),COALESCE(Length,0),COALESCE(UsrName,''),COALESCE(Status,0),
        COALESCE(Reserved1,0),COALESCE(FilePath,''),COALESCE(SegmentId,''),
        COALESCE(Reserved2,''),COALESCE(Reserved3,'') FROM MsgSegments ORDER BY OffSet"""
    )
    result = [TextSegment(*row) for row in rows]
    expected = 0
    for item in result:
        if item.offset != expected:
            raise ValueError(
                f"MsgSegments rowid {item.row_id}: expected offset {expected}, got {item.offset}"
            )
        if item.length <= 0 or item.length % 16:
            raise ValueError(f"MsgSegments rowid {item.row_id}: invalid AES length {item.length}")
        expected += item.length
    if expected != text_path.stat().st_size:
        raise ValueError(f"MsgSegments cover {expected} bytes, file has {text_path.stat().st_size}")
    return result


def _load_media(
    db: sqlite3.Connection, paths: BackupPaths, require_media: bool
) -> tuple[dict[int, MediaObject], list[MediaObject], dict[str, int]]:
    media: dict[int, MediaObject] = {}
    by_identifier: dict[str, int] = {}
    for row in db.execute(
        """SELECT COALESCE(MediaId,0),COALESCE(talkerId,0),COALESCE(MsgSegmentId,0),
        COALESCE(SvrId,0),COALESCE(MD5,''),COALESCE(talker,''),COALESCE(MediaIdStr,'')
        FROM MsgMedia"""
    ):
        record = MediaRecord(*row)
        if record.media_id <= 0 or not record.identifier:
            raise ValueError(f"invalid MsgMedia row for media id {record.media_id}")
        if record.media_id in media:
            raise ValueError(f"duplicate MsgMedia.MediaId {record.media_id}")
        if record.identifier in by_identifier:
            raise ValueError(f"duplicate MsgMedia.MediaIdStr {record.identifier!r}")
        media[record.media_id] = MediaObject(record.media_id, record)
        by_identifier[record.identifier] = record.media_id

    expected_by_container: dict[str, int] = {}
    rows = db.execute(
        """SELECT rowid,MapKey,InnerOffSet,Length,TotalLen,OffSet,FileName
        FROM MsgFileSegment ORDER BY FileName,OffSet"""
    )
    for row in rows:
        item = MediaSegment(*row)
        if (
            item.container != Path(item.container).name
            or not item.container.startswith("BAK_")
            or not item.container.endswith("_MEDIA")
        ):
            raise ValueError(f"unsafe media container name {item.container!r}")
        try:
            media_id = int(item.map_key)
        except ValueError as exc:
            raise ValueError(f"non-numeric media map key {item.map_key!r}") from exc
        if media_id not in media:
            raise ValueError(f"media segment {item.row_id} references unknown media {media_id}")
        expected = expected_by_container.get(item.container, 0)
        if item.offset != expected:
            raise ValueError(f"{item.container}: expected offset {expected}, got {item.offset}")
        if item.offset % 16 or item.inner_offset % 16 or item.length <= 0 or item.length % 16:
            raise ValueError(f"invalid AES alignment at media segment {item.row_id}")
        expected_by_container[item.container] = expected + item.length
        media[media_id].segments.append(item)

    for container, covered in expected_by_container.items():
        path = paths.media.get(container)
        if path is None:
            if require_media:
                raise FileNotFoundError(f"index requires missing media container {container}")
            continue
        if path.stat().st_size != covered:
            raise ValueError(
                f"{container}: index covers {covered} bytes, file has {path.stat().st_size}"
            )

    for media_id, obj in media.items():
        if not obj.segments:
            raise ValueError(f"media id {media_id} has no file segments")
        obj.segments.sort(key=lambda item: item.inner_offset)
        obj.first_container = obj.segments[0].container
        obj.first_offset = obj.segments[0].offset
        obj.encrypted_size = obj.segments[0].total_length
        expected_inner = 0
        seen: set[str] = set()
        for item in obj.segments:
            if item.inner_offset != expected_inner or item.total_length != obj.encrypted_size:
                raise ValueError(f"inconsistent media offsets for media id {media_id}")
            expected_inner += item.length
            if item.container not in seen:
                seen.add(item.container)
                obj.containers.append(item.container)
        if expected_inner != obj.encrypted_size:
            raise ValueError(f"media id {media_id}: segment lengths do not cover TotalLen")
    order = sorted(media.values(), key=lambda item: (item.first_container, item.first_offset))
    mapped = 0
    for rowid, identifier in db.execute("SELECT rowid,UsrName FROM MediaStr2ID"):
        if rowid not in media or media[rowid].record.identifier != identifier:
            raise ValueError(f"MediaStr2ID rowid {rowid} does not match MsgMedia")
        mapped += 1
    if mapped != len(media):
        raise ValueError("MediaStr2ID and MsgMedia counts differ")
    return media, order, by_identifier


def load_index(db_path: Path, paths: BackupPaths, require_media: bool) -> BackupIndex:
    with closing(_connect_readonly(db_path)) as db:
        metadata = load_backup_metadata(db)
        conversations = _load_conversations(db)
        names = _load_names(db)
        text_segments = _load_text_segments(db, paths.text)
        media, media_order, by_identifier = _load_media(db, paths, require_media)
    return BackupIndex(
        metadata, conversations, names, text_segments, media, media_order, by_identifier
    )
