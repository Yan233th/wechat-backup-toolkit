from __future__ import annotations

import json
import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class ProtoField:
    number: int
    wire: int
    value: int | bytes


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift < 70:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise ValueError("invalid or truncated protobuf varint")


def parse_proto(data: bytes) -> list[ProtoField]:
    fields: list[ProtoField] = []
    offset = 0
    while offset < len(data):
        tag, offset = read_varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("protobuf field number 0")
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 1:
            if offset + 8 > len(data):
                raise ValueError("truncated protobuf fixed64")
            value = struct.unpack_from("<Q", data, offset)[0]
            offset += 8
        elif wire == 2:
            size, offset = read_varint(data, offset)
            if offset + size > len(data):
                raise ValueError("truncated protobuf length-delimited field")
            value = data[offset : offset + size]
            offset += size
        elif wire == 5:
            if offset + 4 > len(data):
                raise ValueError("truncated protobuf fixed32")
            value = struct.unpack_from("<I", data, offset)[0]
            offset += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        fields.append(ProtoField(number, wire, value))
    return fields


def first_varint(fields: list[ProtoField], number: int, default: int = 0) -> int:
    for field in fields:
        if field.number == number and field.wire == 0:
            return int(field.value)
    return default


def first_bytes(fields: list[ProtoField], number: int) -> bytes | None:
    for field in fields:
        if field.number == number and field.wire == 2:
            return bytes(field.value)
    return None


def all_bytes(fields: list[ProtoField], number: int) -> list[bytes]:
    return [bytes(field.value) for field in fields if field.number == number and field.wire == 2]


def decode_text(value: bytes | None) -> str | None:
    return None if value is None else value.decode("utf-8", "replace")


def decode_etl(value: bytes | None) -> str | None:
    return decode_text(first_bytes(parse_proto(value), 1)) if value is not None else None


def decode_etm(value: bytes) -> int:
    return first_varint(parse_proto(value), 1)


def decode_gol(value: bytes | None) -> tuple[int, bytes | None]:
    if value is None:
        return 0, None
    fields = parse_proto(value)
    return first_varint(fields, 1), first_bytes(fields, 2)


@dataclass
class ParsedMessage:
    msg_type: int
    field2_text: str | None
    from_username: str | None
    to_username: str | None
    content: str | None
    status: int
    create_time: int
    field8_text: str | None
    legacy_server_id: int
    media_count: int
    media_paths: list[str | None]
    media_types: list[int]
    embedded_declared_length: int
    embedded_data: bytes | None
    embedded_data_length: int
    embedded_media_type: int
    msg_server_id: int
    msg_seq: int
    create_time_ms: int
    flag: int
    unknown_fields: list[dict[str, int | None]]
    raw: bytes

    @property
    def media_paths_json(self) -> str:
        return json.dumps(self.media_paths, ensure_ascii=False, separators=(",", ":"))

    @property
    def media_types_json(self) -> str:
        return json.dumps(self.media_types, separators=(",", ":"))

    @property
    def unknown_fields_json(self) -> str:
        return json.dumps(self.unknown_fields, separators=(",", ":"))


def parse_message(raw: bytes) -> ParsedMessage:
    fields = parse_proto(raw)
    embedded_declared, embedded_data = decode_gol(first_bytes(fields, 13))
    known = set(range(1, 20))
    unknown: list[dict[str, int | None]] = []
    for field in fields:
        if field.number in known:
            continue
        unknown.append(
            {
                "field": field.number,
                "wire": field.wire,
                "length": len(field.value) if field.wire == 2 else None,
                "value": int(field.value) if field.wire == 0 else None,
            }
        )
    return ParsedMessage(
        msg_type=first_varint(fields, 1),
        field2_text=decode_text(first_bytes(fields, 2)),
        from_username=decode_etl(first_bytes(fields, 3)),
        to_username=decode_etl(first_bytes(fields, 4)),
        content=decode_etl(first_bytes(fields, 5)),
        status=first_varint(fields, 6),
        create_time=first_varint(fields, 7),
        field8_text=decode_text(first_bytes(fields, 8)),
        legacy_server_id=first_varint(fields, 9),
        media_count=first_varint(fields, 10),
        media_paths=[decode_etl(value) for value in all_bytes(fields, 11)],
        media_types=[decode_etm(value) for value in all_bytes(fields, 12)],
        embedded_declared_length=embedded_declared,
        embedded_data=embedded_data,
        embedded_data_length=first_varint(fields, 14),
        embedded_media_type=first_varint(fields, 15),
        msg_server_id=first_varint(fields, 16),
        msg_seq=first_varint(fields, 17),
        create_time_ms=first_varint(fields, 18),
        flag=first_varint(fields, 19),
        unknown_fields=unknown,
        raw=raw,
    )


def parse_segment(data: bytes) -> tuple[int, list[bytes]]:
    fields = parse_proto(data)
    declared = first_varint(fields, 1)
    messages = all_bytes(fields, 2)
    if declared != len(messages):
        raise ValueError(f"message count mismatch: declared {declared}, parsed {len(messages)}")
    return declared, messages
