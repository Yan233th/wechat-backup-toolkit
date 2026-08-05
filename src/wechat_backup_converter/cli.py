from __future__ import annotations

import argparse
import getpass
import hashlib
import sys
from pathlib import Path

from . import __version__
from .archive import discover_backup_files, prepare_input
from .crypto import decrypt_sqlcipher3
from .export import ExportConfig, convert_backup
from .verify import VerificationResult, verify_backup


def _add_input_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", required=True, type=Path, help="backup directory or .7z archive")
    parser.add_argument(
        "--key-file",
        type=Path,
        help="raw 32-byte key or an English record containing Key:",
    )
    parser.add_argument("--work-dir", type=Path, help="parent directory for temporary work files")
    parser.add_argument("--7z", dest="seven_zip", help="path to 7z/7zz/7za executable")
    parser.add_argument(
        "--keep-work",
        action="store_true",
        help="retain decrypted temporary index/archive files",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Translate or verify an authorized WeChat PC backup"
    )
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    convert = commands.add_parser("convert", help="translate the backup into SQLite")
    _add_input_options(convert)
    convert.add_argument(
        "--output",
        type=Path,
        default=Path("wechat_export.db"),
        help="output SQLite database",
    )
    convert.add_argument("--media", choices=("none", "sample", "all"), default="none")
    convert.add_argument(
        "--media-dir",
        type=Path,
        help="media output directory (default: <output>.media)",
    )
    convert.add_argument(
        "--media-limit", type=int, default=20, help="maximum items for --media sample"
    )
    convert.add_argument(
        "--overwrite",
        action="store_true",
        help="replace output after making a timestamped backup",
    )

    verify = commands.add_parser(
        "verify", help="validate the complete backup without producing SQLite"
    )
    _add_input_options(verify)
    return parser


def _parse_key_record(data: str) -> str:
    for line in data.replace("\r\n", "\n").splitlines():
        stripped = line.strip()
        if stripped.startswith("Key:"):
            return stripped.removeprefix("Key:").strip()
    return data.strip().removeprefix("\ufeff")


def load_key(path: Path | None) -> bytes:
    raw = (
        _parse_key_record(path.read_text(encoding="utf-8-sig"))
        if path
        else getpass.getpass("Backup key (32 literal ASCII characters): ").strip()
    )
    key = raw.encode("ascii", "strict")
    if len(key) != 32:
        raise ValueError(
            f"key must be exactly 32 literal bytes, got {len(key)}; do not hex-decode it"
        )
    if any(value < 0x20 or value > 0x7E for value in key):
        raise ValueError("key must contain 32 printable ASCII characters")
    return key


def _decrypt_index(args: argparse.Namespace, include_media: bool):
    key = load_key(args.key_file)
    key_hash = hashlib.sha256(key).hexdigest()
    print(f"key: 32 literal ASCII bytes, sha256={key_hash}")
    prepared = prepare_input(args.input, args.work_dir, include_media, args.seven_zip)
    prepared.retained = args.keep_work
    try:
        paths = discover_backup_files(prepared.input_dir)
        decrypted_index = prepared.work_dir / "Backup.decrypted.db"
        print("decrypting and authenticating Backup.db")
        pages = decrypt_sqlcipher3(paths.backup_db, decrypted_index, key)
        print(f"Backup.db: {pages} authenticated pages")
        return key, key_hash, prepared, paths, decrypted_index
    except BaseException:
        if args.keep_work:
            print(f"work directory retained: {prepared.work_dir}")
        else:
            prepared.cleanup()
        raise


def run_convert(args: argparse.Namespace) -> Path:
    if args.media_limit < 1:
        raise ValueError("--media-limit must be positive")
    key, key_hash, prepared, paths, decrypted_index = _decrypt_index(args, args.media != "none")
    try:
        media_dir = args.media_dir
        if media_dir is None and args.media in {"sample", "all"}:
            media_dir = Path(f"{args.output}.media")
        config = ExportConfig(
            args.output,
            args.media,
            media_dir,
            args.media_limit,
            args.overwrite,
        )
        return convert_backup(config, paths, decrypted_index, key, key_hash)
    finally:
        if args.keep_work:
            print(f"work directory retained: {prepared.work_dir}")
        else:
            prepared.cleanup()


def run_verify(args: argparse.Namespace) -> VerificationResult:
    key, _, prepared, paths, decrypted_index = _decrypt_index(args, include_media=True)
    try:
        return verify_backup(paths, decrypted_index, key)
    finally:
        if args.keep_work:
            print(f"work directory retained: {prepared.work_dir}")
        else:
            prepared.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "convert":
            run_convert(args)
        else:
            run_verify(args)
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary reports operational failures cleanly.
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
