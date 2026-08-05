from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackupPaths:
    root: Path
    backup_db: Path
    text: Path
    media: dict[str, Path]


@dataclass
class PreparedInput:
    input_dir: Path
    work_dir: Path
    retained: bool = False

    def cleanup(self) -> None:
        if not self.retained:
            shutil.rmtree(self.work_dir, ignore_errors=True)


def default_seven_zip_candidates() -> list[str]:
    candidates = ["7z", "7zz", "7za"]
    if sys.platform == "win32":
        for variable in ("ProgramFiles", "ProgramW6432"):
            root = os.environ.get(variable)
            if root:
                candidates.append(str(Path(root) / "7-Zip" / "7z.exe"))
    return candidates


def find_seven_zip(explicit: str | None) -> str:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"7-Zip executable not found: {path}")
        return str(path)
    for candidate in default_seven_zip_candidates():
        path = shutil.which(candidate)
        if path:
            return path
        direct = Path(candidate)
        if direct.is_file():
            return str(direct)
    raise FileNotFoundError("7-Zip executable not found; install official 7-Zip or pass --7z")


def prepare_input(
    input_path: Path, work_parent: Path | None, include_media: bool, seven_zip: str | None
) -> PreparedInput:
    input_path = input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    parent = work_parent.expanduser().resolve() if work_parent else None
    if parent is not None:
        parent.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="wechat-backup-converter-", dir=parent))
    os.chmod(work_dir, 0o700)
    if input_path.is_dir():
        return PreparedInput(input_path, work_dir)
    if input_path.suffix.lower() != ".7z":
        shutil.rmtree(work_dir, ignore_errors=True)
        raise ValueError("input must be a backup directory or .7z archive")
    tool = find_seven_zip(seven_zip)
    extracted = work_dir / "input"
    extracted.mkdir(mode=0o700)
    members = ["Backup.db", "BAK_0_TEXT"]
    if include_media:
        members.append("BAK_*_MEDIA")
    command = [
        tool,
        "x",
        "-bd",
        "-y",
        f"-o{extracted}",
        "--",
        str(input_path),
        *members,
    ]
    print(
        f"archive: {Path(tool).name} x -bd -y -o{extracted} -- <archive> <members>",
        file=sys.stderr,
    )
    try:
        subprocess.run(command, check=True, stdout=sys.stderr, stderr=sys.stderr)
    except Exception:
        shutil.rmtree(work_dir, ignore_errors=True)
        raise
    for entry in extracted.iterdir():
        if entry.is_symlink():
            shutil.rmtree(work_dir, ignore_errors=True)
            raise ValueError(f"archive member must not be a symbolic link: {entry.name}")
        if entry.is_file():
            os.chmod(entry, 0o600)
    return PreparedInput(extracted, work_dir)


def discover_backup_files(root: Path) -> BackupPaths:
    root = root.resolve()
    backup_db = root / "Backup.db"
    text = root / "BAK_0_TEXT"
    for required in (backup_db, text):
        if required.is_symlink() or not required.is_file():
            raise FileNotFoundError(f"required file is missing: {required.name}")
    media: dict[str, Path] = {}
    for entry in root.iterdir():
        if not entry.name.startswith("BAK_") or not entry.name.endswith("_MEDIA"):
            continue
        if entry.is_symlink() or not entry.is_file():
            raise ValueError(f"media container must be a regular file: {entry.name}")
        media[entry.name] = entry
    return BackupPaths(root, backup_db, text, media)
