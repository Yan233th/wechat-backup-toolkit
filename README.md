# WeChat Backup Converter

A Python workflow for converting authorized WeChat PC backup files into a normal
SQLite database. It can also verify or extract encrypted media referenced by the
backup index.

The project is intentionally distributed as editable Python source. Dependencies,
the virtual environment, and command execution are managed by
[uv](https://docs.astral.sh/uv/).

> This is an independent recovery and interoperability project. It is not
> affiliated with or endorsed by Tencent or WeChat. Use it only with backups and
> accounts you are authorized to access.

## Features

- Authenticates and decrypts the SQLCipher 3 `Backup.db` page by page.
- Decrypts `BAK_0_TEXT` by indexed AES-ECB segments without writing a full
  plaintext text container.
- Parses the message protobuf records into ordinary SQLite columns.
- Preserves the conversation, segment, media, and message-to-media indexes.
- Supports media objects split across multiple `BAK_*_MEDIA` containers.
- Streams large media objects with bounded memory.
- Accepts an extracted directory or a `.7z` archive.
- Never stores the backup key in the output database.
- Publishes SQLite output only after `PRAGMA integrity_check` succeeds.

## Requirements

- Python 3.11 or newer.
- `uv`.
- Official 7-Zip when the input is a `.7z` archive. Extracted directories do not
  require 7-Zip.

The Python dependencies are declared in `pyproject.toml` and pinned by `uv.lock`.

## Setup

```powershell
uv sync --locked
uv run wechat-backup-converter --help
```

`uv` creates and manages the local virtual environment automatically.

## Input layout

An extracted backup normally contains:

```text
Backup.db
BAK_0_TEXT
BAK_0_MEDIA
BAK_1_MEDIA
...
```

`Backup.db` and `BAK_0_TEXT` are required. Media containers are required for
`--media sample`, `verify`, and `all`.

## Usage

Convert messages and the media index from an extracted directory:

```powershell
uv run wechat-backup-converter `
  --input "D:\Backups\WeChat" `
  --output "D:\Recovered\wechat.db" `
  --media none `
  --compact
```

Read directly from an archive and verify every media object without writing
decrypted media files:

```powershell
uv run wechat-backup-converter `
  --input "D:\Backups\wechat-backup.7z" `
  --output "D:\Recovered\wechat-verified.db" `
  --media verify `
  --work-dir "D:\Temp\wechat-work"
```

Extract all media:

```powershell
uv run wechat-backup-converter `
  --input "D:\Backups\WeChat" `
  --output "D:\Recovered\wechat.db" `
  --media all `
  --media-dir "D:\Recovered\wechat.media"
```

The same commands work in other shells with their normal line-continuation
syntax.

## Key input

Without `--key-file`, the command prompts for the key without echoing it. The
expected value is exactly 32 literal printable ASCII characters. Do not
hex-decode it.

For an unattended local workflow, `--key-file` accepts either:

- a file containing only the 32-character key; or
- a text record containing a line beginning with `Key:`.

Protect the key file separately and never commit it. The SQLite output records a
SHA-256 fingerprint for key identification, but not the key itself.

## Media modes

| Mode | Behavior |
| --- | --- |
| `none` | Export messages and the media index without opening media containers. |
| `sample` | Extract representative small objects up to `--media-limit`. |
| `verify` | Decrypt and validate every media object without writing plaintext files. |
| `all` | Validate and extract every media object. |

Recognized files receive common extensions such as `.jpg`, `.png`, `.mp4`,
`.pdf`, and `.zip`. WeChat `wxgf` images are preserved as `.wxgf`, OLE compound
documents as `.ole`, and unknown binary data as `.bin`. The converter does not
transcode the plaintext.

## SQLite output

Useful tables include:

- `backup_info`, `conversations`, and `name_map`
- `segments` and `messages`
- `media`, `media_segments`, and `message_media`
- `message_type_counts` and `export_meta`

`--compact` omits raw protobuf and embedded binary blobs while retaining parsed
fields.

The database is written to a unique temporary file beside the requested output.
It is renamed into place only after SQLite integrity validation. Existing output
is rejected by default. With `--overwrite`, the previous database is retained as
a timestamped `.backup-*` file before the new database is published.

An existing non-empty media output directory is always rejected.

## Temporary data

For directory input, the work directory contains a temporary decrypted copy of
`Backup.db`. For archive input, it also contains the encrypted members extracted
from the archive. Temporary work is removed after success or an ordinary error.

`--work-dir` selects the parent directory. `--keep-work` retains the work
directory for diagnosis; retained work must be handled as sensitive data.

## Development

```powershell
uv sync --locked --dev
uv run ruff format --check src tests
uv run ruff check src tests
uv run pytest
```

No real backup, key, process dump, decrypted database, or fixture is part of this
repository. Tests use synthetic protocol and cryptographic data only.

## Format compatibility

The implementation targets the observed WeChat 4.x PC backup layout. The format
is not publicly documented and may change. Authentication, segment coverage,
padding, message counts, media identifiers, and SQLite integrity are checked so
unsupported changes fail explicitly instead of silently producing partial data.
