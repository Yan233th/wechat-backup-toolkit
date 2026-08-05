# WeChat Backup Converter

A Python workflow for translating authorized WeChat PC backup files into a normal
SQLite database, with a separate command for validating a backup without producing
an export.

The project is intentionally distributed as editable Python source. Dependencies,
the virtual environment, and command execution are managed by
[uv](https://docs.astral.sh/uv/).

> This is an independent recovery and interoperability project. It is not
> affiliated with or endorsed by Tencent or WeChat. Use it only with backups and
> accounts you are authorized to access.

## Commands

- `convert` performs a one-way translation into SQLite and optionally writes media.
- `verify` checks the complete encrypted backup and produces no SQLite database or
  decrypted media output.

## Features

- Authenticates and decrypts the SQLCipher 3 `Backup.db` page by page.
- Decrypts `BAK_0_TEXT` by indexed AES-ECB segments without writing a full
  plaintext text container.
- Translates known message fields into ordinary SQLite columns.
- Preserves conversation, segment, media, and message-to-media relationships.
- Supports media objects split across multiple `BAK_*_MEDIA` containers.
- Streams large media objects with bounded memory.
- Accepts an extracted directory or a `.7z` archive.
- Never stores the backup key in the output database.
- Publishes SQLite output only after `PRAGMA integrity_check` succeeds.

The SQLite export is intentionally one-way. It does not retain raw protobuf,
unknown protocol fields, or opaque embedded message bytes for later reconstruction.

## Requirements

- Python 3.11 or newer.
- `uv`.
- Official 7-Zip when the input is a `.7z` archive. Extracted directories do not
  require 7-Zip.

Dependencies are declared in `pyproject.toml` and pinned by `uv.lock`.

## Setup

```powershell
uv sync --locked
uv run wechat-backup-converter --help
```

## Input layout

An extracted backup normally contains:

```text
Backup.db
BAK_0_TEXT
BAK_0_MEDIA
BAK_1_MEDIA
...
```

`Backup.db` and `BAK_0_TEXT` are required. Media containers are required when
extracting media and when running the complete `verify` command.

## Convert to SQLite

Translate messages and the media index without decrypting media files:

```powershell
uv run wechat-backup-converter convert `
  --input "D:\Backups\WeChat" `
  --output "D:\Recovered\wechat.db" `
  --media none
```

Translate the backup and extract all media:

```powershell
uv run wechat-backup-converter convert `
  --input "D:\Backups\WeChat" `
  --output "D:\Recovered\wechat.db" `
  --media all `
  --media-dir "D:\Recovered\wechat.media"
```

For archive input, select a work drive with enough temporary space:

```powershell
uv run wechat-backup-converter convert `
  --input "D:\Backups\wechat-backup.7z" `
  --output "D:\Recovered\wechat.db" `
  --media none `
  --work-dir "D:\Temp\wechat-work"
```

### Media output choices

| Choice | Conversion output |
| --- | --- |
| `none` | Write messages and the media index only. |
| `sample` | Also write representative small media files, up to `--media-limit`. |
| `all` | Also decrypt and write every indexed media object. |

Recognized files receive common extensions such as `.jpg`, `.png`, `.mp4`,
`.pdf`, and `.zip`. WeChat `wxgf` images are preserved as `.wxgf`, OLE compound
documents as `.ole`, and unknown binary data as `.bin`. The converter does not
transcode the plaintext.

## Verify a backup

`verify` validates the encrypted input without producing a translated database:

```powershell
uv run wechat-backup-converter verify `
  --input "D:\Backups\WeChat" `
  --work-dir "D:\Temp\wechat-work"
```

It checks:

- every authenticated SQLCipher page in `Backup.db`;
- TEXT segment coverage, AES padding, protobuf structure, and declared message
  counts;
- message-to-media identifiers and declared media counts;
- media container coverage, cross-container ordering, AES padding, and every
  indexed media object.

Successful verification prints counts and byte totals, then removes temporary
work. It does not create SQLite or decrypted media files.

## Key input

Without `--key-file`, both commands prompt for the key without echoing it. The
expected value is exactly 32 literal printable ASCII characters. Do not
hex-decode it.

For an unattended local workflow, `--key-file` accepts either:

- a file containing only the 32-character key; or
- a text record containing a line beginning with `Key:`.

Protect the key file separately and never commit it. A converted SQLite database
contains a SHA-256 key fingerprint for identification, but not the key itself.

## SQLite output

Useful tables include:

- `backup_info`, `conversations`, and `name_map`
- `segments` and `messages`
- `media`, `media_segments`, and `message_media`
- `message_type_counts` and `export_meta`

The `messages` table contains interpreted fields such as message type, sender,
recipient, content, timestamps, status, server identifiers, and media references.
It does not contain raw protocol records or uninterpreted embedded binary data.

The database is written to a unique temporary file beside the requested output.
It is renamed into place only after SQLite integrity validation. Existing output
is rejected by default. With `--overwrite`, the previous database is retained as
a timestamped `.backup-*` file before the new database is published.

An existing non-empty media output directory is always rejected.

## Temporary data

For directory input, the work directory contains a temporary decrypted copy of
`Backup.db`. For archive input, it also contains encrypted members extracted from
the archive. Temporary work is removed after success, an ordinary error, or an
interrupt.

`--work-dir` selects the parent directory. `--keep-work` retains the work directory
for diagnosis; retained work must be handled as sensitive data.

## Development

```powershell
uv sync --locked --dev
uv run ruff format --check src tests
uv run ruff check src tests
uv run pytest
```

No real backup, key, process dump, decrypted database, message content, or fixture
is part of this repository. Tests use synthetic protocol and cryptographic data
only.

## Format compatibility

The implementation targets the observed WeChat 4.x PC backup layout. The format
is not publicly documented and may change. Authentication, segment coverage,
padding, message counts, media identifiers, and SQLite integrity are checked so
unsupported changes fail explicitly instead of silently producing partial data.
