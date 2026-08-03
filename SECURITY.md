# Security and privacy

Do not attach real backup files, keys, process dumps, decrypted databases,
message content, usernames, device identifiers, or source hashes to public bug
reports.

When reporting a parsing or compatibility issue, prefer a synthetic reproducer.
If a real sample is essential, minimize and redact it locally before sharing and
verify that the minimized file no longer contains personal data.

The converter deliberately avoids storing the backup key in SQLite. Temporary
work may contain a decrypted `Backup.db`; use `--keep-work` only when necessary
and remove retained work after diagnosis.
