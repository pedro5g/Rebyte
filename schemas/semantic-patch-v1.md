# Rebyte Semantic Patch v1

Copyright (c) 2026 Pedro Martins (pedro5g)

## Purpose and trust boundary

Semantic Patch v1 applies ordered data-model changes to one existing JSON or
TOML configuration file. It is designed for local emergency changes where
unrelated keys, TOML comments and layout should survive.

The patch is unsigned JSON. It provides strict structure, optional exact-byte
preconditions and semantic tests, but no publisher authentication,
confidentiality, expiration or authorization. A patch never executes code,
commands, templates, environment expansion, network requests or hooks.

## Document

```json
{
  "schemaVersion": 1,
  "format": "toml",
  "targetDigest": "optional 64-character lowercase RAP file digest",
  "operations": [
    { "op": "test", "path": "/server/port", "value": 80 },
    { "op": "set", "path": "/server/port", "value": 8080 },
    { "op": "remove", "path": "/server/legacy" }
  ]
}
```

All fields shown for the selected operation are required. `targetDigest` may
be omitted. Unknown fields, unknown operations and duplicate object keys at
any nesting level are errors. The document is at most 2 `MiB` and contains
between 1 and 512 operations.

## Pointer and operation semantics

`path` is an RFC 6901 JSON Pointer of at most 1024 UTF-8 bytes and 64
components. `~0` decodes to `~`; `~1` decodes to `/`; other tilde escapes are
invalid.

Operations run in document order:

1. `test` requires the selected value to exist and equal `value`.
2. `set` inserts or replaces a value under an existing parent.
3. `remove` requires and removes the selected value.

JSON object members and array indexes are supported. Array indexes are
canonical unsigned decimal without leading zeroes; `-` is accepted only by
`set` and appends. An empty pointer selects the JSON root for `test` and `set`;
the root cannot be removed.

TOML v1 accepts nonempty table-key pointers only. Array indexes and root
replacement are rejected. Patch values use JSON syntax and must be
representable in TOML; JSON `null` is not representable. Surrounding TOML
comments, key order and untouched formatting are retained. Replacing a scalar
retains its prefix and suffix decoration, including an inline comment.

## Application order

1. Read the patch and target through bounded no-follow regular-file opens.
2. Validate the complete patch schema and pointers.
3. Hash the exact original target with `rebyte:v1:file`.
4. Compare `targetDigest` when supplied.
5. Parse target syntax with duplicate-key rejection.
6. Execute every ordered operation in memory.
7. Serialize the complete result and compute its file digest.
8. Display a sanitized preview and require confirmation unless `--yes`.
9. Optionally create a new, exact backup without overwriting.
10. Stage output in the target directory and synchronize it.
11. Reopen and hash the target to detect a concurrent change.
12. Atomically replace the one target file and synchronize its parent.
13. Reopen the committed target and verify the result digest.

Failures before step 12 leave the target unchanged. Semantic Patch v1 is a
single-file operation; related multi-file changes belong in a signed,
recoverable RAP capsule.
