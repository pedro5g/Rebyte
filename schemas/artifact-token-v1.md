# Rebyte Artifact Token v1

Copyright (c) 2026 Pedro Martins (pedro5g)

## Purpose and boundary

Artifact Token v1 transports one regular file or a portable directory tree
without keys. The binary representation uses `.rba`; the identical bytes can
be represented as Base64URL without padding using the `ra1_` prefix.

The format provides byte-exact reconstruction, bounded decoding and BLAKE3
integrity. It does not authenticate the creator, authorize a destination or
provide confidentiality. Suggested names and destinations are untrusted hints.

## Canonical header

All integers are unsigned and big-endian.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII magic `RBAT` |
| 4 | 1 | version `1` |
| 5 | 1 | kind: `0` file, `1` directory |
| 6 | 1 | compression: `0` none, `1` Zstandard |
| 7 | 1 | profile: `0` fast, `1` balanced, `2` maximum |
| 8 | 2 | flags: bit 0 suggested name, bit 1 suggested path |
| 10 | 2 | reserved zero |
| 12 | 4 | entry count |
| 16 | 8 | manifest length |
| 24 | 8 | aggregate reconstructed file bytes |
| 32 | 8 | stored payload length |
| 40 | 32 | content digest |
| 72 | 32 | envelope digest |

The header is followed by exactly the declared canonical manifest and stored
payload. Trailing bytes are forbidden.

## Manifest

The manifest begins with a `u16` suggested-name length and UTF-8 bytes, a
`u16` suggested-path length and UTF-8 bytes, and a `u32` entry count. A zero
length means absent.

Each entry contains:

| Size | Field |
|---:|---|
| 1 | kind: `0` file, `1` directory |
| 1 | executable boolean |
| 2 | reserved zero |
| 2 | UTF-8 path length |
| 2 | reserved zero |
| 8 | uncompressed payload offset |
| 8 | file size |
| 32 | file digest |
| variable | path bytes |

Directory entries have zero offset, size and digest and cannot be executable.
A file artifact contains exactly one pathless file. Directory entries require
portable paths sorted lexicographically by UTF-8 bytes. Duplicates and a file
used as an ancestor path are rejected. File payload ranges are contiguous in
manifest order.

## Integrity domains

The content identity uses BLAKE3 derive-key context
`rebyte:v1:artifact-content` over kind and canonical entry identity. Suggested
name and destination are excluded, so changing a destination hint does not
change the content identity.

The envelope digest uses context `rebyte:v1:artifact-envelope` over version,
kind, compression, profile, flags, all declared lengths, the content digest,
manifest and stored payload. Every field is verified before reconstructed
content is released.

Each file uses the existing `rebyte:v1:file` digest domain.

## Destination safety

Names are single portable UTF-8 components. Suggested destinations use the RAP
portable relative-path rules: no roots, backslashes, control bytes, empty
components, `.`/`..`, Windows device names, trailing dots/spaces, colon or the
reserved `.rebyte` root.

Consumers must never write to a suggested path silently. A caller-provided
output overrides all hints; otherwise explicit acceptance below a selected
root is required.
