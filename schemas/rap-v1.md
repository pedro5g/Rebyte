# Rebyte Artifact Protocol v1

Copyright (c) 2026 Pedro Martins (pedro5g)

Status: normative and stable for Rebyte 1.x.

## Primitive encoding

All integers are unsigned and big-endian. Fixed arrays are emitted verbatim.
There is no alignment padding beyond fields explicitly named `reserved`.
Length-prefixed byte strings use a `u32` byte length followed by those bytes.
Optional strings use a one-byte tag (`0` absent, `1` present) and, when
present, a length-prefixed UTF-8 string. Any other tag is invalid.

Decoders reject non-zero reserved fields, unknown enum values, integer
overflow, trailing bytes and representations that are not canonical.

## Signed envelope

The final `.rbc` representation is:

```
header[80] || manifest[manifest_size] || payload[compressed_payload_size]
|| capsule_digest[32] || signature[64]
```

The header layout is fixed:

| Offset | Size | Field | RAP v1 value |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `RBAP` |
| 4 | 2 | protocol_version | `1` |
| 6 | 2 | header_size | `80` |
| 8 | 4 | flags | `0` |
| 12 | 1 | compression | `0` none, `1` Zstandard |
| 13 | 1 | signature | `1` Ed25519 |
| 14 | 2 | reserved | `0` |
| 16 | 8 | manifest_size | bounded byte count |
| 24 | 8 | compressed_payload_size | bounded byte count |
| 32 | 8 | uncompressed_payload_size | bounded byte count |
| 40 | 4 | file_count | `0..=512` |
| 44 | 4 | reserved | `0` |
| 48 | 32 | publisher_key_id | BLAKE3-derived key ID |

The total binary length must equal `80 + manifest_size +
compressed_payload_size + 32 + 64` using checked arithmetic.

## Canonical manifest

The manifest begins with:

1. `manifest_version: u16`, exactly `1`;
2. `reserved: u16`, exactly `0`;
3. optional capsule name, at most 256 UTF-8 bytes;
4. optional description, at most 4096 UTF-8 bytes;
5. producer name, at most 256 UTF-8 bytes;
6. optional producer version, at most 128 UTF-8 bytes;
7. exactly `header.file_count` file entries.

Each file entry is encoded as:

1. path as a length-prefixed UTF-8 string;
2. operation `u8`, exactly `0` (`CreateOrReplace`);
3. content kind `u8`: `0` binary or `1` UTF-8 text;
4. executable `u8`: `0` or `1`;
5. reserved `u8`, exactly `0`;
6. uncompressed payload offset `u64`;
7. file size `u64`;
8. file digest `[u8; 32]`.

Entries are strictly ordered by their raw UTF-8 path bytes. Offsets are
contiguous, start at zero and end at `uncompressed_payload_size`; gaps,
overlaps, duplicate paths and zero-length discontinuities are invalid.

## Portable paths

The protocol separator is `/`. A path must be non-empty, relative, at most
1024 bytes and contain no empty, `.` or `..` component. Backslash, colon, NUL,
ASCII control bytes, Windows device names, trailing dot and trailing space are
forbidden. The first component `.rebyte` is reserved. Unicode is preserved
byte-for-byte and is never normalized.

## Payload and content

The uncompressed payload is the concatenation of file bytes in manifest order.
`ContentKind` is informational and never changes verification or application.
For `TextUtf8`, the corresponding bytes must be valid UTF-8. Empty files are
valid. Empty directories are not represented.

Compression `0` stores the payload verbatim. Compression `1` is a single
Zstandard frame produced with the RAP v1 parameters documented by the encoder.
The decoder enforces compressed size, output size and ratio while streaming.

## Digest and signature

Per-file digests use the context `rebyte:v1:file`. The capsule digest uses
`rebyte:v1:capsule` over `header || manifest || compressed_payload`. The
manifest and payload domains are exposed for diagnostics and test vectors but
are not additional envelope fields.

Ed25519 signs `rebyte:v1:signature\0 || capsule_digest`. Verification first
recomputes the digest and key ID, then evaluates local key status/channel, then
verifies the signature.

## Text token

`rb1_` followed by unpadded Base64URL of the complete `.rbc` bytes. Leading and
trailing ASCII whitespace may be stripped by a CLI input adapter; whitespace
inside the token is invalid. The textual limit is checked before decoding.

See `rap-v1.abnf` for the textual grammar.

## Compatibility

- A RAP v1 decoder rejects versions other than `1` and unknown algorithms.
- New implementations must continue to accept every published valid v1 vector.
- Published vector bytes and expected outcomes are immutable.
- New optional semantics require a new protocol version because v1 has no
  skippable manifest fields.
- Implementations may lower local limits but must report a policy error rather
  than treating a valid larger capsule as malformed.
- An older CLI must report an unsupported-version error for a future capsule.
