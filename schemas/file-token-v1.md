# Rebyte File Token v1

Copyright (c) 2026 Pedro Martins (pedro5g)

## Purpose and security boundary

A File Token v1 transports exactly one file as a portable `rf1_` string. It
contains all reconstructed bytes, optional compression metadata and a
domain-separated BLAKE3 digest. It requires no keyring and makes no publisher,
identity, freshness or authorization claim. Signed RAP v1 capsules remain the
required format when the origin of bytes matters.

A 32-byte digest alone cannot reconstruct arbitrary input. The token is
reversible because it carries a compressed representation of the complete
file in addition to the digest.

## Text representation

The canonical text is the ASCII prefix `rf1_` followed by RFC 4648 Base64URL
without padding. Whitespace, `=`, non-URL-safe alphabet bytes, empty payloads
and non-canonical trailing bits are rejected. Integers in the decoded binary
representation are unsigned and big-endian.

## Binary layout

| Offset | Size | Field | Required value |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `RBFT` |
| 4 | 1 | version | `1` |
| 5 | 1 | compression | `0` none, `1` Zstandard |
| 6 | 2 | reserved | zero |
| 8 | 8 | original size | reconstructed byte length |
| 16 | 8 | stored size | exact remaining payload length |
| 24 | 32 | file digest | BLAKE3 derive-key context `rebyte:v1:file` |
| 56 | variable | stored payload | verbatim bytes or one Zstandard frame |

Trailing bytes, truncated payloads, unknown versions or algorithms and
nonzero reserved fields are errors. Zstandard uses Rebyte's fixed v1 encoder
level and bounded streaming decoder. `auto` is an encoder policy: it stores
Zstandard only when the valid compressed payload is smaller; explicit `none`
and `zstd` remain valid canonical representations.

## Verification order

1. Bound textual length before Base64URL decoding.
2. Validate prefix, alphabet and canonical Base64URL.
3. Bound decoded length and parse the fixed header.
4. Reject unsupported fields, nonzero reserved bytes and length mismatch.
5. Enforce stored-size, reconstructed-size and compression-ratio limits.
6. Decompress while enforcing the declared output size.
7. Compute the domain-separated file digest and compare it in constant time.
8. Release reconstructed bytes only after every check succeeds.

The default limits are inherited from `SecurityLimits::V1`: 48 MiB text,
34 MiB decoded token, 32 MiB stored payload, 64 MiB single reconstructed file
and a 200:1 maximum expansion ratio. Encoders self-decode and verify their
result before returning it.

## Compatibility

`rf1_` and this binary layout are frozen for File Token v1. Incompatible
changes require a new prefix and version. The immutable uncompressed `Rebyte`
test vector is:

```text
rf1_UkJGVAEAAAAAAAAAAAAABgAAAAAAAAAGELq0ltLAXFF-dIZTKN_Sfl_nGEqHDZAKUuFpxKbGy2BSZWJ5dGU
```
