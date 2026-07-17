# Rebyte

Rebyte Artifact Protocol (RAP) reconstructs exact file artifacts from bounded,
signed and self-contained capsules without executing commands or depending on
remote storage.

> Rebyte is under active development. The protocol specification is available
> in [`schemas/rap-v1.md`](schemas/rap-v1.md); no production key is trusted yet.

## Design promises

- byte-for-byte reconstruction verified with BLAKE3;
- Ed25519 publisher authentication and local trust policy;
- strictly relative, portable paths and bounded decompression;
- no shell commands, hooks, network access or generated-code execution;
- atomic replacement per file with recoverable multi-file transactions;
- native CLI targets for Linux, macOS and Windows plus a filesystem-free Wasm
  interface.

The detailed threat and security models live in [`docs/`](docs/). User-facing
installation, API and operations documentation will grow with each implemented
phase and be complete before the v1 release.

## Development

The repository uses Rust 1.97.1, Edition 2024 and a Cargo workspace. Once the
workspace dependencies are fetched:

```console
cargo xtask check
cargo xtask test
```

Internal AI-assisted notes must stay below the ignored `.ai/` directory.

## License

Licensed under either Apache License, Version 2.0 or the MIT license, at your
option.
