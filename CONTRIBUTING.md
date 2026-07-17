# Contributing to Rebyte

## Quality gate

Every change must keep these commands green:

```console
cargo xtask check
cargo xtask test
```

Security-sensitive changes additionally require the relevant protocol vectors,
property tests, adversarial tests or fuzz targets. Public behavior must be
documented in the README and rustdoc in the same commit.

## Commit messages

Use Conventional Commits, for example:

```text
feat(codec): reject non-canonical manifest fields
fix(apply): revalidate target before atomic rename
docs(protocol): clarify signature domain
```

Keep commits reviewable and do not add generated AI notes, prompts or chat logs.
Such internal material belongs only in the ignored `.ai/` directory.

## Safety rules

- Do not add private production keys, tokens or credentials.
- Do not add command execution or network behavior to product crates.
- Do not introduce unsafe Rust without changing the published policy first.
- Never rewrite a published RAP v1 test vector.
