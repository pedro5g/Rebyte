# Quality baselines

Copyright (c) 2026 Pedro Martins (pedro5g)

The long-term release target is at least 90% line coverage across product
crates and 95% in codec, verification, paths and transaction journal logic.
Coverage is evidence about exercised lines, not a replacement for fuzzing,
properties, mutation testing, Miri or filesystem fault tests.

The first complete RAP v1 implementation measured 73.54% workspace line
coverage on 2026-07-16. This is the explicit baseline, not a claim that the
release target is already met. New public behavior must include tests, and
coverage may not regress while the project closes the gap to the target.

Scheduled CI publishes `lcov.info` and Criterion estimates. Reviewers compare
critical-operation medians against the most recent accepted artifact. A
regression over 10% requires investigation; a regression over 20% blocks a
release unless the changelog records a reviewed platform or security tradeoff.

Reproduce the measurements with:

```console
cargo llvm-cov --workspace --all-features --summary-only
cargo bench -p rebyte-codec --bench codec -- --noplot
```
