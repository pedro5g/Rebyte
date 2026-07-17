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

Rebyte 1.0.0 measures 76.73% workspace line coverage after adding the complete
publisher CLI integration. The encrypted key-document module measures 90.29%,
codec decode/encode measure 92.55%/96.74%, and apply remains 83.78%. The
workspace and several critical modules are still below the 90%/95% targets, so
the gap remains explicit release follow-up rather than being presented as
completed security evidence.

Rebyte 1.1.0 measures 77.10% workspace line coverage. The new File Token v1
crate measures 83.85% and is additionally exercised by property, immutable
vector, malformed-input, large-text process integration and fuzz tests. This is
an improvement over 1.0.0, but it does not satisfy the long-term workspace or
critical-module targets; those targets remain open quality work.

Scheduled CI publishes `lcov.info` and Criterion estimates. Reviewers compare
critical-operation medians against the most recent accepted artifact. A
regression over 10% requires investigation; a regression over 20% blocks a
release unless the changelog records a reviewed platform or security tradeoff.

Reproduce the measurements with:

```console
cargo llvm-cov --workspace --all-features --summary-only
cargo bench -p rebyte-codec --bench codec -- --noplot
```
