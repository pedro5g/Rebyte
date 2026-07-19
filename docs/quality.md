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

The current unreleased Chain v2 workspace measures 80.92% line coverage on
2026-07-18 after removing File Token v1. Security-sensitive results include
96.21% for quorum release, 97.83% for Shamir secret sharing, 90.44% for the
encrypted envelope, 91.01% for Access Contract v1, 91.28% for the in-memory
artifact codec and 90.80% for the CLI release ledger. RAP decode is 92.55%,
portable paths are 80.00%, artifact streaming is 85.79%, verification is
82.26% and filesystem apply is 83.19%. The aggregate improved, but the
workspace and several critical modules still do not meet the stated 90%/95%
targets. A release must report this gap honestly rather than relabeling tested
behavior as independently audited assurance.

On 2026-07-19 the unreleased workspace adds targeted edge tests for the four
weakest review-flagged modules. Portable paths now measure 100% in-crate,
verification, filesystem apply and artifact streaming each gained
error-display, staged-typestate, interrupted-transaction and
conflicting-output tests, and the transaction engine's incomplete-transaction
and corrupted-journal failsafes are exercised directly. Workspace totals
temporarily include the new sharded-challenge, key-sequence, ceremony, audit
and rekey CLI surface, whose subprocess-driven coverage remains below target;
the honest reading is per-module, and the 90%/95% targets stay open work.

Scheduled CI publishes `lcov.info` and Criterion estimates. Reviewers compare
critical-operation medians against the most recent accepted artifact. A
regression over 10% requires investigation; a regression over 20% blocks a
release unless the changelog records a reviewed platform or security tradeoff.

Reproduce the measurements with:

```console
cargo llvm-cov --workspace --all-features --summary-only
cargo bench -p rebyte-codec --bench codec -- --noplot
```
