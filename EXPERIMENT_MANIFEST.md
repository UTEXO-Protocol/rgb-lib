# RGB historical witness performance experiment

Recorded: 2026-08-06 23:48:28 IST

## Purpose and ownership

This manifest defines the complete rollback boundary for the experiment that reproduced and optimized the multi-minute RGB transfer acceptance path. None of these changes are approved production changes. The work is preserved on `hardik/rgb-witness-resolution-experiment` in each protocol repository so it remains isolated from production branches.

The Iris Wallet app worktree at `/Users/hardik/Projects/utexo-app` is explicitly outside this experiment. It was already dirty, remains on `signet-testing` at `31766e7f5ee725a825499e6651b569b58f819c65`, and no app file was edited during this experiment.

## Repository summary

| Repository | Local experiment worktree | Immutable baseline | Before | After |
|---|---|---|---|---|
| `UTEXO-Protocol/rgb-lib` | `/Users/hardik/Projects/rgb-protocol-perf-lab` | `2e1026e9b15fffdbc2ea8b0f7f23a10ffe1f11ca` | Clean detached checkout; no performance fixture or resolver changes | Operation-scoped witness cache, bounded witness prefetch, acceptance integration, test harness adaptations, deterministic fixture and diagnostic proxy |
| `rgb-protocol/rgb-ops` | `/Users/hardik/Projects/rgb-ops-perf-lab` | `08911c5b66b8a7e628f6636a99a17b8082dbc232` | Clean detached checkout; Esplora resolver made two sequential requests | One-response Esplora resolver using `get_tx_info()`; preserved on `Jainakin/rgb-ops` because upstream rejected direct branch pushes |
| `UTEXO-Protocol/rgb-lightning-node` | `/Users/hardik/Projects/rgb-lightning-node-perf-lab` | `0bfa66fa256a6c36f3737d5b6402eacea40c68fc` | Clean detached checkout using tagged `rgb-lib` | Build-only local dependency override proving RLN compiles with one patched `rgb-lib` instance |

All three directories were created specifically for this experiment. Deleting these three worktrees removes every repository change described here without touching any pre-existing wallet work.

## rgb-lib changes

Tracked files:

- `Cargo.toml`: adds `[patch.crates-io]` entries for `rgb-ops` and `rgb-invoicing` from `Jainakin/rgb-ops` branch `hardik/rgb-witness-resolution-experiment`.
- `Cargo.lock`: pins those experiment dependencies to commit `b9da59b0`.
- `src/lib.rs`: imports `VecDeque`, `Mutex`, and `MutexGuard`.
- `src/utils.rs`: adds `OperationResolver`, successful-result operation caching, eight-worker bounded prefetch, a 256-witness prefetch bound, typed network failure aggregation, and poison-tolerant lock acquisition.
- `src/wallet/rust_only.rs`: prefetches before mutation and reuses one resolver through validation, contract import, and runtime acceptance in both `accept_transfer()` and `save_new_asset()`.
- `src/wallet/test/mod.rs`: registers the performance test module.
- `src/wallet/test/utils/chain.rs`: points fixture mining and indexer synchronization at the existing wallet Regtest stack.
- `src/wallet/test/utils/helpers.rs`: uses the existing stack's direct Docker execution path.

Untracked experiment files:

- `EXPERIMENT_MANIFEST.md`: this rollback manifest.
- `evidence/2026-08-06/`: 19 copied benchmark, fault-injection and regression logs generated during the experiment.
- `src/wallet/test/high_history_perf.rs`: fixture generator, replay benchmarks, worker-count experiments, persistence replay and fault injection.
- `tests/perf-fixture/asset-id.txt`
- `tests/perf-fixture/final-txid.txt`
- `tests/perf-fixture/high-history.rgbc`
- `tools/signet-profile-proxy.mjs`: deterministic latency and request-budget failure proxy.

Fixture identity:

- Asset: `rgb:VyLXf0Dy-VDAK5iZ-ETnpZkt-3q6PNt5-hYLM5gx-Ylf2EoE`
- Final transaction: `79c4574bf73c2b5fcd490e639ffe0c68eb6990c13b82531f465d3c762fa49c30`
- Consignment: 49,648 bytes, 88 witness bundles, 88 transitions
- Consignment SHA-256: `f5afdbfc721abfab208a40ffd9b2d063cc477a614349ecc8953c51c8d2e65983`
- Benchmark source SHA-256: `450892cc55bb3375b106ed4cb2167331d2af21befb4785f07f842c3c6997960b`
- Failure proxy SHA-256: `30dc10894ee24b20c160bb3fa0782ae0642ccc0e6239302b6225029fa2dc50a6`

## rgb-ops changes

Tracked files:

- `src/indexers/esplora_blocking.rs`: replaces sequential `get_tx()` and `get_tx_status()` calls with one `get_tx_info()` call and converts its transaction/status data into the same `WitnessStatus` result.

Current file SHA-256: `bb3e3b87a0b4cba7592de610c1f16a6db9fe6377374cc27817e7884d803baa9f`.

There are no untracked files in this worktree.

## rgb-lightning-node changes

Tracked files:

- `Cargo.toml`: points the direct `rgb-lib` dependency to the local experiment and adds a source-level patch for `rgb-lib` and `rgb-lib-migration`, ensuring RLN and Rust Lightning use one crate instance.
- `Cargo.lock`: records the local dependency resolution.

No RLN protocol, channel, mutex, event, persistence or API implementation was changed. This worktree exists only as an integration compile proof.

There are no untracked files in this worktree. Generated Cargo build artifacts were cleaned after the integration compile.

## Local stack side effects

The shared `utexo-wallet-devstack` was not rebuilt or reconfigured, but its persistent Regtest data was mutated by the fixture:

- The 88 fixture transfers are confirmed from block 270 through block 357.
- The current Esplora tip after fixture generation and follow-up acceptance tests is block 362.
- The RGB proxy contains consignments produced by the fixture.
- Temporary Toxiproxy and Node latency/failure proxies were stopped and removed.
- Bitcoin, Electrs, Esplora, RGB proxy, VSS and LSP remain running.

The exact pre-experiment chain height was not captured. Bitcoin blocks and proxy data cannot be selectively rolled back safely. A full dev-stack volume reset would remove this experiment's chain state, but it would also erase unrelated local wallets, channels, VSS data and previous test state. Do not reset those volumes as part of a source-code rollback without a separate explicit decision.

## Evidence and results

Key results:

- Untouched local resolver: 1.88 seconds.
- Untouched resolver with Signet-like latency: 234.59 seconds.
- Memoization only: 119.57 seconds.
- One-response resolver only: 120.84 seconds.
- One response plus memoization: 61.47 seconds.
- Four-worker prefetch: 18.32 seconds.
- Eight-worker prefetch: 10.96 seconds.
- Sixteen-worker prefetch: 7.53 seconds.
- Production-shaped eight-worker implementation: 12.11 seconds.
- Acceptance plus independent `save_new_asset()` pass: 21.90 seconds.
- Controlled request-budget test: original failed after 91.25 seconds; optimized completed in 12.12 seconds.

Primary logs are durably copied to `evidence/2026-08-06/`. The original temporary copies remain under `/private/tmp` with the prefix `rgb-regtest-` and date suffix `2026-08-06.log`. The fixture-generation log is `evidence/2026-08-06/rgb-regtest-high-history-generate-2026-08-06.log`, SHA-256 `f9b20049d58fdef8042685e1a3321055690d5786a33a2286f42ae2638365a3e4`.

## Verification completed

- Existing real `accept_transfer` test on Esplora.
- Existing real `save_new_asset` test.
- Default Electrum acceptance test.
- Pure Electrum compilation.
- Pure Esplora compilation.
- Strict `cargo clippy --features esplora --lib --tests -- -D warnings`.
- Repository formatting and whitespace checks.
- All 37 `rgb-ops` tests with all features.
- Fresh RLN integration compilation with one patched `rgb-lib` dependency.
- Failure-before-mutation fault injection.

## Reversion boundary

Source rollback should operate only on the three disposable worktrees listed above. The clean baseline for each is its recorded immutable commit. Since the directories did not exist before the experiment, removing the directories is the most complete rollback and also removes fixtures, test adaptations and local dependency wiring.

Do not run a restore, clean, reset or checkout command in `/Users/hardik/Projects/utexo-app` as part of this rollback. Do not reset Docker volumes unless erasing the shared Regtest/VSS/LSP state is separately approved.
