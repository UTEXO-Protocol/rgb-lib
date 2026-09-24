# Two-role MPC support

2026-09-24. Preserve `dev` MPC behavior: fund Internal once, prepare External UTXOs with the existing `create_utxos_begin` / external signing / `create_utxos_end`, then blind receive. Two addresses remain: External for the RGB pool; Internal for BTC funding and one shared BTC/RGB change output. The API registers both fixed P2TR scripts with `get_rgb_address` / `get_address`; the companion API/Gateway/UI now expose delegated pool preparation, review, signing and recovery. No separate External deposit is required by the library.

RGB sends keep the upstream builder, Internal fee-input selection, fee estimator and dust rule. BTC remainder and returned RGB allocations can share the Internal output. Such an output is not eligible for plain BTC spending. The six public BTC balance fields retain the upstream address-based accounting; they are not a claim that every Internal satoshi is asset-free. There is no fixed carrier setting or separate excess output. MPC witness receive and pending-witness accounting additions were removed. The user's separate BFA invoice correction in `offline.rs` is preserved.

Address and UTXO helpers share the caller's transaction. A clean-dev temporary-wallet probe reproduced an eight-second DB pool timeout on `get_btc_balance(None, true)` without any provider call. The service-account `DfnsProvider` itself is unchanged. The delegated API verifies public metadata and signatures; the Gateway handles customer authorization.

A complete unsigned transaction is saved by `MpcWallet::send_begin` with the Initiated transfer in `mpc_prepared_inputs`, before the same DB commit; dry runs do not reserve inputs. No shared reservation hook is required. It reserves colored and fee inputs across restart even when the original PSBT file is missing. Legacy Initiated records without complete reservations need their original nonempty matching PSBT restored; malformed, missing or mismatched data blocks spending. Never clear journals/reservations to retry an unknown operation.

Pool preparation now excludes known RGB and reserved inputs, reserving selected inputs only when `dry_run=false`. Completion counts and records External outputs using registered provider scripts, because the placeholder BDK descriptors do not track them. Failed broadcast retains reservations; successful completion releases them. Repeating completion does not duplicate outputs or reset spent state. `list_pending_vanilla_txs` and `abort_pending_vanilla_tx` expose the native reservation lifecycle to MPC callers; abort only a transaction known not to have been broadcast and which will not be submitted later. Unknown outcomes require reconciliation.

The default pool remains five 1000-sat outputs, subject to available BTC, with at most one Internal change output. Provider-internal signing, address rotation, drain behavior and `src/mpc/dfns.rs` are unchanged. Gateway owns new-user `deriveFrom` provisioning and requires no library derivation change; existing independent wallets are preserved. Ordinary `Wallet` behavior is unchanged by this step.

## Evidence and repeatable checks

Clean base: `ca5f6b782e239b104fdaa3c30019668373f92377` (`dev`), eight baseline MPC PSBT tests passed. The clean `dfns_e2e` example compiles; its legacy service-account path was not executed against Dfns because credentials were unavailable. The new Gateway uses delegated keys-signature APIs instead.

```sh
cargo test --locked --lib --features mpc wallet::mpc
cargo clippy --locked --lib --features mpc -- -D warnings
```

Native test infrastructure now matches `dev`: the four files containing local indexer/proxy/miner/no-EVM overrides were restored. Use the repository's standard test infrastructure for native/HTLC suites. The MPC tests above need only temporary directories and localhost sockets, not Docker or an EVM node.

Verified 2026-09-24 after scope cleanup: 13 MPC tests, all-features/all-targets Clippy and formatting passed. The former helper-only input-filter test was folded into the public `create_utxos_begin` regression, including protection of known RGB change before synchronization. Pool regressions use synthetic UTXOs and a localhost Electrum fixture; they cover protected input selection, dry runs, restart/cancel, failed broadcast, output shape/count, blind invoice creation and repeated completion. They do not validate real signatures or chain acceptance.

Companion API verification on September 24 additionally passed one Internal deposit → pool preparation → blind receive 25 → sends 10 and 5 → remainder 10, with real local signatures/chain acceptance, lost pool prepare/submit responses, cancellation and restart recovery. Live Dfns HD creation/signing still needs acceptance.

Earlier September 24 evidence: 14 native HTLC and 3 native balance tests, plus the companion API regtest for funded blind receiving, two single-Internal-change sends (two keys then one), RGB-change protection, a separate BTC spend, unrelated allocations/exhaustion and restart recovery. Those tests were not rerun for this MPC-only step. No new provider call or live transfer was made. Private upstream Git mirrors remain build dependencies; BFA/EVM runtime is not needed.
