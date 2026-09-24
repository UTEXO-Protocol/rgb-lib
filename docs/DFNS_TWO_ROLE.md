# Two-role MPC support

2026-09-24. Preserve `dev` MPC behavior with blind receiving and one Internal change output. Two addresses remain: External for the initial funded RGB UTXO; Internal for BTC funding and change. The API registers both fixed P2TR scripts with `get_rgb_address` / `get_address`. Fund External before the first blind invoice.

RGB sends keep the upstream builder, fee estimator and dust rule. BTC remainder and returned RGB allocations can share the Internal output. Such an output is not eligible for plain BTC spending. The six public BTC balance fields retain the upstream address-based accounting; they are not a claim that every Internal satoshi is asset-free. There is no fixed carrier setting or separate excess output. `offline.rs` is identical to `dev`; MPC witness receive and pending-witness accounting additions were removed.

Address and UTXO helpers share the caller's transaction. A clean-dev temporary-wallet probe reproduced an eight-second DB pool timeout on `get_btc_balance(None, true)` without any provider call. The service-account `DfnsProvider` itself is unchanged. The delegated API verifies public metadata and signatures; the Gateway handles customer authorization.

A complete unsigned transaction is saved by `MpcWallet::send_begin` with the Initiated transfer in `mpc_prepared_inputs`, before the same DB commit; dry runs do not reserve inputs. No shared reservation hook is required. It reserves colored and fee inputs across restart even when the original PSBT file is missing. Legacy Initiated records without complete reservations need their original nonempty matching PSBT restored; malformed, missing or mismatched data blocks spending. Never clear journals/reservations to retry an unknown operation.

The scope review removed changes to provider-internal signing, address rotation, MPC `create_utxos` completion and create/drain reservation creation. Those existing service-account operations are not used by the delegated API. Their upstream behavior is unchanged except for adapting shared transaction-aware address/UTXO helpers. The API verifies immutable provider metadata before opening the wallet. All delegated signing remains in Gateway; `src/mpc/dfns.rs` is unchanged.

## Evidence and repeatable checks

Clean base: `ca5f6b782e239b104fdaa3c30019668373f92377` (`dev`), eight baseline MPC PSBT tests passed. The clean `dfns_e2e` example compiles; its legacy service-account path was not executed against Dfns because credentials were unavailable. The new Gateway uses delegated keys-signature APIs instead.

```sh
cargo test --locked --lib --features mpc wallet::mpc
cargo clippy --locked --lib --features mpc -- -D warnings
```

For native/HTLC tests against the API's isolated `tests/dfns/compose.yaml`, set the following for **each Cargo invocation** (indexer/proxy/no-EVM settings are compile-time). Create/fund the named regtest miner first. The override checks only the selected indexer; default upstream multi-indexer tests are unchanged.

```sh
export SKIP_INIT=1 COMPOSE_PROJECT_NAME=dfns-isolated
export RGB_TEST_RPC_WALLET=dfns-upstream-miner RGB_TEST_NO_EVM=1
export RGB_TEST_ELECTRUM_URL=127.0.0.1:51111
export RGB_TEST_PROXY_HOST=127.0.0.1:31110/json-rpc
export RGB_TEST_PROXY_URL=http://127.0.0.1:31110/json-rpc
cargo test --locked --lib --features mpc psbt_op_ -- --test-threads=1
cargo test --locked --lib --features mpc wallet::test::get_asset_balance -- --test-threads=1
cargo test --locked --lib --features mpc wallet::test::witness_receive -- --test-threads=1
```

Verified 2026-09-24: 12 MPC, 14 native HTLC and 3 native balance tests; all-features/all-targets Clippy. The companion API regtest passes funded blind receiving, two single-Internal-change sends (two keys then one), RGB-change protection, a separate BTC spend, unrelated allocations/exhaustion and restart recovery. No local test establishes live Dfns authorization. Private upstream Git mirrors remain build dependencies; BFA/EVM runtime is not needed.
