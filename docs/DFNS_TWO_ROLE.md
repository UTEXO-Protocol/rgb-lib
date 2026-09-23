# Two-role MPC support

2026-09-23. Provider-neutral library work for the Dfns experiment. Live provider signing remains outside this library's acceptance evidence.

`MpcWallet` reuses two independently verified P2TR scripts when `reuse_addresses=true`: External is the RGB carrier, Internal is fee/excess BTC. `set_rgb_carrier_amount` accepts 330–100000 sat (default 1000). A carrier is created only when the selected inputs return RGB assignments, including contracts absent from the send request. Carried-forward contracts have no recipient transport endpoints; finalization skips their endpoint update. Other change goes to Internal; sub-dust remainder becomes fee. Estimation includes final Taproot witnesses and the actual OP_RETURN commitment size.

Address and UTXO-query helpers participate in the caller's database transaction. Own change does not consume an unrelated pending witness invoice on a reused script. Pending amount-bearing witness invoices contribute to future balance only until a Receive coloring exists; the public balance accounting fields remain unchanged.

A complete unsigned transaction is saved by `MpcWallet::send_begin` with the Initiated transfer in `mpc_prepared_inputs`, before the same DB commit; dry runs do not reserve inputs. No shared reservation hook is required. It reserves colored and fee inputs across restart even when the original PSBT file is missing. Legacy Initiated records without complete reservations need their original nonempty matching PSBT restored; malformed, missing or mismatched data blocks spending. Never clear journals/reservations to retry an unknown operation.

The scope review removed changes to provider-internal signing, address rotation, MPC `create_utxos` completion and create/drain reservation creation. Those existing service-account operations are not used by the delegated API. Their upstream behavior is unchanged except for adapting shared transaction-aware address/UTXO helpers. The API verifies immutable provider metadata before opening the wallet. All delegated signing remains in Gateway; `src/mpc/dfns.rs` is unchanged.

## Evidence and repeatable checks

Clean base: `ca5f6b782e239b104fdaa3c30019668373f92377` (`dev`), eight baseline MPC PSBT tests passed. The clean `dfns_e2e` example compiles; its legacy service-account path was not executed against Dfns because credentials were unavailable. The new Gateway uses delegated keys-signature APIs instead.

```sh
cargo test --locked --lib --features mpc wallet::mpc
cargo test --locked --lib --features mpc database::pending_witness_balance_tests
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

Verified 2026-09-23: 14 HTLC, 3 native balance and 2 native witness tests passed. The API integration fixture exercises two successive two-key sends, separate vanilla spend, unknown prepare/submit recovery, fee reservation after restart without the original PSBT, unrelated allocations and exhausted RGB change. All coins/keys are disposable regtest fixtures. Private upstream Git mirrors are still build dependencies; no BFA runtime or legacy provider flow is required by these checks.
