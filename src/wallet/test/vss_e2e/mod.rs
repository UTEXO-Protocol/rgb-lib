use super::*;

// VSS E2E integration tests (QA scenarios).
//
// Run:
// - Recommended (full suite on regtest): `cargo test --features vss,electrum vss_e2e -- --nocapture`
// - Ignored/manual-only: `cargo test --features vss,electrum vss_e2e -- --ignored --nocapture`
// - Minimal (no regtest; only tests gated by `feature="vss"`): `cargo test --features vss vss_e2e -- --nocapture`
//
// Notes:
// - Some scenarios are intentionally `#[ignore]` (slow/flaky/disruptive) or explicitly blocked
//   by a known issue (the ignore reason string explains why).
// - Disruptive scenarios that stop docker services are `#[serial]`.

mod autobackup;
mod disruptive;
mod migration;
mod negative;
mod restore_chunked;
mod restore_encrypted;
mod restore_unencrypted;
