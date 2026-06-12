//! Op #5: party-2 ACK path with cosigner-3 keys instead of cosigner-2.
//!
//! Only party-1 + party-2 cosigner signatures should count. A signature from cosigner-3
//! on behalf of party-2 must be rejected at **every** validation step.

use super::inspect_psbt_gaps_common::*;

const SEND_RGB_ASSET_ID: &str = "rgb:i419M6E9-RyPUoXr-hIFFGnm-mM_5FWO-nDV9a2p-4O3kogQ";

/// Wrong-cosigner PSBT alone (party-2 slot, cosigner-3 key) — pre-ACK inspection path.
#[test]
fn op5_wrong_cosigner_single_psbt_rejected_at_each_step() {
    let wallet = signet_party_wallet_from_fixture(1);
    let wrong_party2_psbt = load_fixture_b64("send_rgb", "signed_wrong_slot3.psbt.b64");
    let fascia_path = fixture_root()
        .join("send_rgb/fascia.bin")
        .to_string_lossy()
        .to_string();

    let gaps = collect_psbt_validation_gaps(
        &wallet,
        &wrong_party2_psbt,
        Some(&fascia_path),
        Some(SEND_RGB_ENTROPY),
    );

    assert_no_security_gaps(
        "op #5 party-2 PSBT signed with cosigner-3 (fp 07310948, expected 27efda0a)",
        &gaps,
    );
}

/// After hub combine (cosigner-1 + wrong cosigner-3) — broadcast path must still reject wrong identity.
#[test]
fn op5_wrong_cosigner_combined_psbt_rejected_at_finalize() {
    let wallet = signet_party_wallet_from_fixture(1);
    let wrong_party2_psbt = load_fixture_b64("send_rgb", "signed_wrong_slot3.psbt.b64");
    let unsigned = load_fixture_b64("send_rgb", "unsigned.psbt.b64");

    let cosigner_1 = signet_singlesig_wallet(COSIGNER_1_MNEMONIC, COSIGNER_1_FP);
    let party1_signed = cosigner_1.sign_psbt(unsigned, None).unwrap();
    let combined = combine_psbts(&party1_signed, &wrong_party2_psbt);

    let gaps = collect_psbt_validation_gaps(&wallet, &combined, None, None);

    assert_no_security_gaps(
        "op #5 combined PSBT (cosigner-1 + cosigner-3 posing as party-2)",
        &gaps,
    );
}

/// Documents current behaviour when gaps exist — run with `--nocapture` to see per-step OK/GAP lines.
#[test]
#[ignore = "diagnostic: prints gap report without failing; run manually"]
fn op5_wrong_cosigner_gap_report() {
    let wallet = signet_party_wallet_from_fixture(1);
    let wrong_party2_psbt = load_fixture_b64("send_rgb", "signed_wrong_slot3.psbt.b64");
    let fascia_path = fixture_root()
        .join("send_rgb/fascia.bin")
        .to_string_lossy()
        .to_string();

    println!("=== op #5 wrong cosigner — single PSBT ===");
    let gaps = collect_psbt_validation_gaps(
        &wallet,
        &wrong_party2_psbt,
        Some(&fascia_path),
        Some(SEND_RGB_ENTROPY),
    );
    for g in &gaps {
        println!("GAP: {g}");
    }
    if gaps.is_empty() {
        println!("No gaps — rgb-lib correctly rejects wrong cosigner at all steps");
    }

    let unsigned = load_fixture_b64("send_rgb", "unsigned.psbt.b64");
    let cosigner_1 = signet_singlesig_wallet(COSIGNER_1_MNEMONIC, COSIGNER_1_FP);
    let combined = combine_psbts(
        &cosigner_1.sign_psbt(unsigned, None).unwrap(),
        &wrong_party2_psbt,
    );

    println!("=== op #5 wrong cosigner — combined PSBT (hub Approved path) ===");
    let gaps = collect_psbt_validation_gaps(&wallet, &combined, None, None);
    for g in &gaps {
        println!("GAP: {g}");
    }

    let _ = SEND_RGB_ASSET_ID;
}
