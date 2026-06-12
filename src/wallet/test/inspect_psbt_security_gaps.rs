//! PSBT validation gaps: 1 valid cosigner signature + foreign mnemonic signatures.
//!
//! Expected behaviour: **reject at every step**. Until rgb-lib enforces cosigner
//! fingerprints / quorum, this test fails and prints which steps wrongly accept the PSBT.

use std::str::FromStr;

use bdk_wallet::bitcoin::psbt::Psbt;

use super::*;
use super::inspect_psbt_gaps_common::*;
use crate::wallet::offline::RgbWalletOpsOffline;

/// 1 valid cosigner-1 signature + 2 bogus foreign `tap_script_sigs` (op #6 adversarial build).
#[test]
fn foreign_one_valid_two_foreign_rejected_at_each_step() {
    let wallet = signet_party_wallet_from_fixture(1);
    let psbt = load_fixture_b64("foreign_mnemonic", "combined_valid1_foreign2.psbt.b64");
    let fascia_path = fixture_root()
        .join("send_rgb/fascia.bin")
        .to_string_lossy()
        .to_string();

    let gaps = collect_psbt_validation_gaps(
        &wallet,
        &psbt,
        Some(&fascia_path),
        Some(SEND_RGB_ENTROPY),
    );

    assert_no_security_gaps(
        "1 valid cosigner + 2 foreign mnemonic signatures (combined_valid1_foreign2)",
        &gaps,
    );
}

/// Foreign-only PSBT (no valid cosigner signature) — ACK pre-check still passes today.
#[test]
fn foreign_only_signatures_rejected_at_each_step() {
    let wallet = signet_multisig_wallet("foreign_only");
    let psbt = load_fixture_b64("foreign_mnemonic", "send_btc_foreign_only.psbt.b64");

    let gaps = collect_psbt_validation_gaps(&wallet, &psbt, None, None);

    assert_no_security_gaps("foreign-only signatures (send_btc_foreign_only)", &gaps);
}

#[test]
fn finalize_rejects_foreign_combined_psbt() {
    let wallet = signet_multisig_wallet("foreign_finalize");
    let psbt = load_fixture_b64("foreign_mnemonic", "combined_valid1_foreign2.psbt.b64");
    let result = wallet.finalize_psbt(psbt, None);
    assert_matches!(result, Err(Error::CannotFinalizePsbt));
}

#[test]
fn inspect_psbt_omits_tap_key_sig_from_signature_count() {
    let wallet = signet_multisig_wallet("tap_key_sig");
    let psbt_str = load_fixture_b64("send_rgb", "signed_correct_slot2.psbt.b64");
    let psbt = Psbt::from_str(&psbt_str).unwrap();

    let info = wallet.inspect_psbt(psbt_str).unwrap();
    let mut rgb_count = 0u16;
    for input in psbt.inputs.iter() {
        rgb_count += input.partial_sigs.len() as u16;
        rgb_count += input.tap_script_sigs.len() as u16;
    }
    assert_eq!(info.signature_count, rgb_count);

    let tap_key_sig_count = psbt
        .inputs
        .iter()
        .filter(|i| i.tap_key_sig.is_some())
        .count() as u16;
    if tap_key_sig_count > 0 {
        assert!(
            info.signature_count + tap_key_sig_count > rgb_count,
            "tap_key_sig not included in signature_count"
        );
    }
}
