//! Shared helpers for multisig PSBT security-gap tests.

use std::{fmt, fs, path::PathBuf, str::FromStr};

use bdk_wallet::bitcoin::psbt::Psbt;

use super::*;
use crate::{
    keys::restore_keys,
    wallet::{offline::RgbWalletOpsOffline, singlesig::SinglesigKeys},
};

pub(super) const COSIGNER_1_MNEMONIC: &str =
    "else echo damage jealous green april knife prize corn stairs mother style";
pub(super) const COSIGNER_1_FP: &str = "a0d30ec5";
pub(super) const COSIGNER_2_FP: &str = "27efda0a";
pub(super) const COSIGNER_3_FP: &str = "07310948";

pub(super) const COSIGNER_1_COLORED_XPUB: &str =
    "tpubDC89L63ALPX4yxaguKmQhfn2zLFv2GyjihKgJ8MqsDqrCGEw53vGt1df7GTAsgmCnU6MLkesZZfAGKMVMjchMoDVuZTjWL63nkn7WvEBrXW";
pub(super) const COSIGNER_2_COLORED_XPUB: &str =
    "tpubDCyM9iGCqRoruh6fr5B87cntA6pKDTJV2CVXndi8wvcatPXboeJs52RAQ1XXEbBdshgN8ttdcZUEA6XcS33ZXXjtVosMcvtf516orwfJGZJ";
pub(super) const COSIGNER_3_COLORED_XPUB: &str =
    "tpubDCM2tNjRs8MZ8bzYDkgvttm9cNQSg5sxix9fSoYgSPgarYqaTS7oGTfTFyvvLZYs8kCFjvEZHBxVMi7dfqwHZBKdxL5aydFC59bmmgMWaCj";

pub(super) const COSIGNER_1_VANILLA_XPUB: &str =
    "tpubDDPXUJ8Zm9YLxyg8fHAwZEKPUdV63b5GDA2XQov3xP4D7QUaZNtUE5HxbZRJerYHBuJaZm7gsmffPDPa7qfV33LP9dNJjZybD5AhrR5aG2o";
pub(super) const COSIGNER_2_VANILLA_XPUB: &str =
    "tpubDDqkxr2nDKQdDFPV9w6xnRQQWs7UZ9fgmpj2c8AR4fKAUEPR2uSQhnV4AL6D8XutaqhSzRingsA8fKegVanwdRyyege3iJsQaoMZ74JmjYE";
pub(super) const COSIGNER_3_VANILLA_XPUB: &str =
    "tpubDCKJZh6VBQZBU1k67ASkgZZqUwV2go2MsnyKwKwY6vtcwqxhxuqhqnT9G5FhAu5pX2CFxZ1YGNkjRuS2LAYQRCpGW1BFoUPCwy7ALywMiBU";

pub(super) const SEND_RGB_ENTROPY: u64 = 1890141285888588334;
pub(super) const SEND_RGB_TXID: &str =
    "fcf92b9147c3eb7a0dbdae1ded6874cb4035a3fd47a4a36f373e8bc2c558a094";

pub(super) fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/wallet/test/fixtures/inspect_psbt_gaps")
}

pub(super) fn load_fixture_b64(subdir: &str, name: &str) -> String {
    fs::read_to_string(fixture_root().join(subdir).join(name))
        .unwrap()
        .trim()
        .to_string()
}

pub(super) fn signet_multisig_keys() -> MultisigKeys {
    MultisigKeys::new(
        vec![
            Cosigner {
                master_fingerprint: COSIGNER_1_FP.to_string(),
                account_xpub_colored: COSIGNER_1_COLORED_XPUB.to_string(),
                account_xpub_vanilla: COSIGNER_1_VANILLA_XPUB.to_string(),
                vanilla_keychain: None,
            },
            Cosigner {
                master_fingerprint: COSIGNER_2_FP.to_string(),
                account_xpub_colored: COSIGNER_2_COLORED_XPUB.to_string(),
                account_xpub_vanilla: COSIGNER_2_VANILLA_XPUB.to_string(),
                vanilla_keychain: None,
            },
            Cosigner {
                master_fingerprint: COSIGNER_3_FP.to_string(),
                account_xpub_colored: COSIGNER_3_COLORED_XPUB.to_string(),
                account_xpub_vanilla: COSIGNER_3_VANILLA_XPUB.to_string(),
                vanilla_keychain: None,
            },
        ],
        2,
        2,
    )
}

pub(super) fn signet_multisig_wallet(dir_suffix: &str) -> MultisigWallet {
    create_test_data_dir();
    let data_dir = get_test_data_dir_path()
        .join(format!("inspect_psbt_gaps_{dir_suffix}"))
        .to_string_lossy()
        .to_string();
    let _ = fs::create_dir_all(&data_dir);
    MultisigWallet::new(
        WalletData {
            data_dir,
            bitcoin_network: BitcoinNetwork::Signet,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        signet_multisig_keys(),
    )
    .unwrap()
}

pub(super) fn signet_party_wallet_from_fixture(party: u8) -> MultisigWallet {
    let data_dir = fixture_root()
        .join(format!("party_datadirs/party-{party}"))
        .to_string_lossy()
        .to_string();
    MultisigWallet::new(
        WalletData {
            data_dir,
            bitcoin_network: BitcoinNetwork::Signet,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        signet_multisig_keys(),
    )
    .unwrap()
}

pub(super) fn signet_singlesig_wallet(mnemonic: &str, expected_fp: &str) -> Wallet {
    let keys = restore_keys(
        BitcoinNetwork::Signet,
        mnemonic.to_string(),
        WitnessVersion::Taproot,
    )
    .unwrap();
    assert_eq!(keys.master_fingerprint, expected_fp);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let data_dir = fixture_root()
        .join(format!("singlesig_{expected_fp}"))
        .to_string_lossy()
        .to_string();
    let _ = fs::create_dir_all(&data_dir);
    Wallet::new(
        WalletData {
            data_dir,
            bitcoin_network: BitcoinNetwork::Signet,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        wallet_keys,
    )
    .unwrap()
}

pub(super) fn combine_psbts(base: &str, other: &str) -> String {
    let mut combined = Psbt::from_str(base).unwrap();
    combined.combine(Psbt::from_str(other).unwrap()).unwrap();
    combined.to_string()
}

/// One validation layer in the multisig ACK / broadcast path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ValidationStep {
    InspectPsbt,
    InspectRgbTransfer,
    RespondToOperationPreAck,
    FinalizePsbt,
}

impl fmt::Display for ValidationStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InspectPsbt => write!(f, "inspect_psbt"),
            Self::InspectRgbTransfer => write!(f, "inspect_rgb_transfer"),
            Self::RespondToOperationPreAck => write!(f, "respond_to_operation (pre-ACK)"),
            Self::FinalizePsbt => write!(f, "finalize_psbt"),
        }
    }
}

#[derive(Debug)]
pub(super) struct StepSecurityGap {
    pub step: ValidationStep,
    pub detail: String,
}

impl fmt::Display for StepSecurityGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.step, self.detail)
    }
}

/// Run all four checks. Returns gaps where rgb-lib **accepted** a PSBT that should be rejected.
pub(super) fn collect_psbt_validation_gaps(
    wallet: &MultisigWallet,
    psbt: &str,
    fascia_path: Option<&str>,
    entropy: Option<u64>,
) -> Vec<StepSecurityGap> {
    let mut gaps = Vec::new();

    match wallet.inspect_psbt(psbt.to_string()) {
        Ok(info) => gaps.push(StepSecurityGap {
            step: ValidationStep::InspectPsbt,
            detail: format!(
                "accepted PSBT (txid {}, signature_count={}) — expected reject: not all signatures are from wallet cosigners",
                info.txid, info.signature_count
            ),
        }),
        Err(e) => eprintln!("OK {}: rejected — {e}", ValidationStep::InspectPsbt),
    }

    if let (Some(fascia_path), Some(entropy)) = (fascia_path, entropy) {
        match wallet.inspect_rgb_transfer(psbt.to_string(), fascia_path.to_string(), entropy) {
            Ok(inspection) => gaps.push(StepSecurityGap {
                step: ValidationStep::InspectRgbTransfer,
                detail: format!(
                    "accepted RGB transfer ({} operation(s), commitment {}) — expected reject: invalid cosigner signatures",
                    inspection.operations.len(),
                    &inspection.commitment_hex[..16]
                ),
            }),
            Err(e) => eprintln!("OK {}: rejected — {e}", ValidationStep::InspectRgbTransfer),
        }
    }

    // Mirrors respond_to_operation: sig count > 0 + txid match (no fingerprint / quorum).
    match wallet.inspect_psbt(psbt.to_string()) {
        Ok(info) if info.signature_count > 0 => gaps.push(StepSecurityGap {
            step: ValidationStep::RespondToOperationPreAck,
            detail: format!(
                "would accept ACK (signature_count={} > 0, no cosigner fingerprint check) — expected reject: foreign or wrong-party signatures",
                info.signature_count
            ),
        }),
        Ok(_) => eprintln!(
            "OK {}: rejected — zero signatures",
            ValidationStep::RespondToOperationPreAck
        ),
        Err(e) => eprintln!(
            "OK {}: rejected — {e}",
            ValidationStep::RespondToOperationPreAck
        ),
    }

    match wallet.finalize_psbt(psbt.to_string(), None) {
        Ok(_) => gaps.push(StepSecurityGap {
            step: ValidationStep::FinalizePsbt,
            detail: s!("finalized PSBT — expected reject: insufficient valid cosigner signatures"),
        }),
        Err(Error::CannotFinalizePsbt) => {
            eprintln!("OK {}: rejected — CannotFinalizePsbt", ValidationStep::FinalizePsbt)
        }
        Err(e) => eprintln!("OK {}: rejected — {e}", ValidationStep::FinalizePsbt),
    }

    gaps
}

pub(super) fn assert_no_security_gaps(scenario: &str, gaps: &[StepSecurityGap]) {
    if gaps.is_empty() {
        return;
    }
    let report = gaps
        .iter()
        .map(|g| format!("  - {g}"))
        .collect::<Vec<_>>()
        .join("\n");
    panic!(
        "SECURITY GAP in scenario '{scenario}': rgb-lib should reject at every step \
         (only cosigner signatures count), but accepted at:\n{report}\n\
         Fix rgb-lib, then this test should pass with zero gaps."
    );
}
