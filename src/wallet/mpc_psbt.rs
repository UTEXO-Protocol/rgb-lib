//! Manual PSBT construction utilities for MPC mode.
//!
//! Since MPC wallets don't have a BDK wallet instance, we build PSBTs manually
//! using the `bitcoin` crate primitives.

use bdk_wallet::bitcoin::{
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    locktime::absolute::LockTime, psbt::Psbt, transaction::Version,
};

use crate::Error;

/// Taproot (P2TR) dust limit in satoshis.
pub const TAPROOT_DUST: u64 = 330;

/// Taproot key-path spend vbytes per input.
const TAPROOT_INPUT_VBYTES: u64 = 58;
/// P2TR output vbytes.
const P2TR_OUTPUT_VBYTES: u64 = 43;
/// Transaction overhead vbytes.
const TX_OVERHEAD_VBYTES: u64 = 11;

/// Estimate the virtual size of a transaction with the given number of
/// Taproot key-path inputs and P2TR outputs.
pub fn estimate_tx_vbytes(num_inputs: usize, num_outputs: usize) -> u64 {
    TX_OVERHEAD_VBYTES
        + num_inputs as u64 * TAPROOT_INPUT_VBYTES
        + num_outputs as u64 * P2TR_OUTPUT_VBYTES
}

/// Calculate the fee in satoshis for the given number of inputs/outputs at the
/// specified fee rate.
pub fn calculate_fee(
    num_inputs: usize,
    num_outputs: usize,
    fee_rate: bdk_wallet::bitcoin::blockdata::fee_rate::FeeRate,
) -> u64 {
    let vbytes = estimate_tx_vbytes(num_inputs, num_outputs);
    fee_rate.to_sat_per_vb_ceil() * vbytes
}

/// Build an unsigned PSBT from the provided inputs and outputs.
///
/// Each input gets its `witness_utxo` populated in the PSBT (required for
/// Taproot signing).
pub fn build_psbt(inputs: Vec<(OutPoint, TxOut)>, outputs: Vec<TxOut>) -> Result<Psbt, Error> {
    let tx_inputs: Vec<TxIn> = inputs
        .iter()
        .map(|(outpoint, _)| TxIn {
            previous_output: *outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        })
        .collect();

    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    };

    let mut psbt = Psbt::from_unsigned_tx(transaction).map_err(|e| Error::Internal {
        details: format!("Failed to create PSBT: {e}"),
    })?;

    // Populate witness_utxo and tap_internal_key for each input (required for Taproot signing)
    for (i, (_, txout)) in inputs.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(txout.clone());

        // For P2TR inputs, extract the x-only public key from the script pubkey
        // P2TR script: OP_1 (0x51) + OP_PUSHBYTES_32 (0x20) + 32-byte x-only pubkey
        let script = txout.script_pubkey.as_bytes();
        if script.len() == 34
            && script[0] == 0x51
            && script[1] == 0x20
            && let Ok(xonly) = XOnlyPublicKey::from_slice(&script[2..34])
        {
            psbt.inputs[i].tap_internal_key = Some(xonly);
        }
    }

    Ok(psbt)
}

/// Simple largest-first coin selection.
///
/// Returns the selected UTXOs and their total value.
pub fn select_coins(
    available: &[(OutPoint, TxOut)],
    target: u64,
    fee_rate: bdk_wallet::bitcoin::blockdata::fee_rate::FeeRate,
    num_outputs: usize,
) -> Result<(Vec<(OutPoint, TxOut)>, u64), Error> {
    // Sort by value descending (largest first)
    let mut sorted: Vec<_> = available.to_vec();
    sorted.sort_by(|a, b| b.1.value.cmp(&a.1.value));

    let mut selected = Vec::new();
    let mut total: u64 = 0;

    for utxo in sorted {
        selected.push(utxo.clone());
        total += utxo.1.value.to_sat();
        let fee = calculate_fee(selected.len(), num_outputs + 1, fee_rate); // +1 for change
        if total >= target + fee {
            return Ok((selected, total));
        }
    }

    // Check if we have enough even without change output
    let fee = calculate_fee(selected.len(), num_outputs, fee_rate);
    if total >= target + fee {
        return Ok((selected, total));
    }

    Err(Error::InsufficientBitcoins {
        needed: target + fee,
        available: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::Amount;
    use bdk_wallet::bitcoin::blockdata::fee_rate::FeeRate;

    #[test]
    fn test_estimate_tx_vbytes() {
        let vbytes = estimate_tx_vbytes(1, 2);
        // 11 overhead + 58 input + 86 outputs = 155
        assert_eq!(vbytes, 155);

        let vbytes = estimate_tx_vbytes(2, 3);
        // 11 + 116 + 129 = 256
        assert_eq!(vbytes, 256);
    }

    #[test]
    fn test_calculate_fee() {
        let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();
        let fee = calculate_fee(1, 2, fee_rate);
        // 155 vbytes * 2 sat/vb = 310
        assert_eq!(fee, 310);
    }

    #[test]
    fn test_build_psbt_basic() {
        use bdk_wallet::bitcoin::hashes::Hash;

        let txid_bytes = [1u8; 32];
        let txid = bdk_wallet::bitcoin::Txid::from_byte_array(txid_bytes);
        let outpoint = OutPoint::new(txid, 0);
        let input_txout = TxOut {
            value: Amount::from_sat(10000),
            script_pubkey: ScriptBuf::new(),
        };
        let output = TxOut {
            value: Amount::from_sat(9000),
            script_pubkey: ScriptBuf::new(),
        };

        let psbt = build_psbt(vec![(outpoint, input_txout.clone())], vec![output]).unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 1);
        assert_eq!(psbt.unsigned_tx.output.len(), 1);
        assert_eq!(psbt.unsigned_tx.output[0].value.to_sat(), 9000);
        // Verify witness_utxo is populated
        assert_eq!(psbt.inputs[0].witness_utxo, Some(input_txout));
    }

    #[test]
    fn test_select_coins_sufficient() {
        use bdk_wallet::bitcoin::hashes::Hash;

        let txid1 = bdk_wallet::bitcoin::Txid::from_byte_array([1u8; 32]);
        let txid2 = bdk_wallet::bitcoin::Txid::from_byte_array([2u8; 32]);

        let utxos = vec![
            (
                OutPoint::new(txid1, 0),
                TxOut {
                    value: Amount::from_sat(5000),
                    script_pubkey: ScriptBuf::new(),
                },
            ),
            (
                OutPoint::new(txid2, 0),
                TxOut {
                    value: Amount::from_sat(10000),
                    script_pubkey: ScriptBuf::new(),
                },
            ),
        ];
        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
        let (selected, total) = select_coins(&utxos, 8000, fee_rate, 1).unwrap();
        assert_eq!(selected.len(), 1); // largest (10000) should be enough
        assert_eq!(total, 10000);
    }

    #[test]
    fn test_select_coins_needs_multiple() {
        use bdk_wallet::bitcoin::hashes::Hash;

        let txid1 = bdk_wallet::bitcoin::Txid::from_byte_array([1u8; 32]);
        let txid2 = bdk_wallet::bitcoin::Txid::from_byte_array([2u8; 32]);

        let utxos = vec![
            (
                OutPoint::new(txid1, 0),
                TxOut {
                    value: Amount::from_sat(5000),
                    script_pubkey: ScriptBuf::new(),
                },
            ),
            (
                OutPoint::new(txid2, 0),
                TxOut {
                    value: Amount::from_sat(6000),
                    script_pubkey: ScriptBuf::new(),
                },
            ),
        ];
        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
        let (selected, total) = select_coins(&utxos, 10000, fee_rate, 1).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(total, 11000);
    }

    #[test]
    fn test_select_coins_insufficient() {
        use bdk_wallet::bitcoin::hashes::Hash;

        let txid1 = bdk_wallet::bitcoin::Txid::from_byte_array([1u8; 32]);

        let utxos = vec![(
            OutPoint::new(txid1, 0),
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::new(),
            },
        )];
        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
        let result = select_coins(&utxos, 10000, fee_rate, 1);
        assert!(result.is_err());
    }
}
