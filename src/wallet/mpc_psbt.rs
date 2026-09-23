//! Manual PSBT construction utilities for MPC mode.
//!
//! Since MPC wallets don't have a BDK wallet instance, we build PSBTs manually
//! using the `bitcoin` crate primitives.

use amplify::s;
use bdk_wallet::bitcoin::{
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, locktime::absolute::LockTime,
    psbt::Psbt, transaction::Version,
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
) -> Result<u64, Error> {
    let vbytes = estimate_tx_vbytes(num_inputs, num_outputs);
    fee_rate
        .to_sat_per_vb_ceil()
        .checked_mul(vbytes)
        .ok_or_else(|| Error::InvalidFeeRate {
            details: s!("fee amount overflows u64"),
        })
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

    // A P2TR script contains the tweaked OUTPUT key, never the internal key.
    // The registry adds authenticated internal-key metadata before external signing.
    for (i, (_, txout)) in inputs.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(txout.clone());
    }

    Ok(psbt)
}

/// Fee for the final Taproot transaction shape, including the RGB commitment.
pub fn actual_fee(
    inputs: &[(OutPoint, TxOut)],
    outputs: &[TxOut],
    rate: bdk_wallet::bitcoin::FeeRate,
) -> Result<u64, Error> {
    let mut tx = build_psbt(inputs.to_vec(), outputs.to_vec())?.unsigned_tx;
    for (input, (_, prevout)) in tx.input.iter_mut().zip(inputs) {
        if !prevout.script_pubkey.is_p2tr() {
            return Err(Error::InvalidPsbt {
                details: s!("MPC split change requires Taproot inputs"),
            });
        }
        input.witness.push([0u8; 65]); // DEFAULT or ALL signature, conservatively sized
    }
    for output in &mut tx.output {
        if output.script_pubkey.is_op_return() {
            output.script_pubkey = ScriptBuf::new_op_return([0; 32]);
        }
    }
    rate.to_sat_per_vb_ceil()
        .checked_mul(tx.vsize() as u64)
        .ok_or_else(|| Error::InvalidFeeRate {
            details: s!("fee overflow"),
        })
}

/// Select fees and construct role-separated change before RGB commitments exist.
pub fn split_change(
    mut selected: Vec<(OutPoint, TxOut)>,
    mut available: Vec<(OutPoint, TxOut)>,
    mut outputs: Vec<TxOut>,
    colored: ScriptBuf,
    vanilla: ScriptBuf,
    carrier: Option<u64>,
    rate: bdk_wallet::bitcoin::FeeRate,
) -> Result<(Psbt, Option<super::BtcChange>), Error> {
    if colored == vanilla || !colored.is_p2tr() || !vanilla.is_p2tr() {
        return Err(Error::InvalidPsbt {
            details: s!("Distinct Taproot role scripts required"),
        });
    }
    let rgb_change = if let Some(amount) = carrier {
        if amount < colored.minimal_non_dust().to_sat() || amount > 100_000 {
            return Err(Error::InvalidPsbt {
                details: s!("RGB carrier outside policy"),
            });
        }
        let change = super::BtcChange {
            vout: outputs.len() as u32,
            amount,
        };
        outputs.push(TxOut {
            value: bdk_wallet::bitcoin::Amount::from_sat(amount),
            script_pubkey: colored,
        });
        Some(change)
    } else {
        None
    };
    let target = outputs
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()))
        .ok_or_else(|| Error::InvalidPsbt {
            details: s!("Output amount overflow"),
        })?;
    let mut seen = std::collections::HashSet::new();
    if selected.iter().any(|(op, _)| !seen.insert(*op)) {
        return Err(Error::InvalidPsbt {
            details: s!("Duplicate required input"),
        });
    }
    available.retain(|(op, _)| seen.insert(*op));
    available.sort_by_key(|(_, output)| output.value);
    loop {
        let total = selected
            .iter()
            .try_fold(0u64, |sum, (_, output)| {
                sum.checked_add(output.value.to_sat())
            })
            .ok_or_else(|| Error::InvalidPsbt {
                details: s!("Input amount overflow"),
            })?;
        let mut with_vanilla = outputs.clone();
        with_vanilla.push(TxOut {
            value: bdk_wallet::bitcoin::Amount::ZERO,
            script_pubkey: vanilla.clone(),
        });
        let fee = actual_fee(&selected, &with_vanilla, rate)?;
        if let Some(change) = total
            .checked_sub(target)
            .and_then(|value| value.checked_sub(fee))
            && change >= vanilla.minimal_non_dust().to_sat()
        {
            with_vanilla.last_mut().unwrap().value = bdk_wallet::bitcoin::Amount::from_sat(change);
            return Ok((build_psbt(selected, with_vanilla)?, rgb_change));
        }
        let minimum_fee = actual_fee(&selected, &outputs, rate)?;
        let needed = target
            .checked_add(minimum_fee)
            .ok_or_else(|| Error::InvalidFeeRate {
                details: s!("Fee overflow"),
            })?;
        if total >= needed && !selected.is_empty() {
            // Sub-dust remainder is fee. The API enforces the saved maximum fee.
            return Ok((build_psbt(selected, outputs)?, rgb_change));
        }
        match available.pop() {
            Some(input) => selected.push(input),
            None => {
                return Err(Error::InsufficientBitcoins {
                    needed,
                    available: total,
                });
            }
        }
    }
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
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1.value));

    let mut selected = Vec::new();
    let mut total: u64 = 0;

    for utxo in sorted {
        selected.push(utxo.clone());
        total += utxo.1.value.to_sat();
        let fee = calculate_fee(selected.len(), num_outputs + 1, fee_rate)?; // +1 for change
        if target
            .checked_add(fee)
            .is_some_and(|needed| total >= needed)
        {
            return Ok((selected, total));
        }
    }

    // Check if we have enough even without change output
    let fee = calculate_fee(selected.len(), num_outputs, fee_rate)?;
    if target
        .checked_add(fee)
        .is_some_and(|needed| total >= needed)
    {
        return Ok((selected, total));
    }

    Err(Error::InsufficientBitcoins {
        needed: target.saturating_add(fee),
        available: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::Amount;
    use bdk_wallet::bitcoin::blockdata::fee_rate::FeeRate;

    fn role_script(seed: u8) -> ScriptBuf {
        use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
        let key = SecretKey::from_slice(&[seed; 32])
            .unwrap()
            .public_key(&Secp256k1::new())
            .x_only_public_key()
            .0;
        ScriptBuf::new_p2tr(&Secp256k1::new(), key, None)
    }
    #[test]
    fn split_change_keeps_rgb_carrier_and_returns_excess_to_vanilla() {
        use bdk_wallet::bitcoin::{Txid, hashes::Hash};
        let colored = role_script(1);
        let vanilla = role_script(2);
        let input = |seed, amount, script| {
            (
                OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
                TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: script,
                },
            )
        };
        let (psbt, change) = split_change(
            vec![input(1, 1000, colored.clone())],
            vec![input(2, 100_000, vanilla.clone())],
            vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
            colored.clone(),
            vanilla.clone(),
            Some(1000),
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .unwrap();
        assert_eq!(psbt.unsigned_tx.input.len(), 2);
        assert_eq!(psbt.unsigned_tx.output.len(), 3);
        assert_eq!(change.unwrap().vout, 1);
        assert_eq!(psbt.unsigned_tx.output[1].script_pubkey, colored);
        assert_eq!(psbt.unsigned_tx.output[1].value.to_sat(), 1000);
        assert_eq!(psbt.unsigned_tx.output[2].script_pubkey, vanilla);
        assert!(psbt.unsigned_tx.output[2].value.to_sat() > 99_000);
        assert!(
            psbt.inputs
                .iter()
                .all(|input| input.tap_internal_key.is_none())
        );
        let (psbt, change) = split_change(
            vec![input(1, 1000, colored.clone())],
            vec![],
            vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            }],
            colored,
            vanilla.clone(),
            None,
            FeeRate::from_sat_per_vb(1).unwrap(),
        )
        .unwrap();
        assert!(change.is_none());
        assert_eq!(psbt.unsigned_tx.output.len(), 2);
        assert_eq!(psbt.unsigned_tx.output[1].script_pubkey, vanilla);
    }
    #[test]
    fn split_change_rejects_dust_carrier_and_reports_shortage() {
        let outputs = vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([]),
        }];
        assert!(matches!(
            split_change(
                vec![],
                vec![],
                outputs.clone(),
                role_script(1),
                role_script(2),
                Some(329),
                FeeRate::from_sat_per_vb(1).unwrap()
            ),
            Err(Error::InvalidPsbt { .. })
        ));
        assert!(matches!(
            split_change(
                vec![],
                vec![],
                outputs,
                role_script(1),
                role_script(2),
                Some(1000),
                FeeRate::from_sat_per_vb(1).unwrap()
            ),
            Err(Error::InsufficientBitcoins { .. })
        ));
    }

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
        let fee = calculate_fee(1, 2, fee_rate).unwrap();
        // 155 vbytes * 2 sat/vb = 310
        assert_eq!(fee, 310);
    }

    #[test]
    fn test_calculate_fee_overflow() {
        let fee_rate = FeeRate::from_sat_per_vb(1_000_000_000_000_000).unwrap();
        let result = calculate_fee(1000, 2, fee_rate);
        assert!(matches!(result, Err(Error::InvalidFeeRate { .. })));
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

    #[test]
    fn test_select_coins_target_overflow() {
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
        let result = select_coins(&utxos, u64::MAX, fee_rate, 1);
        assert!(matches!(
            result,
            Err(Error::InsufficientBitcoins {
                needed: u64::MAX,
                available: 100
            })
        ));
    }
}
