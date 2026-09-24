//! Offline regressions; every wallet and operation lives in a temporary directory.
use super::*;
use crate::mpc::MpcAddressInfo;
use bdk_wallet::bitcoin::{
    Txid,
    hashes::Hash,
    secp256k1::{Secp256k1, SecretKey},
};
use std::sync::atomic::{AtomicBool, Ordering};

struct Provider {
    broken: Arc<AtomicBool>,
}
impl MpcWalletProvider for Provider {
    fn create_address(
        &self,
        network: BitcoinNetwork,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<MpcAddressInfo, Error> {
        let seed = 1
            + index as u8
            + if keychain == KeychainKind::Internal {
                50
            } else {
                0
            };
        let key = SecretKey::from_slice(&[seed; 32])
            .unwrap()
            .public_key(&Secp256k1::new())
            .x_only_public_key()
            .0;
        let address = BdkAddress::p2tr(&Secp256k1::new(), key, None, BdkNetwork::from(network));
        Ok(MpcAddressInfo {
            script_pubkey: if self.broken.load(Ordering::SeqCst) {
                ScriptBuf::new()
            } else {
                address.script_pubkey()
            },
            address: address.to_string(),
            signing_key_id: format!("fixture-{seed}"),
            derivation_index: index,
        })
    }
    fn sign_psbt(&self, psbt: Psbt, keys: Vec<String>) -> Result<Psbt, Error> {
        assert_eq!(keys, ["fixture-1"]);
        Ok(psbt)
    }
}

fn wallet() -> (tempfile::TempDir, MpcWallet, Arc<AtomicBool>) {
    wallet_with_schemas(vec![AssetSchema::Nia])
}

fn wallet_with_schemas(
    schemas: Vec<AssetSchema>,
) -> (tempfile::TempDir, MpcWallet, Arc<AtomicBool>) {
    let dir = tempfile::tempdir().unwrap();
    let broken = Arc::new(AtomicBool::new(false));
    let wallet = MpcWallet::new(
        WalletData {
            data_dir: dir.path().to_string_lossy().into(),
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: 5,
            supported_schemas: schemas,
            reuse_addresses: true,
        },
        "offline-mpc-regression".into(),
        Box::new(Provider {
            broken: broken.clone(),
        }),
    )
    .unwrap();
    (dir, wallet, broken)
}

fn output(seed: u8, script: &ScriptBuf) -> (OutPoint, TxOut) {
    (
        OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
        TxOut {
            value: BdkAmount::from_sat(5_000),
            script_pubkey: script.clone(),
        },
    )
}
fn txo(outpoint: OutPoint, exists: bool) -> DbTxoActMod {
    DbTxoActMod {
        txid: ActiveValue::Set(outpoint.txid.to_string()),
        vout: ActiveValue::Set(outpoint.vout),
        btc_amount: ActiveValue::Set("5000".into()),
        exists: ActiveValue::Set(exists),
        spent: ActiveValue::Set(false),
        pending_witness: ActiveValue::Set(false),
        ..Default::default()
    }
}

#[test]
fn empty_balance_does_not_open_a_nested_transaction() {
    let (_dir, mut wallet, _) = wallet();
    let balance = wallet.get_btc_balance(None, true).unwrap();
    assert_eq!(balance.colored.spendable, 0);
    assert_eq!(balance.vanilla.spendable, 0);
}

#[test]
fn legacy_rgb_and_reserved_vanilla_inputs_are_excluded() {
    let (_dir, wallet, _) = wallet();
    let txn = wallet.database().begin_transaction().unwrap();
    let script = wallet
        .register_address(&txn, KeychainKind::Internal)
        .unwrap()
        .script_pubkey();
    let legacy = output(2, &script);
    let reserved = output(3, &script);
    let free = output(4, &script);
    txn.set_txo(txo(legacy.0, false)).unwrap();
    let psbt = mpc_psbt::build_psbt(vec![reserved.clone()], vec![]).unwrap();
    wallet
        .reserve_vanilla_txos(&txn, &psbt, WalletTransactionType::SendBtc)
        .unwrap();
    let candidates = vec![legacy, reserved, free.clone()]
        .into_iter()
        .map(|(op, txout)| (op, txout, "key".into()))
        .collect();
    let selected = wallet
        .filter_spendable_vanilla_utxos(&txn, candidates)
        .unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].0, free.0);
    txn.commit().unwrap();
}

#[test]
fn pending_rgb_psbt_reserves_empty_fee_inputs_across_restart() {
    let (dir, wallet, broken) = wallet();
    let txn = wallet.database().begin_transaction().unwrap();
    let script = wallet
        .register_address(&txn, KeychainKind::External)
        .unwrap()
        .script_pubkey();
    let fee = output(5, &script);
    let persisted_fee = output(6, &script);
    let free = output(7, &script);
    for input in [&fee, &persisted_fee, &free] {
        txn.set_txo(txo(input.0, true)).unwrap();
    }
    // New bridge preparations persist reservations in the database. Older MPC
    // preparations below reserve inputs through their saved PSBT instead.
    let persisted_psbt = mpc_psbt::build_psbt(vec![persisted_fee.clone()], vec![]).unwrap();
    wallet
        .reserve_vanilla_txos(&txn, &persisted_psbt, WalletTransactionType::RgbTransfer)
        .unwrap();
    let psbt = mpc_psbt::build_psbt(vec![fee.clone()], vec![]).unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfer_dir = wallet.get_transfer_dir(&txid);
    fs::create_dir_all(&transfer_dir).unwrap();
    fs::write(transfer_dir.join(UNSIGNED_PSBT_FILE), psbt.to_string()).unwrap();
    let idx = txn
        .set_batch_transfer(DbBatchTransferActMod {
            txid: ActiveValue::Set(Some(txid)),
            status: ActiveValue::Set(TransferStatus::Initiated),
            created_at: ActiveValue::Set(1),
            updated_at: ActiveValue::Set(1),
            incoming: ActiveValue::Set(false),
            min_confirmations: ActiveValue::Set(1),
            expiration: ActiveValue::Set(None),
            ..Default::default()
        })
        .unwrap();
    txn.commit().unwrap();
    let txn = wallet.database().begin_transaction().unwrap();
    wallet.get_reserved_vanilla_outpoints(&txn).unwrap();
    txn.commit().unwrap();
    fs::remove_file(transfer_dir.join(UNSIGNED_PSBT_FILE)).unwrap();
    let data = wallet.wallet_data().clone();
    drop(wallet);
    let mut wallet = MpcWallet::new(
        data,
        "offline-mpc-regression".into(),
        Box::new(Provider { broken }),
    )
    .unwrap();
    let txn = wallet.database().begin_transaction().unwrap();
    let reserved = wallet.get_reserved_vanilla_outpoints(&txn).unwrap();
    assert!(reserved.contains(&fee.0));
    assert!(reserved.contains(&persisted_fee.0));
    let (_, _, selected, _) = wallet.get_transfer_begin_data(&txn, 1).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(BdkOutPoint::from(selected[0].utxo.clone()), free.0);

    wallet
        .release_reserved_txos(&txn, &persisted_psbt.unsigned_tx.compute_txid().to_string())
        .unwrap();
    let reserved = wallet.get_reserved_vanilla_outpoints(&txn).unwrap();
    assert!(reserved.contains(&fee.0));
    assert!(!reserved.contains(&persisted_fee.0));
    let mut batch: DbBatchTransferActMod = txn
        .iter_batch_transfers()
        .unwrap()
        .into_iter()
        .find(|b| b.idx == idx)
        .unwrap()
        .into();
    batch.status = ActiveValue::Set(TransferStatus::Failed);
    txn.update_batch_transfer(&mut batch).unwrap();
    assert!(
        !wallet
            .get_reserved_vanilla_outpoints(&txn)
            .unwrap()
            .contains(&fee.0)
    );
    txn.commit().unwrap();
    drop(wallet);
    drop(dir);
}

#[test]
fn incomplete_legacy_reservations_block_spends_until_matching_psbt_is_restored() {
    let (_dir, wallet, _) = wallet();
    let txn = wallet.database().begin_transaction().unwrap();
    let script = wallet
        .register_address(&txn, KeychainKind::External)
        .unwrap()
        .script_pubkey();
    let input = output(19, &script);
    let psbt = mpc_psbt::build_psbt(vec![input.clone()], vec![]).unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    txn.set_batch_transfer(DbBatchTransferActMod {
        txid: ActiveValue::Set(Some(txid.clone())),
        status: ActiveValue::Set(TransferStatus::Initiated),
        created_at: ActiveValue::Set(1),
        updated_at: ActiveValue::Set(1),
        incoming: ActiveValue::Set(false),
        min_confirmations: ActiveValue::Set(1),
        expiration: ActiveValue::Set(None),
        ..Default::default()
    })
    .unwrap();
    assert!(wallet.get_reserved_vanilla_outpoints(&txn).is_err());
    assert!(txn.mpc_prepared_inputs(&txid).unwrap().is_none());
    let path = wallet.get_transfer_dir(&txid);
    fs::create_dir_all(&path).unwrap();
    let different = mpc_psbt::build_psbt(vec![output(20, &script)], vec![]).unwrap();
    fs::write(path.join(UNSIGNED_PSBT_FILE), different.to_string()).unwrap();
    assert!(wallet.get_reserved_vanilla_outpoints(&txn).is_err());
    assert!(txn.mpc_prepared_inputs(&txid).unwrap().is_none());
    fs::write(path.join(UNSIGNED_PSBT_FILE), psbt.to_string()).unwrap();
    assert!(
        wallet
            .get_reserved_vanilla_outpoints(&txn)
            .unwrap()
            .contains(&input.0)
    );
    assert!(txn.mpc_prepared_inputs(&txid).unwrap().is_some());
    txn.commit().unwrap();
}
