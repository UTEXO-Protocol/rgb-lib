//! Offline regressions; every wallet and operation lives in a temporary directory.
use super::*;
use crate::mpc::MpcAddressInfo;
use bdk_wallet::bitcoin::{
    CompressedPublicKey, Txid,
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
        let key = CompressedPublicKey(
            SecretKey::from_slice(&[seed; 32])
                .unwrap()
                .public_key(&Secp256k1::new()),
        );
        let address = BdkAddress::p2wpkh(&key, BdkNetwork::from(network));
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
    let dir = tempfile::tempdir().unwrap();
    let broken = Arc::new(AtomicBool::new(false));
    let wallet = MpcWallet::new(
        WalletData {
            data_dir: dir.path().to_string_lossy().into(),
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: 5,
            supported_schemas: vec![AssetSchema::Nia],
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
fn signing_uses_the_callers_single_connection_transaction() {
    let (_dir, wallet, _) = wallet();
    let txn = wallet.database().begin_transaction().unwrap();
    let address = wallet
        .register_address(&txn, KeychainKind::External)
        .unwrap();
    let psbt = mpc_psbt::build_psbt(vec![output(2, &address.script_pubkey())], vec![]).unwrap();
    wallet.mpc_sign_psbt(&txn, psbt).unwrap();
    txn.commit().unwrap();
}

#[test]
fn own_change_does_not_consume_a_reused_witness_receive() {
    let (_dir, mut wallet, _) = wallet();
    wallet
        .witness_receive(
            None,
            Assignment::Fungible(25),
            (now().unix_timestamp() + 3600) as u64,
            vec!["rpc://127.0.0.1:31010/json-rpc".into()],
            1,
        )
        .unwrap();
    let txn = wallet.database().begin_transaction().unwrap();
    let script = wallet
        .register_address(&txn, KeychainKind::External)
        .unwrap()
        .script_pubkey();
    let change = output(2, &script);
    txn.set_txo(txo(change.0, false)).unwrap();
    wallet
        .record_indexed_outputs(&txn, &script, vec![change.clone()])
        .unwrap();
    let saved_change = txn.get_txo(&change.0.into()).unwrap().unwrap();
    assert!(saved_change.exists);
    assert!(!saved_change.pending_witness);
    assert_eq!(txn.iter_pending_witness_scripts().unwrap().len(), 1);
    let incoming = output(3, &script);
    wallet
        .record_indexed_outputs(&txn, &script, vec![incoming.clone()])
        .unwrap();
    assert!(
        txn.get_txo(&incoming.0.into())
            .unwrap()
            .unwrap()
            .pending_witness
    );
    // A second indexed output cannot steal the remaining invoice either.
    let other = output(4, &script);
    wallet
        .record_indexed_outputs(&txn, &script, vec![other.clone()])
        .unwrap();
    assert!(
        txn.get_txo(&other.0.into())
            .unwrap()
            .unwrap()
            .pending_witness
    );
    txn.commit().unwrap();
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
        .register_address(&txn, KeychainKind::Internal)
        .unwrap()
        .script_pubkey();
    let fee = output(5, &script);
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
    let data = wallet.wallet_data().clone();
    drop(wallet);
    let wallet = MpcWallet::new(
        data,
        "offline-mpc-regression".into(),
        Box::new(Provider { broken }),
    )
    .unwrap();
    let txn = wallet.database().begin_transaction().unwrap();
    assert!(
        wallet
            .get_reserved_vanilla_outpoints(&txn)
            .unwrap()
            .contains(&fee.0)
    );
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
fn rotation_validates_metadata_without_consuming_the_index() {
    let (_dir, mut wallet, broken) = wallet();
    let first = wallet.get_address().unwrap();
    broken.store(true, Ordering::SeqCst);
    assert!(matches!(
        wallet.rotate_address(KeychainKind::Internal),
        Err(Error::MpcProvider { .. })
    ));
    assert_eq!(wallet.get_address().unwrap(), first);
    broken.store(false, Ordering::SeqCst);
    assert_ne!(
        wallet.rotate_address(KeychainKind::Internal).unwrap(),
        first
    );
    assert!(matches!(
        wallet.blind_receive(None, Assignment::Any, u64::MAX, vec![], 1),
        Err(Error::InvalidExpiration)
    ));
}
