//! Isolated regressions; wallets use temporary directories and synthetic UTXOs.
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

#[cfg(feature = "electrum")]
mod create_utxos {
    use super::*;
    use bdk_electrum::electrum_client::ConfigBuilder;
    use serde_json::json;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread,
    };

    // Accounting fixture only: broadcasts are accepted without signature checks,
    // and listunspent deliberately lags behind them. No real chain is contacted.
    fn connect(wallet: &mut MpcWallet, coins: Vec<(OutPoint, TxOut)>) -> Arc<AtomicBool> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let reject = Arc::new(AtomicBool::new(false));
        let server_reject = reject.clone();
        thread::spawn(move || {
            // The indexer and RGB resolver each open a connection.
            let mut handlers = vec![];
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let coins = coins.clone();
                let reject = server_reject.clone();
                handlers.push(thread::spawn(move || {
                    let reader = BufReader::new(stream.try_clone().unwrap());
                    for line in reader.lines() {
                        let req: serde_json::Value =
                            serde_json::from_str(&line.unwrap()).unwrap();
                        let result = match req["method"].as_str().unwrap() {
                            "server.version" => json!(["fixture-electrum", "1.4"]),
                            "blockchain.scripthash.listunspent" => json!(
                                coins.iter().filter_map(|(op, output)| {
                                    let mut hash = bdk_wallet::bitcoin::hashes::sha256::Hash::hash(
                                        output.script_pubkey.as_bytes(),
                                    ).to_byte_array();
                                    hash.reverse();
                                    (req["params"][0] == hex::encode(hash)).then(|| json!({
                                        "tx_hash": op.txid.to_string(), "tx_pos": op.vout,
                                        "height": 1, "value": output.value.to_sat(),
                                    }))
                                }).collect::<Vec<_>>()
                            ),
                            "blockchain.transaction.broadcast" if !reject.load(Ordering::SeqCst) => {
                                let tx: BdkTransaction = bdk_wallet::bitcoin::consensus::deserialize(
                                    &hex::decode(req["params"][0].as_str().unwrap()).unwrap(),
                                ).unwrap();
                                json!(tx.compute_txid().to_string())
                            }
                            "blockchain.transaction.broadcast" | "blockchain.transaction.get" => {
                                writeln!(stream, "{}", json!({
                                    "jsonrpc": "2.0", "id": req["id"],
                                    "error": {"code": -1, "message": "No such mempool or blockchain transaction"},
                                })).unwrap();
                                continue;
                            }
                            other => panic!("unexpected Electrum method: {other}"),
                        };
                        writeln!(stream, "{}", json!({
                            "jsonrpc": "2.0", "id": req["id"], "result": result,
                        })).unwrap();
                    }
                }));
            }
            for handler in handlers {
                handler.join().unwrap();
            }
        });
        let opts = ConfigBuilder::new()
            .retry(0)
            .timeout(Some(std::time::Duration::from_secs(2)))
            .build();
        *wallet.online_data_mut() = Some(OnlineData {
            id: 1,
            indexer: Indexer::Electrum(Box::new(BdkElectrumClient::new(
                ElectrumClient::from_config(&url, opts.clone()).unwrap(),
            ))),
            resolver: AnyResolver::electrum_blocking(&url, Some(opts)).unwrap(),
            indexer_url: url,
            eth_rpc_url: None,
            hub_client: None,
            user_role: None,
            cosigner_xpub: None,
            vanilla_sync_lookback: 0,
        });
        reject
    }

    fn funding(wallet: &MpcWallet) -> (OutPoint, TxOut) {
        let txn = wallet.database().begin_transaction().unwrap();
        let script = wallet
            .register_address(&txn, KeychainKind::Internal)
            .unwrap()
            .script_pubkey();
        txn.commit().unwrap();
        let (op, mut output) = output(30, &script);
        output.value = BdkAmount::from_sat(100_000);
        (op, output)
    }

    fn prepare(wallet: &mut MpcWallet, dry_run: bool) -> Result<String, Error> {
        wallet.create_utxos_begin(Online { id: 1 }, false, None, None, 1, false, dry_run)
    }

    #[test]
    fn preparation_filters_inputs_and_preserves_reservations_across_restart() {
        let (_dir, mut wallet, broken) = wallet();
        let free = funding(&wallet);
        let (rgb_op, mut rgb_output) = output(31, &free.1.script_pubkey);
        rgb_output.value = BdkAmount::from_sat(200_000);
        let (reserved_op, mut reserved_output) = output(32, &free.1.script_pubkey);
        reserved_output.value = BdkAmount::from_sat(300_000);
        let txn = wallet.database().begin_transaction().unwrap();
        txn.set_txo(txo(rgb_op, false)).unwrap();
        let reserved =
            mpc_psbt::build_psbt(vec![(reserved_op, reserved_output.clone())], vec![]).unwrap();
        wallet
            .reserve_vanilla_txos(&txn, &reserved, WalletTransactionType::SendBtc)
            .unwrap();
        txn.commit().unwrap();
        let coins = vec![
            free.clone(),
            (rgb_op, rgb_output),
            (reserved_op, reserved_output),
        ];
        connect(&mut wallet, coins.clone());

        // Known RGB change remains protected even before synchronization marks it as existing.
        let dry = Psbt::from_str(
            &wallet
                .create_utxos_begin(Online { id: 1 }, false, None, None, 1, true, true)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(dry.unsigned_tx.input.len(), 1);
        assert_eq!(dry.unsigned_tx.input[0].previous_output, free.0);
        assert_eq!(wallet.list_pending_vanilla_txs().unwrap().len(), 1);
        let prepared = prepare(&mut wallet, false).unwrap();
        assert_eq!(prepared, dry.to_string());
        let txid = dry.unsigned_tx.compute_txid().to_string();
        assert!(matches!(
            prepare(&mut wallet, false),
            Err(Error::InsufficientBitcoins { .. })
        ));

        let data = wallet.wallet_data().clone();
        drop(wallet);
        let mut wallet = MpcWallet::new(
            data,
            "offline-mpc-regression".into(),
            Box::new(Provider { broken }),
        )
        .unwrap();
        connect(&mut wallet, coins);
        let pending = wallet.list_pending_vanilla_txs().unwrap();
        assert_eq!(pending.len(), 2);
        assert!(
            pending
                .iter()
                .any(|p| p.txid == txid && p.r#type == WalletTransactionType::CreateUtxos)
        );
        assert!(matches!(
            prepare(&mut wallet, false),
            Err(Error::InsufficientBitcoins { .. })
        ));
        wallet.abort_pending_vanilla_tx(txid.clone()).unwrap();
        assert_eq!(wallet.list_pending_vanilla_txs().unwrap().len(), 1);
        assert!(matches!(
            wallet.abort_pending_vanilla_tx(txid),
            Err(Error::CannotAbortPendingVanillaTx)
        ));
        assert_eq!(prepare(&mut wallet, false).unwrap(), prepared);
    }

    #[test]
    fn completion_records_external_pool_for_blind_receive_and_is_retryable() {
        let (_dir, mut wallet, _) = wallet();
        let free = funding(&wallet);
        let internal_script = free.1.script_pubkey.clone();
        let reject = connect(&mut wallet, vec![free]);
        let prepared = prepare(&mut wallet, false).unwrap();
        let psbt = Psbt::from_str(&prepared).unwrap();
        // Dev defaults: five 1000-sat External UTXOs and one Internal change output.
        assert_eq!(psbt.unsigned_tx.output.len(), 6);
        for output in &psbt.unsigned_tx.output[..5] {
            assert_eq!(output.value.to_sat(), 1_000);
            assert_ne!(output.script_pubkey, internal_script);
            assert_eq!(
                output.script_pubkey,
                psbt.unsigned_tx.output[0].script_pubkey
            );
        }
        assert_eq!(psbt.unsigned_tx.output[5].script_pubkey, internal_script);
        let txid = psbt.unsigned_tx.compute_txid().to_string();
        reject.store(true, Ordering::SeqCst);
        assert!(
            wallet
                .create_utxos_end(Online { id: 1 }, prepared.clone())
                .is_err()
        );
        assert_eq!(wallet.list_pending_vanilla_txs().unwrap().len(), 1);
        let txn = wallet.database().begin_transaction().unwrap();
        assert!(txn.iter_txos().unwrap().is_empty());
        txn.commit().unwrap();
        reject.store(false, Ordering::SeqCst);
        assert_eq!(
            wallet
                .create_utxos_end(Online { id: 1 }, prepared.clone())
                .unwrap(),
            5
        );
        assert!(wallet.list_pending_vanilla_txs().unwrap().is_empty());
        assert!(matches!(
            wallet.abort_pending_vanilla_tx(txid.clone()),
            Err(Error::CannotAbortPendingVanillaTx)
        ));
        let txn = wallet.database().begin_transaction().unwrap();
        let outputs = txn.iter_txos().unwrap();
        assert_eq!(outputs.len(), 5);
        assert!(
            outputs
                .iter()
                .all(|o| o.txid == txid && o.vout < 5 && o.exists && !o.spent)
        );
        txn.commit().unwrap();

        wallet
            .blind_receive(
                None,
                Assignment::Fungible(25),
                now().unix_timestamp() as u64 + 3600,
                vec!["rpc://127.0.0.1:3000/json-rpc".into()],
                1,
            )
            .unwrap();
        // A delayed completion retry must neither duplicate outputs nor resurrect spent ones.
        let txn = wallet.database().begin_transaction().unwrap();
        let mut spent: DbTxoActMod = outputs[0].clone().into();
        spent.spent = ActiveValue::Set(true);
        txn.update_txo(spent).unwrap();
        txn.commit().unwrap();
        assert_eq!(
            wallet.create_utxos_end(Online { id: 1 }, prepared).unwrap(),
            5
        );
        let txn = wallet.database().begin_transaction().unwrap();
        let outputs = txn.iter_txos().unwrap();
        assert_eq!(outputs.len(), 5);
        assert_eq!(outputs.iter().filter(|o| o.spent).count(), 1);
        txn.commit().unwrap();
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
