use super::*;

use crate::wallet::test::utils::vss::{
    VssBackupDeleteGuard, generate_signing_key_and_store_id, tokio_runtime, vss_server_url,
};
use crate::wallet::vss::{VssBackupClient, VssBackupConfig, VssBackupMode, restore_from_vss};

// Enabling auto-backup on a wallet with unsaved state must upload an initial
// backup, without waiting for a later state-changing operation.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn configure_with_pending_state_uploads_initial_backup() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, _online_a) = get_funded_noutxo_wallet!();

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_initial_backup");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Blocking);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let check_client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");

    assert!(
        rt.block_on(check_client.get_backup_version())
            .expect("get_backup_version")
            .is_none(),
        "precondition: no backup before configure"
    );

    wallet_a
        .configure_vss_backup(config)
        .expect("configure_vss_backup");

    let version = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version");
    assert!(
        version.is_some(),
        "an initial backup must exist right after configuring auto-backup"
    );
    assert!(
        wallet_a
            .vss_client()
            .expect("client configured")
            .last_auto_backup_error()
            .is_none(),
        "successful initial backup must leave no error recorded"
    );

    rt.block_on(check_client.delete_backup())
        .expect("delete_backup");
    cleanup.disarm();
}

// A failed auto-backup must be observable through the client and
// `vss_backup_info`, not only in the wallet log file.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn failed_auto_backup_is_exposed() {
    initialize();

    let (mut wallet_a, _online_a) = get_funded_noutxo_wallet!();

    // Unroutable server: the initial blocking upload fails, configure still
    // succeeds (auto-backup is best-effort).
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_backup_error");
    let config = VssBackupConfig::new("http://127.0.0.1:9/vss".to_string(), store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Blocking);
    wallet_a
        .configure_vss_backup(config)
        .expect("configure_vss_backup must not fail on unreachable server");

    let error = wallet_a
        .vss_client()
        .expect("client configured")
        .last_auto_backup_error();
    assert!(
        error.is_some(),
        "the failed upload must be recorded on the client"
    );
}

// A consistency-check failure right after a VSS restore must surface as the
// dedicated `RestoredBackupInconsistent` error; a successful check clears the
// restore marker so later failures report plain `Inconsistency` again.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn inconsistent_restored_backup_returns_dedicated_error() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();

    let _ = wallet_a
        .create_utxos(online_a, true, Some(3), Some(20_000), FEE_RATE, false)
        .expect("create_utxos");
    let _ = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![100])
        .expect("issue_asset_nia");

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_stale_restore");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    rt.block_on(wallet_a.vss_backup(&client)).expect("backup");

    // Restore, then break internal consistency (as a stale or torn backup
    // would): drop the RGB runtime data while the DB still lists the asset.
    let restore_tmp_broken = tempfile::tempdir().expect("tempdir");
    let restored_dir = rt
        .block_on(restore_from_vss(
            config.clone(),
            restore_tmp_broken.path().to_str().unwrap(),
        ))
        .expect("restore_from_vss");
    std::fs::remove_dir_all(restored_dir.join(crate::utils::RGB_RUNTIME_DIR))
        .expect("drop rgb runtime dir");

    let mut restored_data = wallet_a.get_wallet_data();
    restored_data.data_dir = restore_tmp_broken.path().to_string_lossy().to_string();
    let mut wallet_r =
        Wallet::new(restored_data.clone(), wallet_a.get_keys()).expect("Wallet::new restored");
    let mut online_opts = test_go_online_options(None);
    online_opts.skip_consistency_check = false;
    let err = wallet_r
        .go_online(online_opts.clone())
        .expect_err("consistency check must fail on the broken restore");
    assert!(
        matches!(err, Error::RestoredBackupInconsistent { .. }),
        "restore-attributed failure must use the dedicated variant, got: {err:?}"
    );

    // A healthy restore passes the check and clears the marker.
    let restore_tmp_ok = tempfile::tempdir().expect("tempdir");
    let restored_dir_ok = rt
        .block_on(restore_from_vss(
            config.clone(),
            restore_tmp_ok.path().to_str().unwrap(),
        ))
        .expect("restore_from_vss ok");
    assert!(
        restored_dir_ok
            .join(crate::wallet::vss::VSS_RESTORE_MARKER)
            .exists(),
        "marker must exist right after restore"
    );
    let mut restored_data_ok = wallet_a.get_wallet_data();
    restored_data_ok.data_dir = restore_tmp_ok.path().to_string_lossy().to_string();
    let mut wallet_ok =
        Wallet::new(restored_data_ok, wallet_a.get_keys()).expect("Wallet::new restored ok");
    let _online_r = wallet_ok
        .go_online(online_opts)
        .expect("go_online on healthy restore");
    assert!(
        !restored_dir_ok
            .join(crate::wallet::vss::VSS_RESTORE_MARKER)
            .exists(),
        "marker must be cleared after the first successful consistency check"
    );

    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
}

/// Color-consume Initiated accounting + `htlc_ops/` must round-trip through VSS backup/restore.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_consume_and_htlc_ops_survive_vss_restore() {
    initialize();

    let rt = tokio_runtime();
    let amt_sat = 500u64;
    let blinding = 777u64;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let recipient_script = address.assume_checked().script_pubkey();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(recipient_script, BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    // OP_RETURN first (P2TR / OpretFirst)
    let op_return = TxOut {
        value: BdkAmount::from_sat(0),
        script_pubkey: ScriptBuf::new_op_return([]),
    };
    psbt.unsigned_tx.output.insert(0, op_return);
    psbt.outputs.insert(0, Default::default());
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;

    let asset_coloring_info = AssetColoringInfo {
        output_map: HashMap::from([(vout, AMOUNT)]),
        static_blinding: Some(blinding),
    };
    let coloring_info = ColoringInfo {
        asset_info_map: HashMap::from([(
            ContractId::from_str(&asset.asset_id).unwrap(),
            asset_coloring_info,
        )]),
        static_blinding: Some(blinding),
        nonce: None,
    };

    let HtlcPrepareResult {
        operation_id,
        operation_dir,
        ..
    } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let transfers_before = party_send.list_transfers(Some(&asset.asset_id));
    let initiated = transfers_before
        .iter()
        .find(|t| t.status == TransferStatus::Initiated)
        .expect("initiated color-consume transfer");
    assert_eq!(initiated.kind, TransferKind::Send);
    let op_dir_before = party_send.wallet.get_wallet_dir().join(&operation_dir);
    assert!(op_dir_before.join("meta.json").exists());
    assert!(op_dir_before.join("fascia").exists());

    let (signing_key, store_id) =
        generate_signing_key_and_store_id("qa_htlc_color_consume_restore");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    rt.block_on(party_send.wallet.vss_backup(&client))
        .expect("vss_backup after htlc_prepare");

    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restored_dir = rt
        .block_on(restore_from_vss(
            config.clone(),
            restore_tmp.path().to_str().unwrap(),
        ))
        .expect("restore_from_vss");

    let mut restored_data = party_send.wallet.get_wallet_data();
    restored_data.data_dir = restore_tmp.path().to_string_lossy().to_string();
    let mut wallet_r =
        Wallet::new(restored_data, party_send.wallet.get_keys()).expect("Wallet::new restored");
    let _online = wallet_r
        .go_online(test_go_online_options(None))
        .expect("go_online restored");

    let transfers_after = wallet_r
        .list_transfers(AssetFilter::Id(asset.asset_id.clone()), None)
        .expect("list_transfers");
    let restored_xfer = transfers_after
        .iter()
        .find(|t| t.status == TransferStatus::Initiated)
        .expect("Initiated transfer must survive restore");
    assert_eq!(restored_xfer.kind, TransferKind::Send);
    assert_eq!(
        restored_xfer.requested_assignment,
        Some(Assignment::Fungible(AMOUNT))
    );

    let restored_op = restored_dir.join(&operation_dir);
    assert!(
        restored_op.join("meta.json").exists(),
        "htlc_ops meta must be in VSS backup"
    );
    assert!(
        restored_op.join("fascia").exists(),
        "htlc_ops fascia must be in VSS backup"
    );
    assert_eq!(
        wallet_r.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Prepared
    );

    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
}
