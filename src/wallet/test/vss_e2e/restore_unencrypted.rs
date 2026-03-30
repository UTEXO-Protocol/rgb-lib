use super::*;

use crate::wallet::test::utils::vss::{
    VSS_KEY_CHUNK_PREFIX, VSS_KEY_DATA, VSS_KEY_FINGERPRINT, VSS_KEY_MANIFEST, VSS_KEY_METADATA,
    VssBackupDeleteGuard, assert_vss_key_missing, build_raw_vss_client,
    generate_signing_key_and_store_id, get_vss_key, list_zip_names, snapshot_wallet_state,
    summarize_transfers, tokio_runtime, vss_server_url,
};

use crate::wallet::vss::{BackupManifest, VssBackupClient, VssBackupConfig, restore_from_vss};

// Block 2 / Scenario 2.1:
// Unencrypted backup is sanitized and excludes BDK DBs; restore + rehydrate bdk_db restores full state.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn scenario_2_1_unencrypted_backup_sanitized_restore_plus_bdk_db_rehydrate() {
    initialize();
    let rt = tokio_runtime();

    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();
    let (mut wallet_b, online_b) = get_empty_wallet!();

    // Ensure some RGB state.
    let _ = wallet_a
        .create_utxos(
            online_a.clone(),
            true,
            Some(5),
            Some(20_000),
            FEE_RATE,
            false,
        )
        .expect("create_utxos");
    let issued_supply = 100u64;
    let asset = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![issued_supply])
        .expect("issue_asset_nia");
    let asset_id = asset.asset_id.clone();

    let send_amount = 10u64;
    let receive = wallet_b
        .witness_receive(
            None,
            Assignment::Fungible(send_amount),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive");
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: receive.recipient_id,
            witness_data: Some(WitnessData {
                amount_sat: 2_000,
                blinding: None,
            }),
            assignment: Assignment::Fungible(send_amount),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let _ = wallet_a
        .send(
            online_a.clone(),
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            None,
            false,
        )
        .expect("send");
    mine_blocks(false, 2, false);
    let expected_settled = issued_supply - send_amount;
    let ok = wait_for_function(
        || {
            let _ = wallet_b.refresh(online_b.clone(), None, vec![], false);
            let _ = wallet_a.refresh(online_a.clone(), Some(asset_id.clone()), vec![], false);
            let bal = wallet_a.get_asset_balance(asset_id.clone()).unwrap();
            bal.settled == expected_settled
        },
        60,
        500,
    );
    assert!(ok, "timeout waiting for wallet state after send");

    // Snapshot before backup.
    let snapshot_pre =
        snapshot_wallet_state(&mut wallet_a, &online_a, &asset_id).expect("snapshot pre");

    // Save BDK DB bytes locally (unencrypted backup intentionally excludes them).
    let src_bdk_db = test_get_wallet_dir(&wallet_a).join("bdk_db");
    let src_bdk_db_watch_only = test_get_wallet_dir(&wallet_a).join("bdk_db_watch_only");
    assert!(src_bdk_db.exists(), "precondition: bdk_db must exist");
    let bdk_db_bytes = std::fs::read(&src_bdk_db).expect("read bdk_db");
    let bdk_db_watch_only_bytes = src_bdk_db_watch_only
        .exists()
        .then(|| std::fs::read(&src_bdk_db_watch_only).expect("read bdk_db_watch_only"));

    // Configure VSS (unencrypted).
    let vss_url = vss_server_url();
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_unencrypted");
    let config =
        VssBackupConfig::new(vss_url.clone(), store_id.clone(), signing_key).with_encryption(false);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let raw = build_raw_vss_client(&vss_url, signing_key);

    let version = rt
        .block_on(wallet_a.vss_backup(&client))
        .expect("vss_backup");
    let server_version = rt
        .block_on(client.get_backup_version())
        .expect("get_backup_version")
        .unwrap_or(0);
    assert_eq!(server_version, version, "version mismatch");

    // Verify server keys (unencrypted => no metadata).
    let manifest_bytes = rt
        .block_on(get_vss_key(&raw, &store_id, VSS_KEY_MANIFEST))
        .expect("manifest");
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes).expect("manifest json");
    assert!(!manifest.encrypted, "expected unencrypted backup");
    let _ = rt
        .block_on(get_vss_key(&raw, &store_id, VSS_KEY_FINGERPRINT))
        .expect("fingerprint");
    rt.block_on(assert_vss_key_missing(&raw, &store_id, VSS_KEY_METADATA))
        .expect("metadata must be missing");

    if manifest.chunk_count == 1 {
        let _ = rt
            .block_on(get_vss_key(&raw, &store_id, VSS_KEY_DATA))
            .expect("backup/data");
    } else {
        for i in 0..manifest.chunk_count {
            let key = format!("{VSS_KEY_CHUNK_PREFIX}{i}");
            let _ = rt.block_on(get_vss_key(&raw, &store_id, &key)).unwrap();
        }
    }

    // Download sanitized zip and verify expectations.
    let downloaded = rt
        .block_on(client.download_backup())
        .expect("download_backup");
    let names = list_zip_names(&downloaded).expect("list_zip_names");
    assert!(!names.is_empty(), "downloaded zip must not be empty");
    assert!(
        names.iter().all(|n| n.starts_with("wallet/")),
        "Expected zip paths to be sanitized under wallet/"
    );
    assert!(
        names
            .iter()
            .all(|n| n != "wallet/bdk_db" && !n.ends_with("/bdk_db")),
        "bdk_db must be excluded from unencrypted backup zip"
    );
    assert!(
        names
            .iter()
            .all(|n| n != "wallet/bdk_db_watch_only" && !n.ends_with("/bdk_db_watch_only")),
        "bdk_db_watch_only must be excluded from unencrypted backup zip"
    );

    // Restore into a clean directory.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let restored_wallet_dir = rt
        .block_on(restore_from_vss(config.clone(), restore_root))
        .expect("restore_from_vss");

    // Restore must not include BDK DBs (by design for unencrypted backups).
    let dst_bdk_db = restored_wallet_dir.join("bdk_db");
    let dst_bdk_db_watch_only = restored_wallet_dir.join("bdk_db_watch_only");
    assert!(!dst_bdk_db.exists(), "bdk_db must be absent after restore");
    assert!(
        !dst_bdk_db_watch_only.exists(),
        "bdk_db_watch_only must be absent after restore"
    );

    // Re-hydrate BDK DBs from local copy.
    std::fs::write(&dst_bdk_db, &bdk_db_bytes).expect("write bdk_db");
    if let Some(bytes) = bdk_db_watch_only_bytes {
        std::fs::write(&dst_bdk_db_watch_only, bytes).expect("write bdk_db_watch_only");
    }

    // Open restored wallet and compare full state.
    let mut restored_data = wallet_a.get_wallet_data();
    restored_data.data_dir = restore_root.to_string();
    let restored_keys = wallet_a.get_keys();
    let mut wallet_r = Wallet::new(restored_data, restored_keys).expect("Wallet::new restored");
    assert!(
        !wallet_r.backup_info().expect("backup_info"),
        "backup_info should be false immediately after restore"
    );
    let online_r = wallet_r
        .go_online(true, ELECTRUM_URL.to_string())
        .expect("go_online restored");
    let _ = wallet_r.refresh(online_r.clone(), Some(asset_id.clone()), vec![], false);

    let snapshot_post =
        snapshot_wallet_state(&mut wallet_r, &online_r, &asset_id).expect("snapshot post");

    assert_eq!(
        snapshot_post.asset_inventory, snapshot_pre.asset_inventory,
        "asset inventory mismatch after restore"
    );
    assert_eq!(
        snapshot_post.rgb_balance, snapshot_pre.rgb_balance,
        "balance mismatch after restore"
    );
    assert_eq!(
        snapshot_post.rgb_metadata, snapshot_pre.rgb_metadata,
        "metadata mismatch after restore"
    );
    assert_eq!(
        snapshot_post.transfers, snapshot_pre.transfers,
        "transfers mismatch after restore"
    );
    assert_eq!(
        snapshot_post.transactions, snapshot_pre.transactions,
        "txs mismatch after restore"
    );
    assert_eq!(
        snapshot_post.btc_balance, snapshot_pre.btc_balance,
        "BTC balance mismatch after restore (after re-hydrating bdk_db)"
    );
    assert_eq!(
        snapshot_post.unspents_colorable, snapshot_pre.unspents_colorable,
        "colorable unspents count mismatch after restore (after re-hydrating bdk_db)"
    );

    // Operational smoke: restored wallet can create UTXOs + issue a new asset (with visible effects).
    let colorable_before = wallet_r
        .list_unspents(None, false, true)
        .expect("list_unspents pre-op")
        .iter()
        .filter(|u| u.utxo.colorable)
        .count();
    match wallet_r.create_utxos(
        online_r.clone(),
        true,
        Some(1),
        Some(20_000),
        FEE_RATE,
        false,
    ) {
        Ok(n) => {
            if n > 0 {
                let ok = wait_for_function(
                    || {
                        wallet_r
                            .list_unspents(None, false, true)
                            .unwrap()
                            .iter()
                            .filter(|u| u.utxo.colorable)
                            .count()
                            > colorable_before
                    },
                    5,
                    200,
                );
                if !ok {
                    let colorable_after = wallet_r
                        .list_unspents(Some(online_r.clone()), false, false)
                        .expect("list_unspents post-create_utxos")
                        .iter()
                        .filter(|u| u.utxo.colorable)
                        .count();
                    assert!(
                        colorable_after > colorable_before,
                        "expected at least one new colorable UTXO after create_utxos on restored wallet"
                    );
                }
            }
        }
        Err(Error::AllocationsAlreadyAvailable) => {}
        Err(e) => panic!("create_utxos restored failed: {e:?}"),
    }
    let issued2 = 50u64;
    let asset2 = wallet_r
        .issue_asset_nia("QA2".into(), "QA asset 2".into(), 0, vec![issued2])
        .expect("issue_asset_nia restored");
    let bal2 = wallet_r
        .get_asset_balance(asset2.asset_id.clone())
        .expect("get_asset_balance asset2");
    assert_eq!(
        bal2.future, issued2,
        "expected future balance = issued supply for new asset after restore"
    );
    let assets_after = wallet_r
        .list_assets(vec![])
        .expect("list_assets after issue");
    assert!(
        assets_after
            .nia
            .unwrap_or_default()
            .iter()
            .any(|a| a.asset_id == asset2.asset_id),
        "new asset must appear in list_assets after issue on restored wallet"
    );

    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
}

// Block 2 / Scenario 2.2:
// Unencrypted restore WITHOUT re-hydrating bdk_db: RGB state must restore, but BTC info isn't available offline.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn scenario_2_2_unencrypted_restore_without_bdk_db_restores_rgb_state_only() {
    initialize();
    let rt = tokio_runtime();

    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();
    let (mut wallet_b, online_b) = get_empty_wallet!();

    let _ = wallet_a
        .create_utxos(
            online_a.clone(),
            true,
            Some(5),
            Some(20_000),
            FEE_RATE,
            false,
        )
        .expect("create_utxos");
    let issued_supply = 100u64;
    let asset = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![issued_supply])
        .expect("issue_asset_nia");
    let asset_id = asset.asset_id.clone();

    let send_amount = 10u64;
    let receive = wallet_b
        .witness_receive(
            None,
            Assignment::Fungible(send_amount),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive");
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: receive.recipient_id,
            witness_data: Some(WitnessData {
                amount_sat: 2_000,
                blinding: None,
            }),
            assignment: Assignment::Fungible(send_amount),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let _ = wallet_a
        .send(
            online_a.clone(),
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            None,
            false,
        )
        .expect("send");
    mine_blocks(false, 2, false);

    let expected_settled = issued_supply - send_amount;
    let ok = wait_for_function(
        || {
            let _ = wallet_b.refresh(online_b.clone(), None, vec![], false);
            let _ = wallet_a.refresh(online_a.clone(), Some(asset_id.clone()), vec![], false);
            let bal = wallet_a.get_asset_balance(asset_id.clone()).unwrap();
            bal.settled == expected_settled
        },
        60,
        500,
    );
    assert!(ok, "timeout waiting for wallet state after send");

    let bal_pre = wallet_a
        .get_asset_balance(asset_id.clone())
        .expect("balance");
    let meta_pre = wallet_a
        .get_asset_metadata(asset_id.clone())
        .expect("metadata");
    let transfers_pre = summarize_transfers(&wallet_a, &asset_id).expect("transfers summary");

    let vss_url = vss_server_url();
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_unenc_no_bdk");
    let config =
        VssBackupConfig::new(vss_url.clone(), store_id.clone(), signing_key).with_encryption(false);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let raw = build_raw_vss_client(&vss_url, signing_key);

    let _ = rt
        .block_on(wallet_a.vss_backup(&client))
        .expect("vss_backup");

    // Unencrypted => no metadata key.
    rt.block_on(assert_vss_key_missing(&raw, &store_id, VSS_KEY_METADATA))
        .expect("metadata must be missing");

    // Restore into a clean directory.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let restored_wallet_dir = rt
        .block_on(restore_from_vss(config.clone(), restore_root))
        .expect("restore_from_vss");

    // BDK DBs must be absent.
    assert!(
        !restored_wallet_dir.join("bdk_db").exists(),
        "bdk_db must be absent after restore"
    );

    // Open restored wallet: RGB state should be available after going online + refresh.
    let mut restored_data = wallet_a.get_wallet_data();
    restored_data.data_dir = restore_root.to_string();
    let restored_keys = wallet_a.get_keys();
    let mut wallet_r = Wallet::new(restored_data, restored_keys).expect("Wallet::new restored");
    assert!(
        !wallet_r.backup_info().expect("backup_info"),
        "backup_info should be false immediately after restore"
    );

    let online_r = wallet_r
        .go_online(true, ELECTRUM_URL.to_string())
        .expect("go_online restored");
    let _ = wallet_r.refresh(online_r, Some(asset_id.clone()), vec![], false);

    let bal_post = wallet_r
        .get_asset_balance(asset_id.clone())
        .expect("balance");
    let meta_post = wallet_r
        .get_asset_metadata(asset_id.clone())
        .expect("metadata");
    let transfers_post = summarize_transfers(&wallet_r, &asset_id).expect("transfers summary");

    assert_eq!(bal_post, bal_pre, "RGB balance mismatch after restore");
    assert_eq!(meta_post, meta_pre, "RGB metadata mismatch after restore");
    assert_eq!(
        transfers_post, transfers_pre,
        "RGB transfer summaries mismatch after restore"
    );

    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
}
