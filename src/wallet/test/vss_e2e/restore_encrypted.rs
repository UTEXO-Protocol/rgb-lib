use super::*;

use crate::wallet::test::utils::vss::{
    VSS_KEY_CHUNK_PREFIX, VSS_KEY_DATA, VSS_KEY_FINGERPRINT, VSS_KEY_MANIFEST, VSS_KEY_METADATA,
    VssBackupDeleteGuard, build_raw_vss_client, generate_signing_key_and_store_id, get_vss_key,
    snapshot_wallet_state, tokio_runtime, vss_key_exists, vss_server_url,
};

use crate::wallet::vss::{
    BackupManifest, VssBackupClient, VssBackupConfig, VssEncryptionMetadata, restore_from_vss,
};

// Block 1: encrypted backup + restore happy path.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn scenario_1_encrypted_backup_restore_matches_state_and_wallet_operational() {
    initialize();

    let rt = tokio_runtime();

    // Wallet A (sender) + Wallet B (receiver).
    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();
    let (mut wallet_b, online_b) = get_empty_wallet!();

    // Ensure non-trivial RGB state.
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
    let op = wallet_a
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
    assert!(!op.txid.is_empty(), "expected txid after send");

    mine_blocks(false, 2, false);
    let expected_settled = issued_supply - send_amount;
    let ok = wait_for_function(
        || {
            let _ = wallet_b.refresh(online_b.clone(), None, vec![], false);
            let _ = wallet_a.refresh(online_a.clone(), Some(asset_id.clone()), vec![], false);
            let bal = wallet_a.get_asset_balance(asset_id.clone()).unwrap();
            bal.settled == expected_settled
        },
        120,
        500,
    );
    assert!(ok, "timeout waiting for wallet state after send");

    // Snapshot state BEFORE VSS backup (things expected to survive restore).
    let snapshot_pre =
        snapshot_wallet_state(&mut wallet_a, &online_a, &asset_id).expect("snapshot pre");
    assert!(
        !snapshot_pre.transfers.is_empty(),
        "precondition: expected transfers"
    );
    assert!(
        !snapshot_pre.transactions.is_empty(),
        "precondition: expected transactions"
    );

    // Configure VSS (encryption enabled by default).
    let vss_url = vss_server_url();
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_case1");
    let config = VssBackupConfig::new(vss_url.clone(), store_id.clone(), signing_key);
    // Panic guard: best-effort cleanup if the test aborts before explicit delete.
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let raw = build_raw_vss_client(&vss_url, signing_key);

    // Upload wallet backup to VSS.
    let version = rt
        .block_on(wallet_a.vss_backup(&client))
        .expect("vss_backup");
    let server_version = rt
        .block_on(client.get_backup_version())
        .expect("get_backup_version")
        .expect("server version must exist after backup");
    assert_eq!(server_version, version, "version mismatch");

    // Verify expected server-side keys exist.
    let manifest_bytes = rt
        .block_on(get_vss_key(&raw, &store_id, VSS_KEY_MANIFEST))
        .expect("get manifest");
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes).expect("manifest json");
    assert!(manifest.encrypted, "expected encrypted backup");

    assert!(
        rt.block_on(vss_key_exists(&raw, &store_id, VSS_KEY_FINGERPRINT))
            .expect("fingerprint key check"),
        "expected fingerprint key"
    );
    let metadata_exists = rt
        .block_on(vss_key_exists(&raw, &store_id, VSS_KEY_METADATA))
        .expect("metadata key check");
    assert!(metadata_exists, "expected encryption metadata key");
    let metadata_bytes = rt
        .block_on(get_vss_key(&raw, &store_id, VSS_KEY_METADATA))
        .expect("get metadata");
    let _metadata: VssEncryptionMetadata =
        serde_json::from_slice(&metadata_bytes).expect("metadata json");

    if manifest.chunk_count == 1 {
        assert!(
            rt.block_on(vss_key_exists(&raw, &store_id, VSS_KEY_DATA))
                .expect("data key check"),
            "expected backup/data for single-chunk backup"
        );
    } else {
        for i in 0..manifest.chunk_count {
            let key = format!("{VSS_KEY_CHUNK_PREFIX}{i}");
            assert!(
                rt.block_on(vss_key_exists(&raw, &store_id, &key))
                    .expect("chunk key check"),
                "expected chunk key {key}"
            );
        }
    }

    // Restore into a clean directory.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let _restored_wallet_dir = rt
        .block_on(restore_from_vss(config.clone(), restore_root))
        .expect("restore_from_vss");

    // Open restored wallet and compare snapshots.
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
        "transactions mismatch after restore"
    );
    assert_eq!(
        snapshot_post.btc_balance, snapshot_pre.btc_balance,
        "BTC balance mismatch after restore"
    );
    assert_eq!(
        snapshot_post.unspents_colorable, snapshot_pre.unspents_colorable,
        "colorable unspents count mismatch after restore"
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
                // `create_utxos` should immediately register new colorable UTXOs. Keep a short wait
                // to reduce flakiness on slower environments.
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
                    // Fallback: perform one sync and assert again.
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

    // Explicit delete (plus the assertion below); disarm the guard to avoid double-delete in Drop.
    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
    assert!(
        rt.block_on(client.get_backup_version())
            .expect("get_backup_version after delete")
            .is_none(),
        "expected backup to be deleted"
    );
}
