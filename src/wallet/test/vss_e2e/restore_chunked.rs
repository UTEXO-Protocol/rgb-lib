use super::*;

use crate::wallet::test::utils::vss::{
    VSS_KEY_CHUNK_PREFIX, VSS_KEY_FINGERPRINT, VSS_KEY_MANIFEST, VSS_KEY_METADATA,
    VssBackupDeleteGuard, build_raw_vss_client, generate_signing_key_and_store_id, get_vss_key,
    summarize_transfers, tokio_runtime, vss_key_exists, vss_server_url, write_random_file,
};

use crate::wallet::vss::{
    BackupManifest, VSS_CHUNK_SIZE, VssBackupClient, VssBackupConfig, restore_from_vss,
};

// Block 1 (chunked): encrypted backup should use chunked upload and still restore correctly.
#[cfg(feature = "electrum")]
#[test]
#[serial]
fn scenario_1_chunked_encrypted_backup_upload_and_restore() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, online_a) = get_funded_wallet!();
    let (mut wallet_b, online_b) = get_empty_wallet!();

    // Make non-trivial RGB state (so restore correctness isn't just "file exists on disk").
    match wallet_a.create_utxos(
        online_a.clone(),
        true,
        Some(3),
        Some(20_000),
        FEE_RATE,
        false,
    ) {
        Ok(_) | Err(Error::AllocationsAlreadyAvailable) => {}
        Err(e) => panic!("create_utxos failed: {e:?}"),
    }

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
        120,
        500,
    );
    assert!(ok, "timeout waiting for send settle");

    let assets_pre = wallet_a.list_assets(vec![]).expect("list_assets pre");
    let balance_pre = wallet_a
        .get_asset_balance(asset_id.clone())
        .expect("balance pre");
    let meta_pre = wallet_a
        .get_asset_metadata(asset_id.clone())
        .expect("metadata pre");
    let transfers_pre = summarize_transfers(&wallet_a, &asset_id).expect("transfers pre");

    // Write an incompressible file > VSS_CHUNK_SIZE to force chunking.
    let big_path = wallet_a.get_wallet_dir().join("qa_big_random.bin");
    write_random_file(&big_path, VSS_CHUNK_SIZE * 10).expect("write_random_file");

    // Touch chain once so BTC state isn't empty in restored wallet.
    let _ = wallet_a
        .get_btc_balance(Some(online_a.clone()), false)
        .expect("btc balance");

    let vss_url = vss_server_url();
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_chunked");
    let config = VssBackupConfig::new(vss_url.clone(), store_id.clone(), signing_key);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let raw = build_raw_vss_client(&vss_url, signing_key);

    let _version = rt
        .block_on(wallet_a.vss_backup(&client))
        .expect("vss_backup");

    // Manifest should show multiple chunks.
    let manifest_bytes = rt
        .block_on(get_vss_key(&raw, &store_id, VSS_KEY_MANIFEST))
        .expect("manifest");
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes).expect("manifest json");
    assert!(
        manifest.chunk_count > 1,
        "expected chunked upload (chunk_count>1), got {}",
        manifest.chunk_count
    );

    assert!(
        rt.block_on(vss_key_exists(&raw, &store_id, VSS_KEY_FINGERPRINT))
            .expect("fingerprint key check"),
        "expected fingerprint key"
    );
    assert!(
        rt.block_on(vss_key_exists(&raw, &store_id, VSS_KEY_METADATA))
            .expect("metadata key check"),
        "expected metadata key for encrypted backup"
    );

    // Each chunk key should exist (allow brief eventual consistency).
    for i in 0..manifest.chunk_count {
        let key = format!("{VSS_KEY_CHUNK_PREFIX}{i}");
        let mut ok = false;
        for _ in 0..30 {
            if rt
                .block_on(vss_key_exists(&raw, &store_id, &key))
                .expect("chunk key check")
            {
                ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert!(ok, "expected VSS chunk key to exist: {key}");
    }

    // Restore and check big file presence.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let restored_wallet_dir = rt
        .block_on(restore_from_vss(config.clone(), restore_root))
        .expect("restore_from_vss");
    assert!(
        restored_wallet_dir.join("qa_big_random.bin").exists(),
        "expected big file after restore"
    );

    // Open restored wallet and compare RGB state.
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

    let assets_post = wallet_r.list_assets(vec![]).expect("list_assets post");
    let balance_post = wallet_r
        .get_asset_balance(asset_id.clone())
        .expect("balance post");
    let meta_post = wallet_r
        .get_asset_metadata(asset_id.clone())
        .expect("metadata post");
    let transfers_post = summarize_transfers(&wallet_r, &asset_id).expect("transfers post");

    assert_eq!(
        assets_post, assets_pre,
        "asset inventory mismatch after restore"
    );
    assert_eq!(
        balance_post, balance_pre,
        "RGB balance mismatch after restore"
    );
    assert_eq!(meta_post, meta_pre, "RGB metadata mismatch after restore");
    assert_eq!(
        transfers_post, transfers_pre,
        "RGB transfer summaries mismatch after restore"
    );

    // Operational smoke: restored wallet can issue a new asset (visible effects).
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

    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
}
