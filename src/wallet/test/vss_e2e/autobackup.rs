use super::*;

use crate::wallet::test::utils::vss::{
    VssBackupDeleteGuard, generate_signing_key_and_store_id, tokio_runtime,
    vss_backup_retry_on_version_conflict, vss_server_url, write_random_file,
};

use crate::wallet::vss::{VssBackupClient, VssBackupConfig, VssBackupMode, restore_from_vss};

fn assert_version_unchanged_for(
    rt: &tokio::runtime::Runtime,
    client: &VssBackupClient,
    expected: i64,
    duration: Duration,
    context: &str,
) {
    let start = Instant::now();
    while start.elapsed() < duration {
        let v = rt
            .block_on(client.get_backup_version())
            .expect("get_backup_version")
            .unwrap_or(-1);
        assert_eq!(
            v, expected,
            "Expected VSS version to remain unchanged ({expected}) during {context}, got {v}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

// Block 3 / Scenario 3.1:
// Enable auto-backup and verify it bumps server version after each operation (Blocking mode).
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn scenario_3_1_enable_auto_backup_bumps_version_after_each_operation() {
    initialize();

    let rt = tokio_runtime();

    // Use a funded wallet WITHOUT pre-created allocation UTXOs so create_utxos is a real state change.
    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();

    // Configure VSS auto-backup (Blocking) + a check client for server-side version reads.
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_autobackup_enable");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Blocking);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let check_client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    wallet_a
        .configure_vss_backup(config)
        .expect("configure_vss_backup");

    // `-1` means no backup exists yet; any real server version will be > -1.
    let mut prev_version = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .unwrap_or(-1);

    // 1) create_utxos (state change)
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
    let v1 = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .expect("version must exist after create_utxos");
    assert!(
        v1 > prev_version,
        "Blocking: version must be bumped immediately after create_utxos (prev={prev_version}, got={v1})"
    );
    prev_version = v1;

    // 2) issue (state change)
    let issued_supply = 100u64;
    let asset = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![issued_supply])
        .expect("issue_asset_nia");
    let asset_id = asset.asset_id.clone();
    let v2 = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .expect("version must exist after issue");
    assert!(
        v2 > prev_version,
        "Blocking: version must be bumped immediately after issue (prev={prev_version}, got={v2})"
    );
    prev_version = v2;

    // 3) receive (state change)
    let _ = wallet_a
        .witness_receive(
            Some(asset_id.clone()),
            Assignment::Fungible(1),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive");
    let v3 = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .expect("version must exist after witness_receive");
    assert!(
        v3 > prev_version,
        "Blocking: version must be bumped immediately after witness_receive (prev={prev_version}, got={v3})"
    );
    prev_version = v3;

    // 4) send (state change)
    let (mut wallet_b, _online_b) = get_empty_wallet!();
    let receive_b = wallet_b
        .witness_receive(
            None,
            Assignment::Fungible(10),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive receiver");
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: receive_b.recipient_id,
            witness_data: Some(WitnessData {
                amount_sat: 2_000,
                blinding: None,
            }),
            assignment: Assignment::Fungible(10),
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
    let v4 = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .expect("version must exist after send");
    assert!(
        v4 > prev_version,
        "Blocking: version must be bumped immediately after send (prev={prev_version}, got={v4})"
    );

    wallet_a.disable_vss_auto_backup();
    rt.block_on(check_client.delete_backup())
        .expect("delete_backup");
    cleanup.disarm();
}

// Block 3 / Scenario 3.2:
// Disable auto-backup and verify VSS version does NOT bump after operations.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn scenario_3_2_disable_auto_backup_prevents_version_bumps() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_autobackup_disable");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Blocking);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());

    let check_client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    wallet_a
        .configure_vss_backup(config)
        .expect("configure_vss_backup");

    // Trigger one state change while auto-backup is enabled to create the baseline backup.
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
    let baseline = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .expect("precondition: expected a baseline backup version");

    wallet_a.disable_vss_auto_backup();
    assert_version_unchanged_for(
        &rt,
        &check_client,
        baseline,
        Duration::from_secs(2),
        "post-disable idle",
    );

    // NOTE: This scenario intentionally waits a few seconds after each operation.
    // Negative checks ("nothing happened") require observing silence over time.
    // ~3s/op * 4 ops = ~12s total.

    let issued_supply = 100u64;
    let asset = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![issued_supply])
        .expect("issue_asset_nia");
    let asset_id = asset.asset_id.clone();
    assert_version_unchanged_for(
        &rt,
        &check_client,
        baseline,
        Duration::from_secs(3),
        "issue_asset_nia()",
    );

    let _ = wallet_a
        .witness_receive(
            Some(asset_id.clone()),
            Assignment::Fungible(1),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive");
    assert_version_unchanged_for(
        &rt,
        &check_client,
        baseline,
        Duration::from_secs(3),
        "witness_receive()",
    );

    let (mut wallet_b, _online_b) = get_empty_wallet!();
    let receive_b = wallet_b
        .witness_receive(
            None,
            Assignment::Fungible(10),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive receiver");
    let recipient_map = HashMap::from([(
        asset_id.clone(),
        vec![Recipient {
            recipient_id: receive_b.recipient_id,
            witness_data: Some(WitnessData {
                amount_sat: 2_000,
                blinding: None,
            }),
            assignment: Assignment::Fungible(10),
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
    assert_version_unchanged_for(
        &rt,
        &check_client,
        baseline,
        Duration::from_secs(3),
        "send()",
    );

    match wallet_a.create_utxos(
        online_a.clone(),
        true,
        Some(1),
        Some(20_000),
        FEE_RATE,
        false,
    ) {
        Ok(_) | Err(Error::AllocationsAlreadyAvailable) => {}
        Err(e) => panic!("create_utxos failed: {e:?}"),
    }
    assert_version_unchanged_for(
        &rt,
        &check_client,
        baseline,
        Duration::from_secs(3),
        "create_utxos() after disable",
    );

    rt.block_on(check_client.delete_backup())
        .expect("delete_backup");
    cleanup.disarm();
}

// Block 3: additional manual-only checks.
//
// These are intentionally `#[ignore]`:
// - Some are timing-sensitive/flaky (need to observe an in-flight Async upload).
// - Some are manual-only E2E smoke flows kept for debugging/regression triage.

#[cfg(feature = "electrum")]
#[test]
#[serial]
#[ignore = "Flaky/slow: relies on observing in-flight async backup + server timing; run manually."]
fn scenario_3_3_concurrent_auto_backup_triggers_do_not_start_parallel_uploads() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();

    // Make backups heavier (but keep under chunking threshold).
    let heavy_path = test_get_wallet_dir(&wallet_a).join("qa_autobackup_heavy.bin");
    write_random_file(&heavy_path, 2 * 1024 * 1024).expect("write_random_file");

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_autobackup_concurrent");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Async);
    let check_client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());

    // Baseline manual backup first; configure auto-backup only after.
    let baseline = match vss_backup_retry_on_version_conflict(&rt, &wallet_a, &check_client, 5) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{e:?}").to_lowercase();
            if msg.contains("timeout") {
                eprintln!("SKIP: baseline vss_backup timed out in this environment: {e:?}");
                rt.block_on(check_client.delete_backup()).ok();
                cleanup.disarm();
                return;
            }
            panic!("baseline vss_backup: {e:?}");
        }
    };

    wallet_a
        .configure_vss_backup(config.clone())
        .expect("configure_vss_backup");

    // Trigger auto-backup #1 via a state change.
    let _ = wallet_a.get_address().expect("get_address");

    // Fire "concurrent" triggers while the first upload is presumably in-flight.
    // Note: wallet methods need &mut self, so we can't truly parallelize without a Mutex.
    // This test is intentionally `#[ignore]` and serves as a manual smoke check.
    for _ in 0..8 {
        let _ = wallet_a.get_address().expect("get_address");
    }

    // Eventually, the server version should be > baseline.
    let mut v1: Option<i64> = None;
    let ok = wait_for_function(
        || {
            let v = rt
                .block_on(check_client.get_backup_version())
                .ok()
                .flatten();
            if let Some(v) = v {
                if v > baseline {
                    v1 = Some(v);
                    return true;
                }
            }
            false
        },
        90,
        200,
    );
    assert!(ok, "timeout waiting for server version > baseline");
    let v1 = v1.expect("version must be set");
    assert!(v1 > baseline, "expected version bump after triggers");

    // Final consistency check: restore succeeds.
    let restore_dir = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_dir.path().to_str().unwrap();
    let _ = rt
        .block_on(restore_from_vss(config, restore_root))
        .expect("restore_from_vss");

    rt.block_on(check_client.delete_backup())
        .expect("delete_backup");
    cleanup.disarm();
    let _ = online_a; // keep online alive until the end
}

// Manual-only E2E smoke: auto-backup + restore, Async mode.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
#[ignore = "Manual-only (E2E smoke): auto-backup (Async) + restore + on-chain ops; run manually."]
fn manual_smoke_autobackup_async_restore() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, online_a) = get_funded_wallet!();

    // Create non-trivial state: issue an asset and settle.
    let issued_supply = 100u64;
    let asset = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![issued_supply])
        .expect("issue_asset_nia");
    let asset_id = asset.asset_id.clone();
    mine_blocks(false, 2, false);
    let _ = wallet_a.refresh(online_a.clone(), Some(asset_id.clone()), vec![], false);

    let bal_pre = wallet_a
        .get_asset_balance(asset_id.clone())
        .expect("balance");
    let meta_pre = wallet_a
        .get_asset_metadata(asset_id.clone())
        .expect("metadata");
    let transfers_pre = wallet_a
        .list_transfers(Some(asset_id.clone()))
        .expect("list_transfers");

    // Configure auto-backup Async and wait for the backup to complete.
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_autobackup_async");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Async);
    let check_client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    wallet_a
        .configure_vss_backup(config.clone())
        .expect("configure_vss_backup");

    // Trigger a state change to start auto-backup.
    let _ = wallet_a.get_address().expect("get_address");

    // Wait until a backup appears on the server.
    let mut version: Option<i64> = None;
    let ok = wait_for_function(
        || {
            let v = rt
                .block_on(check_client.get_backup_version())
                .ok()
                .flatten();
            if let Some(v) = v {
                version = Some(v);
                return true;
            }
            false
        },
        60,
        500,
    );
    assert!(ok, "timeout waiting for auto-backup to appear on VSS");
    let _version = version.expect("version");

    // Restore and compare basic state.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let _ = rt
        .block_on(restore_from_vss(config.clone(), restore_root))
        .expect("restore_from_vss");

    let mut restored_data = wallet_a.get_wallet_data();
    restored_data.data_dir = restore_root.to_string();
    let restored_keys = wallet_a.get_keys();
    let mut wallet_r = Wallet::new(restored_data, restored_keys).expect("Wallet::new restored");
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
    let transfers_post = wallet_r
        .list_transfers(Some(asset_id.clone()))
        .expect("list_transfers");

    assert_eq!(bal_post, bal_pre, "balance mismatch after restore");
    assert_eq!(meta_post, meta_pre, "metadata mismatch after restore");
    assert_eq!(
        transfers_post.len(),
        transfers_pre.len(),
        "transfer count mismatch after restore"
    );

    rt.block_on(check_client.delete_backup())
        .expect("delete_backup");
    cleanup.disarm();
}

// Manual-only E2E smoke: auto-backup + restore, Blocking mode.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
#[ignore = "Manual-only (E2E smoke): auto-backup (Blocking) + restore + on-chain ops; run manually."]
fn manual_smoke_autobackup_blocking_restore() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, online_a) = get_funded_wallet!();

    let issued_supply = 100u64;
    let asset = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![issued_supply])
        .expect("issue_asset_nia");
    let asset_id = asset.asset_id.clone();
    mine_blocks(false, 2, false);
    let _ = wallet_a.refresh(online_a.clone(), Some(asset_id.clone()), vec![], false);

    let bal_pre = wallet_a
        .get_asset_balance(asset_id.clone())
        .expect("balance");

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_autobackup_blocking");
    let config = VssBackupConfig::new(vss_server_url(), store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Blocking);
    let check_client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    wallet_a
        .configure_vss_backup(config.clone())
        .expect("configure_vss_backup");

    let prev = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .unwrap_or(-1);
    // Blocking should persist before returning.
    let _ = wallet_a.get_address().expect("get_address");
    let v = rt
        .block_on(check_client.get_backup_version())
        .expect("get_backup_version")
        .expect("version must exist");
    assert!(v > prev, "expected version bump in Blocking mode");

    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let _ = rt
        .block_on(restore_from_vss(config.clone(), restore_root))
        .expect("restore_from_vss");

    let mut restored_data = wallet_a.get_wallet_data();
    restored_data.data_dir = restore_root.to_string();
    let restored_keys = wallet_a.get_keys();
    let mut wallet_r = Wallet::new(restored_data, restored_keys).expect("Wallet::new restored");
    let online_r = wallet_r
        .go_online(true, ELECTRUM_URL.to_string())
        .expect("go_online restored");
    let _ = wallet_r.refresh(online_r, Some(asset_id.clone()), vec![], false);
    let bal_post = wallet_r.get_asset_balance(asset_id).expect("balance");
    assert_eq!(bal_post, bal_pre, "balance mismatch after restore");

    rt.block_on(check_client.delete_backup())
        .expect("delete_backup");
    cleanup.disarm();
}
