use super::*;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::wallet::test::utils::vss::{
    VssServerRestartGuard, dir_has_any_subdir, generate_signing_key_and_store_id, start_vss_server,
    stop_vss_server, tokio_runtime, vss_server_url, wait_tcp_up_http_url,
};

use crate::wallet::test::utils::vss::VssBackupDeleteGuard;
use crate::wallet::test::utils::vss::{
    VSS_KEY_CHUNK0, VSS_KEY_MANIFEST, build_raw_vss_client, vss_key_exists, write_random_file,
};

use crate::wallet::vss::{VSS_CHUNK_SIZE, VssBackupClient, VssBackupConfig, restore_from_vss};

// Block 4 / Scenario 4.2:
// VSS server unavailable -> vss_backup/restore_from_vss must fail cleanly.
#[cfg(feature = "electrum")]
#[test]
#[serial]
#[ignore = "Disruptive (stops VSS docker service); run manually."]
fn scenario_4_2_vss_unavailable_backup_and_restore_fail_cleanly() {
    initialize();

    let vss_url = vss_server_url();
    let rt = tokio_runtime();

    let (mut wallet_a, online_a) = get_funded_noutxo_wallet!();

    // Ensure wallet has a non-trivial on-chain state (funded address already exists via helper).
    let _ = wallet_a
        .get_btc_balance(Some(online_a), false)
        .expect("get_btc_balance");

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_neg_vss_down");
    let config = VssBackupConfig::new(vss_url.clone(), store_id, signing_key);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");

    // Establish a baseline backup while VSS is up.
    let _baseline = rt
        .block_on(wallet_a.vss_backup(&client))
        .expect("baseline vss_backup");
    assert!(
        !wallet_a.backup_info().expect("backup_info"),
        "precondition: backup_info=false immediately after successful baseline VSS backup"
    );

    // Make a state change after baseline backup so backup_info becomes true deterministically.
    let _ = wallet_a.get_address().expect("get_address");
    let backup_required_before = wallet_a.backup_info().expect("backup_info");
    assert!(
        backup_required_before,
        "precondition: expected backup_info=true after a state change following baseline backup"
    );

    // Stop VSS server and ensure it is restarted even on panic (fallback only).
    let mut restart_guard = VssServerRestartGuard::new();
    stop_vss_server().expect("stop_vss_server");

    let mut backup_info_bug: Option<String> = None;

    // vss_backup must fail, and must not mark wallet as backed up.
    let err = match rt.block_on(wallet_a.vss_backup(&client)) {
        Ok(v) => panic!("Expected vss_backup to fail, but it succeeded: {v}"),
        Err(e) => e,
    };
    match &err {
        Error::VssError { .. } => {}
        other => panic!("Expected VssError from vss_backup, got: {other:?}"),
    }

    let backup_required_after = wallet_a.backup_info().expect("backup_info");
    if backup_required_after != backup_required_before {
        // Known bug: failed vss_backup may incorrectly clear backup_info.
        backup_info_bug = Some(format!(
            "BUG: backup_info changed after failed vss_backup: before={backup_required_before}, after={backup_required_after}"
        ));
    }

    // restore_from_vss must fail and must not extract any wallet data.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let err = match rt.block_on(restore_from_vss(config, restore_root)) {
        Ok(p) => panic!(
            "Expected restore_from_vss to fail with VSS down, but it succeeded: {}",
            p.display()
        ),
        Err(e) => e,
    };
    match &err {
        Error::VssError { .. } | Error::VssBackupNotFound | Error::VssAuth { .. } => {}
        other => panic!("Expected VSS-related error from restore, got: {other:?}"),
    }
    assert!(
        !dir_has_any_subdir(std::path::Path::new(restore_root)),
        "restore root must not contain any subdirectories on failure (only log files are expected)"
    );

    // Bring VSS back.
    start_vss_server().expect("start_vss_server");
    restart_guard.mark_restarted();
    wait_tcp_up_http_url(&vss_url, Duration::from_secs(30)).expect("wait VSS up");

    if let Some(msg) = backup_info_bug {
        panic!("{msg}");
    }

    rt.block_on(client.delete_backup()).ok();
    cleanup.disarm();
}

// Block 4 / Scenario 4.5:
// Interrupt during chunked upload: baseline backup must remain valid (manifest uploaded last).
#[cfg(feature = "electrum")]
#[test]
#[serial]
#[ignore = "Disruptive + timing-sensitive (stops VSS docker service); run manually when validating chunked upload atomicity."]
fn scenario_4_5_interrupt_during_chunked_upload_keeps_baseline_atomic() {
    initialize();

    let vss_url = vss_server_url();
    let rt = tokio_runtime();

    let keys = generate_keys(BitcoinNetwork::Regtest);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut wallet = Wallet::new(
        WalletData {
            data_dir: tmp.path().to_str().unwrap().to_string(),
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: vec![AssetSchema::Nia],
            reuse_addresses: false,
        },
        wallet_keys,
    )
    .expect("Wallet::new");

    // Make baseline non-empty.
    let _ = wallet.get_address().expect("get_address");

    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_neg_chunk_interrupt");
    let config = VssBackupConfig::new(vss_url.clone(), store_id.clone(), signing_key);
    let _cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let raw = build_raw_vss_client(&vss_url, signing_key);
    // Ensure server is restarted even if we panic/return early (fallback only).
    let mut restart_guard = VssServerRestartGuard::new();

    let baseline_version = rt
        .block_on(wallet.vss_backup(&client))
        .expect("baseline vss_backup");

    // Force chunked upload with an incompressible >= VSS_CHUNK_SIZE file.
    let big_path = wallet.get_wallet_dir().join("qa_big_random.bin");
    write_random_file(&big_path, VSS_CHUNK_SIZE * 10).expect("write_random_file");

    // Background interrupter: wait until chunk 0 is visible, then stop the VSS server.
    let interrupted_after_chunk0 = Arc::new(AtomicBool::new(false));
    let interrupter_done = Arc::new(AtomicBool::new(false));
    let store_id_bg = store_id.clone();
    let vss_url_bg = vss_url.clone();
    let interrupted_after_chunk0_bg = Arc::clone(&interrupted_after_chunk0);
    let interrupter_done_bg = Arc::clone(&interrupter_done);
    let signing_key_bg = signing_key;

    let interrupter = std::thread::spawn(move || {
        let rt_bg = tokio_runtime();
        let raw_bg = build_raw_vss_client(&vss_url_bg, signing_key_bg);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) {
            match rt_bg.block_on(vss_key_exists(&raw_bg, &store_id_bg, VSS_KEY_CHUNK0)) {
                Ok(true) => {
                    if stop_vss_server().is_ok() {
                        interrupted_after_chunk0_bg.store(true, Ordering::SeqCst);
                        break;
                    }
                }
                _ => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        interrupter_done_bg.store(true, Ordering::SeqCst);
    });

    // Attempt the chunked backup; we expect it to fail once the server is stopped.
    let chunked_res = rt.block_on(wallet.vss_backup(&client));
    let interrupter_join = interrupter.join();
    let chunked_err = match chunked_res {
        Ok(v) => {
            interrupter_join.expect("interrupter thread panicked");
            panic!(
                "Expected chunked vss_backup to fail due to interruption, but it succeeded: {v}"
            );
        }
        Err(e) => e,
    };
    interrupter_join.expect("interrupter thread panicked");

    // Bring VSS back (if we stopped it), then wait until it accepts connections.
    if interrupted_after_chunk0.load(Ordering::SeqCst) {
        start_vss_server().expect("start_vss_server");
        restart_guard.mark_restarted();
    }
    wait_tcp_up_http_url(&vss_url, Duration::from_secs(30)).expect("wait VSS up");

    // Baseline must remain valid and downloadable.
    let server_version_after_failure = rt
        .block_on(client.get_backup_version())
        .expect("get_backup_version")
        .unwrap_or(0);
    assert_eq!(
        server_version_after_failure, baseline_version,
        "Expected baseline backup to remain intact after partial chunked upload (manifest uploaded last)"
    );
    let downloaded_baseline = rt
        .block_on(client.download_backup())
        .expect("download_backup");
    assert!(
        !downloaded_baseline.is_empty(),
        "Expected to still be able to download the baseline backup after interruption"
    );
    assert!(
        rt.block_on(vss_key_exists(&raw, &store_id, VSS_KEY_MANIFEST))
            .expect("manifest exists check"),
        "Expected baseline manifest to still exist after interruption"
    );

    // Ensure this test actually validated the "mid-upload interrupt" semantics.
    //
    // We keep this test `#[ignore]` because it is timing-sensitive and disruptive (it stops the
    // VSS docker service). When explicitly run, it must fail if the environment didn't allow us
    // to interrupt during chunked upload (e.g. chunk 0 never became observable).
    assert!(
        interrupter_done.load(Ordering::SeqCst),
        "interrupter thread did not complete (unexpected)"
    );
    assert!(
        interrupted_after_chunk0.load(Ordering::SeqCst),
        "Did not observe chunk 0 on the server within 30s, so we could not validate mid-upload interruption semantics. chunked_err={chunked_err:?}"
    );

    // Retry backup after server recovery.
    match rt.block_on(wallet.vss_backup(&client)) {
        Ok(version_after_retry) => {
            assert!(
                version_after_retry >= baseline_version,
                "Expected version to be >= baseline after retry"
            );
        }
        Err(e) => panic!("unexpected retry backup failure: {e:?}"),
    }

    // Final restore sanity: restored directory must contain our big file.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let restored_wallet_dir = rt
        .block_on(restore_from_vss(config, restore_root))
        .expect("restore_from_vss");
    assert!(
        restored_wallet_dir.join("qa_big_random.bin").exists(),
        "Expected big file to be present after restore"
    );

    rt.block_on(client.delete_backup()).ok();
}
