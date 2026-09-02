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
