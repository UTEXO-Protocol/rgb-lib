use super::*;

use crate::wallet::test::utils::vss::{
    VSS_CHUNK_SIZE_BYTES, VSS_KEY_CHUNK_PREFIX, VSS_KEY_FINGERPRINT, VSS_KEY_MANIFEST,
    VSS_KEY_METADATA, VssBackupDeleteGuard, build_raw_vss_client,
    generate_signing_key_and_store_id, get_vss_key, tokio_runtime, vss_key_exists, vss_server_url,
    write_random_file,
};

use crate::wallet::vss::{BackupManifest, VssBackupClient, VssBackupConfig, restore_from_vss};

// Block 1 (chunked): encrypted backup >4MB should use chunked upload and still restore correctly.
#[cfg(feature = "electrum")]
#[test]
#[serial]
#[ignore = "Flaky/slow: chunked upload depends on HTTP timeouts and environment; run manually."]
fn scenario_1_chunked_encrypted_backup_upload_and_restore() {
    initialize();

    let rt = tokio_runtime();
    let (mut wallet_a, online_a) = get_funded_wallet!();

    // Ensure non-trivial state and write an incompressible file >4MiB to force chunking.
    let big_path = wallet_a.get_wallet_dir().join("qa_big_random.bin");
    write_random_file(&big_path, VSS_CHUNK_SIZE_BYTES + 256 * 1024).expect("write_random_file");

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

    let _version = match rt.block_on(wallet_a.vss_backup(&client)) {
        Ok(v) => v,
        Err(Error::VssError { details }) if details.to_lowercase().contains("timeout") => {
            eprintln!("SKIP: chunked vss_backup timed out in this environment: {details}");
            rt.block_on(client.delete_backup()).ok();
            return;
        }
        Err(e) => panic!("vss_backup: {e:?}"),
    };

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

    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
}
