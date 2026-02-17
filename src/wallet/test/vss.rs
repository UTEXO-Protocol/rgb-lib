use super::*;

use bdk_wallet::bitcoin::secp256k1::rand::rngs::OsRng;
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};

use crate::wallet::vss::{VssBackupClient, VssBackupConfig, VssBackupMode, restore_from_vss};

const VSS_SERVER_URL: &str = "http://localhost:8081/vss";

fn generate_test_keys() -> (SecretKey, String) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    let store_id = format!("test_{}", hex::encode(&public_key.serialize()[0..8]));
    (secret_key, store_id)
}

fn create_test_zip(fingerprint: &str, content: &[u8]) -> Vec<u8> {
    use zip::write::SimpleFileOptions;

    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

        zip.add_directory(format!("{fingerprint}/"), options)
            .unwrap();
        zip.start_file(format!("{fingerprint}/data.bin"), options)
            .unwrap();
        zip.write_all(content).unwrap();
        zip.finish().unwrap();
    }
    buffer.into_inner()
}

fn create_mock_wallet_zip(wallet_dir: &PathBuf) -> Vec<u8> {
    use std::io::Read as StdRead;
    use walkdir::WalkDir;
    use zip::write::SimpleFileOptions;

    let mut buffer = std::io::Cursor::new(Vec::new());

    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);
        let mut file_buffer = [0u8; 4096];

        let prefix = wallet_dir.parent().expect("wallet dir has no parent");

        for entry in WalkDir::new(wallet_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            let name = path.strip_prefix(prefix).expect("strip prefix failed");
            let name_str = name.to_str().expect("invalid path encoding");

            if path.is_file() {
                zip.start_file(name_str, options).unwrap();
                let mut f = fs::File::open(path).unwrap();
                loop {
                    let read_count = f.read(&mut file_buffer).unwrap();
                    if read_count != 0 {
                        zip.write_all(&file_buffer[..read_count]).unwrap();
                    } else {
                        break;
                    }
                }
            } else if !name.as_os_str().is_empty() {
                zip.add_directory(name_str, options).unwrap();
            }
        }

        zip.finish().unwrap();
    }

    buffer.into_inner()
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn encrypted_backup() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    let config = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_encrypted"),
        signing_key,
    );

    let client = VssBackupClient::new(config).unwrap();

    let original_data = create_test_zip(
        "f1e2c3a0",
        b"Hello, this is encrypted test data for VSS backup!",
    );

    let _version = client.upload_backup(original_data.clone()).await.unwrap();

    let downloaded = client.download_backup().await.unwrap();
    assert_eq!(downloaded, original_data);

    client.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn plaintext_backup() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    let config = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_plaintext"),
        signing_key,
    )
    .with_encryption(false);

    let client = VssBackupClient::new(config).unwrap();

    let original_data = create_test_zip("b1a2d3c4", b"This is plaintext data - no encryption!");

    let _version = client.upload_backup(original_data).await.unwrap();

    let downloaded = client.download_backup().await.unwrap();

    // Verify the downloaded zip has sanitized paths (wallet/ instead of fingerprint)
    let reader = std::io::Cursor::new(&downloaded);
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    let has_wallet_dir = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|f| f.name().starts_with("wallet/"))
            .unwrap_or(false)
    });
    assert!(
        has_wallet_dir,
        "Downloaded plaintext backup missing sanitized 'wallet/' directory"
    );

    client.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn version_tracking() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    let config = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_version"),
        signing_key,
    )
    .with_encryption(false);

    let client = VssBackupClient::new(config).unwrap();

    // No backup initially
    let initial_version = client.get_backup_version().await.unwrap();
    assert!(initial_version.is_none());

    // Upload first version
    let data_v1 = create_test_zip("e4d5c6b7", b"Version 1 data");
    let v1 = client.upload_backup(data_v1).await.unwrap();

    // Upload second version
    let data_v2 = create_test_zip("e4d5c6b7", b"Version 2 data - updated");
    let v2 = client.upload_backup(data_v2).await.unwrap();

    assert!(v2 > v1, "Version did not increase: v1={v1}, v2={v2}");

    // Latest data is downloadable
    let downloaded = client.download_backup().await.unwrap();
    assert!(!downloaded.is_empty());

    client.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn delete_backup() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    let config = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_delete"),
        signing_key,
    )
    .with_encryption(false);

    let client = VssBackupClient::new(config).unwrap();

    let data = create_test_zip("d1e2f3a4", b"Data to be deleted");
    client.upload_backup(data).await.unwrap();

    let version = client.get_backup_version().await.unwrap();
    assert!(version.is_some(), "Backup not found after upload");

    client.delete_backup().await.unwrap();

    let version_after = client.get_backup_version().await.unwrap();
    assert!(version_after.is_none(), "Backup still exists after delete");
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn wrong_signing_key() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    // Upload with correct key
    let config_upload = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_wrongkey"),
        signing_key,
    );

    let client_upload = VssBackupClient::new(config_upload).unwrap();

    let data = create_test_zip("a0b1c2d3", b"Secret data");
    client_upload.upload_backup(data).await.unwrap();

    // Try to download with a different signing key
    let wrong_key = SecretKey::new(&mut OsRng);
    let config_download = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_wrongkey"),
        wrong_key,
    );

    let client_download = VssBackupClient::new(config_download).unwrap();

    let result = client_download.download_backup().await;
    assert!(
        result.is_err(),
        "Download should fail with wrong signing key"
    );
    let error_str = format!("{:?}", result.unwrap_err());
    assert!(
        error_str.contains("Vss"),
        "Expected VssError, got: {error_str}"
    );

    client_upload.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn unencrypted_wrong_signing_key() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    // Upload with correct key, encryption disabled
    let config_upload = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_unwrongkey"),
        signing_key,
    )
    .with_encryption(false);

    let client_upload = VssBackupClient::new(config_upload).unwrap();

    let original_data = create_test_zip("f0e1d2c3", b"Plaintext secret data");
    client_upload
        .upload_backup(original_data.clone())
        .await
        .unwrap();

    // With sigs auth, a different signing key is rejected by the server
    // even without encryption — server-side auth protects the data.
    let wrong_key = SecretKey::new(&mut OsRng);
    let config_download = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_unwrongkey"),
        wrong_key,
    )
    .with_encryption(false);

    let client_download = VssBackupClient::new(config_download).unwrap();

    let result = client_download.download_backup().await;
    assert!(
        result.is_err(),
        "Download should fail with wrong signing key even without encryption"
    );
    let error_str = format!("{:?}", result.unwrap_err());
    assert!(
        error_str.contains("Vss"),
        "Expected VssError, got: {error_str}"
    );

    client_upload.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn wallet_backup_restore() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    // Create a temporary "wallet" directory with mock data
    let temp_dir = tempfile::tempdir().unwrap();
    let wallet_fingerprint = "abc12345";
    let wallet_dir = temp_dir.path().join(wallet_fingerprint);
    fs::create_dir_all(&wallet_dir).unwrap();

    // Create mock wallet files
    let db_file = wallet_dir.join("rgb_lib_db");
    let mut f = fs::File::create(&db_file).unwrap();
    f.write_all(b"mock database content with some data")
        .unwrap();

    let assets_dir = wallet_dir.join("assets");
    fs::create_dir_all(&assets_dir).unwrap();

    let asset_file = assets_dir.join("asset_001.dat");
    let mut f = fs::File::create(&asset_file).unwrap();
    f.write_all(b"mock asset data").unwrap();

    // Create VSS config and client
    let config = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_wallet"),
        signing_key,
    );

    let client = VssBackupClient::new(config.clone()).unwrap();

    let backup_data = create_mock_wallet_zip(&wallet_dir);

    let _version = client.upload_backup(backup_data).await.unwrap();

    // Restore to a different directory
    let restore_dir = tempfile::tempdir().unwrap();

    let restored_wallet_path = restore_from_vss(config, restore_dir.path().to_str().unwrap())
        .await
        .unwrap();

    // Verify restored files
    let restored_db = restored_wallet_path.join("rgb_lib_db");
    assert!(restored_db.exists(), "Restored database file not found");
    let restored_db_content = fs::read_to_string(&restored_db).unwrap();
    assert_eq!(restored_db_content, "mock database content with some data");

    let restored_asset = restored_wallet_path.join("assets").join("asset_001.dat");
    assert!(restored_asset.exists(), "Restored asset file not found");
    let restored_asset_content = fs::read_to_string(&restored_asset).unwrap();
    assert_eq!(restored_asset_content, "mock asset data");

    client.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn unencrypted_wallet_backup_restore() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    // Create a temporary "wallet" directory with mock data
    let temp_dir = tempfile::tempdir().unwrap();
    let wallet_fingerprint = "def67890";
    let wallet_dir = temp_dir.path().join(wallet_fingerprint);
    fs::create_dir_all(&wallet_dir).unwrap();

    // Create mock wallet files
    let db_file = wallet_dir.join("rgb_lib_db");
    let mut f = fs::File::create(&db_file).unwrap();
    f.write_all(b"mock database content for plaintext backup")
        .unwrap();

    let assets_dir = wallet_dir.join("assets");
    fs::create_dir_all(&assets_dir).unwrap();

    let asset_file = assets_dir.join("asset_002.dat");
    let mut f = fs::File::create(&asset_file).unwrap();
    f.write_all(b"mock plaintext asset data").unwrap();

    // Create VSS config with encryption disabled
    let config = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_unwallet"),
        signing_key,
    )
    .with_encryption(false);

    let client = VssBackupClient::new(config.clone()).unwrap();

    let backup_data = create_mock_wallet_zip(&wallet_dir);

    let _version = client.upload_backup(backup_data).await.unwrap();

    // Restore to a different directory
    let restore_dir = tempfile::tempdir().unwrap();

    let restored_wallet_path = restore_from_vss(config, restore_dir.path().to_str().unwrap())
        .await
        .unwrap();

    // Verify the restored path uses the original fingerprint (not "wallet/")
    assert!(
        restored_wallet_path
            .to_str()
            .unwrap()
            .contains(wallet_fingerprint),
        "Restored path should contain original fingerprint, got: {:?}",
        restored_wallet_path
    );

    // Verify restored files
    let restored_db = restored_wallet_path.join("rgb_lib_db");
    assert!(restored_db.exists(), "Restored database file not found");
    let restored_db_content = fs::read_to_string(&restored_db).unwrap();
    assert_eq!(
        restored_db_content,
        "mock database content for plaintext backup"
    );

    let restored_asset = restored_wallet_path.join("assets").join("asset_002.dat");
    assert!(restored_asset.exists(), "Restored asset file not found");
    let restored_asset_content = fs::read_to_string(&restored_asset).unwrap();
    assert_eq!(restored_asset_content, "mock plaintext asset data");

    client.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn backup_info() {
    initialize();
    let (signing_key, store_id) = generate_test_keys();

    let config = VssBackupConfig::new(
        VSS_SERVER_URL.to_string(),
        format!("{store_id}_info"),
        signing_key,
    )
    .with_encryption(false);

    let client = VssBackupClient::new(config).unwrap();

    // No backup initially
    let version_before = client.get_backup_version().await.unwrap();
    assert!(version_before.is_none(), "Expected no backup initially");

    // Upload a backup
    let data = create_test_zip("c3d4e5f6", b"Test data for info check");
    client.upload_backup(data).await.unwrap();

    // Backup exists now
    let version_after = client.get_backup_version().await.unwrap();
    assert!(
        version_after.is_some(),
        "Expected backup to exist after upload"
    );

    client.delete_backup().await.unwrap();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn auto_backup() {
    initialize();
    let (_, store_id) = generate_test_keys();

    let secp = Secp256k1::new();
    let (signing_key, _) = secp.generate_keypair(&mut OsRng);

    let wallet_data = {
        let keys = generate_keys(BitcoinNetwork::Regtest);
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap().to_string();

        // Keep the tempdir alive without cleanup (wallet needs it)
        let _keep = temp_dir.keep();

        WalletData {
            data_dir,
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            account_xpub_vanilla: keys.account_xpub_vanilla,
            account_xpub_colored: keys.account_xpub_colored,
            mnemonic: Some(keys.mnemonic),
            master_fingerprint: keys.master_fingerprint,
            vanilla_keychain: None,
            supported_schemas: vec![
                AssetSchema::Nia,
                AssetSchema::Uda,
                AssetSchema::Cfa,
                AssetSchema::Ifa,
            ],
        }
    };

    // Create wallet on a blocking task (Wallet::new uses block_on internally
    // for database migration, which conflicts with the tokio async context)
    let mut wallet = tokio::task::spawn_blocking(move || Wallet::new(wallet_data))
        .await
        .expect("spawn_blocking panicked")
        .expect("failed to create wallet");

    // Configure VSS auto-backup
    let vss_store_id = format!("{store_id}_autobackup");
    let config = VssBackupConfig::new(VSS_SERVER_URL.to_string(), vss_store_id, signing_key)
        .with_auto_backup(true);

    wallet.configure_vss_backup(config.clone()).unwrap();

    // Verify no backup exists yet
    let check_client = VssBackupClient::new(config).unwrap();
    let version_before = check_client.get_backup_version().await.unwrap();
    assert!(
        version_before.is_none(),
        "Backup already exists before state change"
    );

    // Trigger a state-changing operation
    let _address = wallet.get_address().unwrap();

    // Wait for the async auto-backup to complete
    let mut backup_found = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        match check_client.get_backup_version().await {
            Ok(Some(_)) => {
                backup_found = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(
        backup_found,
        "Auto-backup did not complete within 10 seconds"
    );

    // Verify the backup can be downloaded
    let downloaded = check_client.download_backup().await.unwrap();
    assert!(!downloaded.is_empty(), "Downloaded backup is empty");

    // Cleanup
    check_client.delete_backup().await.unwrap();
    wallet.disable_vss_auto_backup();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn unencrypted_auto_backup() {
    initialize();
    let (_, store_id) = generate_test_keys();

    let secp = Secp256k1::new();
    let (signing_key, _) = secp.generate_keypair(&mut OsRng);

    let wallet_data = {
        let keys = generate_keys(BitcoinNetwork::Regtest);
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap().to_string();

        // Keep the tempdir alive without cleanup (wallet needs it)
        let _keep = temp_dir.keep();

        WalletData {
            data_dir,
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            account_xpub_vanilla: keys.account_xpub_vanilla,
            account_xpub_colored: keys.account_xpub_colored,
            mnemonic: Some(keys.mnemonic),
            master_fingerprint: keys.master_fingerprint,
            vanilla_keychain: None,
            supported_schemas: vec![
                AssetSchema::Nia,
                AssetSchema::Uda,
                AssetSchema::Cfa,
                AssetSchema::Ifa,
            ],
        }
    };

    // Create wallet on a blocking task (Wallet::new uses block_on internally
    // for database migration, which conflicts with the tokio async context)
    let mut wallet = tokio::task::spawn_blocking(move || Wallet::new(wallet_data))
        .await
        .expect("spawn_blocking panicked")
        .expect("failed to create wallet");

    // Configure VSS auto-backup with encryption disabled
    let vss_store_id = format!("{store_id}_unautobackup");
    let config = VssBackupConfig::new(VSS_SERVER_URL.to_string(), vss_store_id, signing_key)
        .with_auto_backup(true)
        .with_encryption(false);

    wallet.configure_vss_backup(config.clone()).unwrap();

    // Verify no backup exists yet
    let check_client = VssBackupClient::new(config).unwrap();
    let version_before = check_client.get_backup_version().await.unwrap();
    assert!(
        version_before.is_none(),
        "Backup already exists before state change"
    );

    // Trigger a state-changing operation
    let _address = wallet.get_address().unwrap();

    // Wait for the async auto-backup to complete
    let mut backup_found = false;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        match check_client.get_backup_version().await {
            Ok(Some(_)) => {
                backup_found = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(
        backup_found,
        "Unencrypted auto-backup did not complete within 10 seconds"
    );

    // Verify the backup can be downloaded
    let downloaded = check_client.download_backup().await.unwrap();
    assert!(!downloaded.is_empty(), "Downloaded backup is empty");

    // Verify the downloaded data is a valid zip with sanitized paths (no fingerprint)
    let reader = std::io::Cursor::new(&downloaded);
    let mut archive = zip::ZipArchive::new(reader).unwrap();
    let has_wallet_dir = (0..archive.len()).any(|i| {
        archive
            .by_index(i)
            .map(|f| f.name().starts_with("wallet/"))
            .unwrap_or(false)
    });
    assert!(
        has_wallet_dir,
        "Unencrypted auto-backup should use sanitized 'wallet/' directory"
    );

    // Cleanup
    check_client.delete_backup().await.unwrap();
    wallet.disable_vss_auto_backup();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn blocking_auto_backup() {
    initialize();
    let (_, store_id) = generate_test_keys();

    let secp = Secp256k1::new();
    let (signing_key, _) = secp.generate_keypair(&mut OsRng);

    let wallet_data = {
        let keys = generate_keys(BitcoinNetwork::Regtest);
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap().to_string();

        // Keep the tempdir alive without cleanup (wallet needs it)
        let _keep = temp_dir.keep();

        WalletData {
            data_dir,
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            account_xpub_vanilla: keys.account_xpub_vanilla,
            account_xpub_colored: keys.account_xpub_colored,
            mnemonic: Some(keys.mnemonic),
            master_fingerprint: keys.master_fingerprint,
            vanilla_keychain: None,
            supported_schemas: vec![
                AssetSchema::Nia,
                AssetSchema::Uda,
                AssetSchema::Cfa,
                AssetSchema::Ifa,
            ],
        }
    };

    // Create wallet on a blocking task (Wallet::new uses block_on internally
    // for database migration, which conflicts with the tokio async context)
    let mut wallet = tokio::task::spawn_blocking(move || Wallet::new(wallet_data))
        .await
        .expect("spawn_blocking panicked")
        .expect("failed to create wallet");

    // Configure VSS auto-backup in Blocking mode
    let vss_store_id = format!("{store_id}_blockautobackup");
    let config = VssBackupConfig::new(VSS_SERVER_URL.to_string(), vss_store_id, signing_key)
        .with_auto_backup(true)
        .with_backup_mode(VssBackupMode::Blocking);

    wallet.configure_vss_backup(config.clone()).unwrap();

    // Verify no backup exists yet
    let check_client = VssBackupClient::new(config).unwrap();
    let version_before = check_client.get_backup_version().await.unwrap();
    assert!(
        version_before.is_none(),
        "Backup already exists before state change"
    );

    // Trigger a state-changing operation — in Blocking mode this returns
    // only after the backup upload has completed.
    let _address = wallet.get_address().unwrap();

    // No polling loop needed: the backup must already be persisted.
    let version_after = check_client.get_backup_version().await.unwrap();
    assert!(
        version_after.is_some(),
        "Blocking auto-backup did not persist before get_address() returned"
    );

    // Verify the backup can be downloaded
    let downloaded = check_client.download_backup().await.unwrap();
    assert!(!downloaded.is_empty(), "Downloaded backup is empty");

    // Cleanup
    check_client.delete_backup().await.unwrap();
    wallet.disable_vss_auto_backup();
}

#[cfg(feature = "electrum")]
#[tokio::test]
#[parallel]
async fn auto_backup_disabled_by_default() {
    initialize();
    let (_, store_id) = generate_test_keys();

    let secp = Secp256k1::new();
    let (signing_key, _) = secp.generate_keypair(&mut OsRng);

    let wallet_data = {
        let keys = generate_keys(BitcoinNetwork::Regtest);
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().to_str().unwrap().to_string();

        let _keep = temp_dir.keep();

        WalletData {
            data_dir,
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            account_xpub_vanilla: keys.account_xpub_vanilla,
            account_xpub_colored: keys.account_xpub_colored,
            mnemonic: Some(keys.mnemonic),
            master_fingerprint: keys.master_fingerprint,
            vanilla_keychain: None,
            supported_schemas: vec![
                AssetSchema::Nia,
                AssetSchema::Uda,
                AssetSchema::Cfa,
                AssetSchema::Ifa,
            ],
        }
    };

    let mut wallet = tokio::task::spawn_blocking(move || Wallet::new(wallet_data))
        .await
        .expect("spawn_blocking panicked")
        .expect("failed to create wallet");

    // Configure VSS without enabling auto-backup (default is false)
    let vss_store_id = format!("{store_id}_noautobackup");
    let config = VssBackupConfig::new(VSS_SERVER_URL.to_string(), vss_store_id, signing_key);

    wallet.configure_vss_backup(config.clone()).unwrap();

    let check_client = VssBackupClient::new(config).unwrap();

    // auto_backup defaults to false, so the client should reflect that
    assert!(
        !check_client.auto_backup(),
        "auto_backup should default to false"
    );

    // Trigger a state-changing operation
    let _address = wallet.get_address().unwrap();

    // Wait a bit to confirm no backup is triggered
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let version = check_client.get_backup_version().await.unwrap();
    assert!(
        version.is_none(),
        "No backup should exist when auto_backup is disabled"
    );

    wallet.disable_vss_auto_backup();
}
