use super::*;

use std::io::Read;

use crate::wallet::test::utils::vss::{
    VSS_KEY_CHUNK_PREFIX, VSS_KEY_DATA, VSS_KEY_MANIFEST, VSS_KEY_METADATA, VssBackupDeleteGuard,
    build_raw_vss_client, generate_signing_key_and_store_id, get_vss_key,
};
use crate::wallet::test::utils::vss::{dir_has_any_subdir, tokio_runtime, vss_server_url};

use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::secp256k1::rand::rngs::OsRng;

use crate::wallet::vss::{
    BackupManifest, VssBackupClient, VssBackupConfig, VssEncryptionMetadata, restore_from_vss,
};

use chacha20poly1305::aead::stream;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use sha2::Sha256;

const HKDF_INFO: &[u8] = b"rgb-lib-vss-backup-encryption-v1";
const BACKUP_BUFFER_LEN_ENCRYPT: usize = 239;
const BACKUP_BUFFER_LEN_DECRYPT: usize = BACKUP_BUFFER_LEN_ENCRYPT + 16;
const BACKUP_KEY_LENGTH: usize = 32;
const BACKUP_NONCE_LENGTH: usize = 19;

fn decrypt_bytes_with_signing_key(
    encrypted: &[u8],
    signing_key: &bdk_wallet::bitcoin::secp256k1::SecretKey,
    metadata: &VssEncryptionMetadata,
) -> Result<Vec<u8>, Error> {
    // Intentionally duplicates internal encryption logic:
    // restore_with_wrong_key may fail before download/decrypt due to sigs-auth.
    // This check validates crypto-layer failure with wrong key if bytes are obtained.
    let salt_bytes = hex::decode(&metadata.salt).map_err(|e| Error::Internal {
        details: format!("Invalid salt hex: {e}"),
    })?;
    let nonce_bytes = hex::decode(&metadata.nonce).map_err(|e| Error::Internal {
        details: format!("Invalid nonce hex: {e}"),
    })?;
    if nonce_bytes.len() != BACKUP_NONCE_LENGTH {
        return Err(Error::Internal {
            details: "Invalid nonce length".to_string(),
        });
    }

    let hk = Hkdf::<Sha256>::new(Some(&salt_bytes), &signing_key.secret_bytes());
    let mut key_bytes = [0u8; BACKUP_KEY_LENGTH];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| Error::Internal {
            details: format!("HKDF expansion failed: {e}"),
        })?;

    let aead = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce_bytes);
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce);

    let mut decrypted = Vec::new();
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_DECRYPT];
    let mut reader = std::io::Cursor::new(encrypted);

    loop {
        let read_count = reader.read(&mut buffer).map_err(|e| Error::Internal {
            details: format!("Failed to read data: {e}"),
        })?;

        if read_count == BACKUP_BUFFER_LEN_DECRYPT {
            let cleartext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|_| Error::VssError {
                    details: "decryption failed: wrong signing key or corrupted data".to_string(),
                })?;
            decrypted.extend(cleartext);
        } else if read_count == 0 {
            break;
        } else {
            let cleartext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|_| Error::VssError {
                    details: "decryption failed: wrong signing key or corrupted data".to_string(),
                })?;
            decrypted.extend(cleartext);
            break;
        }
    }

    Ok(decrypted)
}

fn looks_like_network_error(details: &str) -> bool {
    let d = details.to_lowercase();
    d.contains("connection refused")
        || d.contains("connect")
        || d.contains("dns")
        || d.contains("no such host")
        || d.contains("os error")
        || d.contains("timed out")
        || d.contains("timeout")
        || d.contains("error sending request")
        || d.contains("tcp connect error")
}

// Scenario 4.1: restore with a WRONG signing key must fail.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn scenario_4_1_wrong_signing_key_restore_fails_and_writes_no_wallet_data() {
    initialize();

    let rt = tokio_runtime();
    let vss_url = vss_server_url();

    let (mut wallet_a, online_a) = get_funded_wallet!();
    let (mut wallet_b, online_b) = get_empty_wallet!();

    // Create some RGB state.
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

    // Configure VSS with signing key A (encryption enabled by default).
    let (signing_key_a, store_id) = generate_signing_key_and_store_id("qa_neg_wrong_key");
    let config_a = VssBackupConfig::new(vss_url.clone(), store_id.clone(), signing_key_a);
    let _cleanup = VssBackupDeleteGuard::new(config_a.clone());
    let client_a = VssBackupClient::new(config_a.clone()).expect("VssBackupClient new");
    let raw_a = build_raw_vss_client(&vss_url, signing_key_a);

    let _ = rt
        .block_on(wallet_a.vss_backup(&client_a))
        .expect("vss_backup");

    // Attempt restore with signing key B (wrong).
    let secp = Secp256k1::new();
    let (signing_key_b, _) = secp.generate_keypair(&mut OsRng);
    let config_b = VssBackupConfig::new(vss_url.clone(), store_id.clone(), signing_key_b);

    // Manual crypto-layer check (if bytes can be obtained via auth key A).
    let manifest_bytes = rt
        .block_on(get_vss_key(&raw_a, &store_id, VSS_KEY_MANIFEST))
        .expect("manifest");
    let manifest: BackupManifest = serde_json::from_slice(&manifest_bytes).expect("manifest json");
    assert!(
        manifest.encrypted,
        "precondition: expected encrypted backup"
    );

    let encrypted_bytes = if manifest.chunk_count == 1 {
        rt.block_on(get_vss_key(&raw_a, &store_id, VSS_KEY_DATA))
            .expect("backup/data")
    } else {
        let mut data = Vec::with_capacity(manifest.total_size);
        for i in 0..manifest.chunk_count {
            let key = format!("{VSS_KEY_CHUNK_PREFIX}{i}");
            data.extend(
                rt.block_on(get_vss_key(&raw_a, &store_id, &key))
                    .expect("chunk bytes"),
            );
        }
        data
    };
    let metadata_bytes = rt
        .block_on(get_vss_key(&raw_a, &store_id, VSS_KEY_METADATA))
        .expect("metadata");
    let metadata: VssEncryptionMetadata =
        serde_json::from_slice(&metadata_bytes).expect("metadata json");
    match decrypt_bytes_with_signing_key(&encrypted_bytes, &signing_key_b, &metadata) {
        Ok(_) => panic!("Expected decryption to fail with wrong signing key, but it succeeded"),
        Err(Error::VssError { details }) => {
            assert!(
                details.to_lowercase().contains("decryption failed"),
                "Expected decryption failure, got: {details}"
            );
        }
        Err(e) => panic!("Expected VssError on decryption, got: {e:?}"),
    }

    // restore_from_vss() must fail and must not extract wallet dirs.
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let err = match rt.block_on(restore_from_vss(config_b, restore_root)) {
        Ok(p) => panic!(
            "Expected restore_from_vss to fail with wrong signing key, but it succeeded: {}",
            p.display()
        ),
        Err(e) => e,
    };
    match &err {
        Error::VssBackupNotFound | Error::VssAuth { .. } | Error::VssError { .. } => {}
        other => panic!("Expected VSS-related error, got: {other:?}"),
    }
    assert!(
        !dir_has_any_subdir(std::path::Path::new(restore_root)),
        "restore root must not contain any subdirectories on failure (only log files are expected)"
    );

    rt.block_on(client_a.delete_backup()).ok();
}

// Scenario 4.3: invalid/unreachable VSS URL -> vss_backup must fail after retries.
//
// Note: this reproduces the same bug as 4.2: a failed `vss_backup()` must not clear `backup_info`.
#[cfg(feature = "vss")]
#[test]
#[parallel]
#[ignore = "Blocked by known bug: failed vss_backup may incorrectly clear/flip backup_info; keep ignored until fixed."]
fn scenario_4_3_wrong_url_vss_backup_fails_and_keeps_backup_info() {
    // No `initialize()` needed: this scenario does not require regtest/electrs/proxy/VSS.
    let bad_url = std::env::var("VSS_SERVER_URL_BAD")
        .unwrap_or_else(|_| "http://127.0.0.1:1/vss".to_string());

    let rt = tokio_runtime();

    let keys = generate_keys(BitcoinNetwork::Regtest);
    // Keep tempdir alive for the entire test; Wallet::new requires the directory to exist.
    let tmp = tempfile::tempdir().expect("tempdir");
    let data_dir = tmp.path().to_str().unwrap().to_string();
    let mut wallet = Wallet::new(WalletData {
        data_dir,
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
        account_xpub_vanilla: keys.account_xpub_vanilla,
        account_xpub_colored: keys.account_xpub_colored,
        mnemonic: Some(keys.mnemonic),
        master_fingerprint: keys.master_fingerprint,
        vanilla_keychain: None,
        supported_schemas: vec![AssetSchema::Nia],
    })
    .expect("wallet new");

    let _ = wallet.get_address().expect("get_address");
    let backup_required_before = wallet.backup_info().expect("backup_info");
    assert!(
        backup_required_before,
        "precondition: expected backup_info=true before attempting VSS backup"
    );

    let secp = Secp256k1::new();
    let (signing_key, public_key) = secp.generate_keypair(&mut OsRng);
    let store_id = format!(
        "qa_neg_bad_url_{}",
        hex::encode(&public_key.serialize()[0..8])
    );
    let config = VssBackupConfig::new(bad_url, store_id, signing_key);
    let client = VssBackupClient::new(config).expect("VssBackupClient new");

    let start = std::time::Instant::now();
    let err = match rt.block_on(wallet.vss_backup(&client)) {
        Ok(v) => panic!("Expected vss_backup to fail, but it succeeded: {v}"),
        Err(e) => e,
    };
    let elapsed = start.elapsed();

    match &err {
        Error::VssError { details } => {
            assert!(
                looks_like_network_error(details),
                "Expected a network/connectivity error, got: {details}"
            );
        }
        other => panic!("Expected VssError, got: {other:?}"),
    }

    let backup_required_after = wallet.backup_info().expect("backup_info");
    assert_eq!(
        backup_required_after, backup_required_before,
        "BUG: backup_info changed after failed vss_backup (before={backup_required_before}, after={backup_required_after})"
    );

    assert!(
        elapsed < std::time::Duration::from_secs(8),
        "Unexpectedly long elapsed={elapsed:?}; possible hang / timeout too high"
    );
    let _ = tmp; // keep tempdir alive until the end
}

// Scenario 4.4: restore_from_vss() with a non-existent store_id must return "not found"
// and not extract any wallet data.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn scenario_4_4_restore_missing_store_id_is_not_found_and_extracts_nothing() {
    initialize();
    let vss_url = vss_server_url();
    let rt = tokio_runtime();

    let secp = Secp256k1::new();
    let (signing_key, public_key) = secp.generate_keypair(&mut OsRng);
    let store_id = format!(
        "qa_neg_missing_store_{}",
        hex::encode(&public_key.serialize()[0..8])
    );
    let config = VssBackupConfig::new(vss_url, store_id, signing_key);

    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();

    let start = std::time::Instant::now();
    let err = match rt.block_on(restore_from_vss(config, restore_root)) {
        Ok(p) => panic!(
            "Expected restore_from_vss to fail for missing store_id, but it succeeded: {}",
            p.display()
        ),
        Err(e) => e,
    };
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "restore_from_vss took unexpectedly long for missing store_id: {elapsed:?}"
    );

    match &err {
        Error::VssBackupNotFound => {}
        Error::VssError { details } => {
            let d = details.to_lowercase();
            assert!(
                d.contains("nosuchkey") || d.contains("not found") || d.contains("requested key"),
                "Expected a not-found style error, got: {details}"
            );
        }
        other => panic!("Expected VssBackupNotFound/VssError, got: {other:?}"),
    }

    assert!(
        !dir_has_any_subdir(std::path::Path::new(restore_root)),
        "restore root must not contain any subdirectories on failure (only log files are expected)"
    );
}
