//! VSS (Versioned Storage Service) backup module
//!
//! This module provides cloud backup functionality using VSS servers.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bdk_wallet::bitcoin::secp256k1::SecretKey;
// Note: this is the RustCrypto crate (streaming AEAD + XChaCha20). The similarly
// named `chacha20-poly1305` (rust-bitcoin, stateless-only) is a transitive dep
// of vss-client-ng via bitreq — they are not interchangeable.
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, aead::stream};
use hkdf::Hkdf;

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use slog::{Logger, debug, info};
use time::OffsetDateTime;
use vss_client::client::VssClient;
use vss_client::error::VssError;
use vss_client::headers::sigs_auth::SigsAuthProvider;
use vss_client::types::{GetObjectRequest, KeyValue, PutObjectRequest};
use vss_client::util::retry::{
    ExponentialBackoffRetryPolicy, MaxAttemptsRetryPolicy, MaxTotalDelayRetryPolicy, RetryPolicy,
};
use walkdir::WalkDir;
use zip::write::SimpleFileOptions;

use crate::error::Error;
use crate::utils::LOG_FILE;
use crate::utils::setup_logger;

/// Whether auto-backup uploads block the calling operation or run asynchronously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VssBackupMode {
    /// Upload runs on a spawned tokio task (fire-and-forget). Default.
    #[default]
    Async,
    /// Upload blocks the calling operation until the backup is persisted.
    Blocking,
}

/// Type alias for our retry policy
type VssRetryPolicy =
    MaxTotalDelayRetryPolicy<MaxAttemptsRetryPolicy<ExponentialBackoffRetryPolicy<VssError>>>;

// Encryption constants (matching backup.rs)
const BACKUP_BUFFER_LEN_ENCRYPT: usize = 239;
const BACKUP_BUFFER_LEN_DECRYPT: usize = BACKUP_BUFFER_LEN_ENCRYPT + 16;
const BACKUP_KEY_LENGTH: usize = 32;
const BACKUP_NONCE_LENGTH: usize = 19;
const VSS_BACKUP_VERSION: u8 = 1;

/// Default chunk size for large backups
/// Kept under the upstream vss-client-ng 10-second HTTP timeout
/// so that each chunk PUT completes reliably
pub(crate) const VSS_CHUNK_SIZE: usize = 1024 * 1024; // 1MB

/// Key prefix for backup data
const BACKUP_KEY_DATA: &str = "backup/data";
/// Key prefix for backup metadata (encryption params)
const BACKUP_KEY_METADATA: &str = "backup/metadata";
/// Key prefix for backup manifest (chunk info)
const BACKUP_KEY_MANIFEST: &str = "backup/manifest";
/// Key prefix for backup chunks
const BACKUP_KEY_CHUNK_PREFIX: &str = "backup/chunk/";
/// Key for storing wallet fingerprint separately
const BACKUP_KEY_FINGERPRINT: &str = "backup/fingerprint";
/// Generic directory name used in sanitized (plaintext) backups
const SANITIZED_DIR_NAME: &str = "wallet";
/// BDK database filename
const BDK_DB_NAME: &str = "bdk_db";
/// BDK watch-only database filename
const BDK_DB_WO_NAME: &str = "bdk_db_watch_only";

/// Salt length for HKDF key derivation (32 bytes, hex-encoded = 64 chars)
const BACKUP_SALT_LENGTH: usize = 32;

/// Encryption metadata stored alongside encrypted backups
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VssEncryptionMetadata {
    /// Salt used for HKDF key derivation (hex encoded)
    pub salt: String,
    /// Nonce used for encryption
    pub nonce: String,
    /// Version of the encryption format
    pub version: u8,
}

impl VssEncryptionMetadata {
    /// Create new encryption metadata with random salt and nonce
    fn new() -> Self {
        let salt: [u8; BACKUP_SALT_LENGTH] = rand::random();
        let nonce: [u8; BACKUP_NONCE_LENGTH] = rand::random();

        Self {
            salt: hex::encode(salt),
            nonce: hex::encode(nonce),
            version: VSS_BACKUP_VERSION,
        }
    }

    fn nonce_bytes(&self) -> Result<[u8; BACKUP_NONCE_LENGTH], Error> {
        let bytes = hex::decode(&self.nonce).map_err(|e| Error::Internal {
            details: format!("Invalid nonce hex: {e}"),
        })?;
        bytes[0..BACKUP_NONCE_LENGTH]
            .try_into()
            .map_err(|_| Error::Internal {
                details: "Invalid nonce length".to_string(),
            })
    }
}

/// Configuration for VSS backup service
#[derive(Clone)]
pub struct VssBackupConfig {
    /// VSS server URL
    pub(crate) server_url: String,
    /// Store ID (namespace for this wallet's data)
    pub(crate) store_id: String,
    /// Private key for signing requests and deriving encryption key
    pub(crate) signing_key: SecretKey,
    /// Whether to encrypt data before uploading (default: true)
    pub(crate) encryption_enabled: bool,
    /// Whether to automatically back up after state-changing operations (default: false)
    pub(crate) auto_backup: bool,
    /// Whether auto-backup uploads block the caller or run asynchronously (default: Async)
    pub(crate) backup_mode: VssBackupMode,
}

impl VssBackupConfig {
    /// Create a new VSS backup configuration
    ///
    /// Encryption is enabled by default. The encryption key is derived from the
    /// signing key using HKDF-SHA256, so no separate password is needed.
    pub fn new(server_url: String, store_id: String, signing_key: SecretKey) -> Self {
        Self {
            server_url,
            store_id,
            signing_key,
            encryption_enabled: true,
            auto_backup: false,
            backup_mode: VssBackupMode::default(),
        }
    }

    /// Set encryption enabled/disabled
    pub fn with_encryption(mut self, enabled: bool) -> Self {
        self.encryption_enabled = enabled;
        self
    }

    /// Enable or disable automatic backups after state-changing operations
    pub fn with_auto_backup(mut self, enabled: bool) -> Self {
        self.auto_backup = enabled;
        self
    }

    /// Set the auto-backup mode (Async or Blocking)
    pub fn with_backup_mode(mut self, mode: VssBackupMode) -> Self {
        self.backup_mode = mode;
        self
    }
}

/// Backup manifest for tracking chunked backups
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupManifest {
    /// Number of chunks
    pub chunk_count: usize,
    /// Total size in bytes
    pub total_size: usize,
    /// Whether the backup is encrypted
    pub encrypted: bool,
    /// Backup version
    pub version: u8,
}

/// VSS backup client wrapper
pub struct VssBackupClient {
    client: VssClient<VssRetryPolicy>,
    store_id: String,
    encryption_enabled: bool,
    signing_key: SecretKey,
    auto_backup: bool,
    backup_mode: VssBackupMode,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for VssBackupClient {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl VssBackupClient {
    /// Create a new VSS backup client
    pub fn new(config: VssBackupConfig) -> Result<Self, Error> {
        let auth_provider = SigsAuthProvider::new(config.signing_key, HashMap::new());

        let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100))
            .with_max_attempts(3)
            .with_max_total_delay(Duration::from_secs(5));

        let client =
            VssClient::new_with_headers(config.server_url, retry_policy, Arc::new(auth_provider));

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .map_err(|e| Error::Internal {
                details: format!("Failed to create tokio runtime: {e}"),
            })?;

        Ok(Self {
            client,
            store_id: config.store_id,
            encryption_enabled: config.encryption_enabled,
            signing_key: config.signing_key,
            auto_backup: config.auto_backup,
            backup_mode: config.backup_mode,
            runtime: Some(runtime),
        })
    }

    /// Get a handle to the client's tokio runtime
    pub fn handle(&self) -> &tokio::runtime::Handle {
        self.runtime
            .as_ref()
            .expect("runtime not available")
            .handle()
    }

    /// Upload backup data to VSS server
    ///
    /// If encryption is enabled, data will be encrypted before upload.
    /// The encryption key is derived from the signing key using HKDF-SHA256.
    ///
    /// If encryption is disabled, the backup is sanitized to exclude sensitive
    /// data (master fingerprint in paths, BDK database with xpubs). The
    /// fingerprint is stored separately for use during restore.
    ///
    /// Returns the version number of the uploaded backup.
    pub async fn upload_backup(&self, data: Vec<u8>) -> Result<i64, Error> {
        // Extract fingerprint from zip data
        let fingerprint = get_fingerprint_from_zip_bytes(&data)?;

        // Encrypt or sanitize data
        let (upload_data, encryption_metadata) = if self.encryption_enabled {
            let metadata = VssEncryptionMetadata::new();
            let encrypted = encrypt_data(&data, &self.signing_key, &metadata)?;
            (encrypted, Some(metadata))
        } else {
            // Sanitize for plaintext: remove fingerprint from paths, exclude bdk_db
            let (sanitized, _) = sanitize_zip_for_plaintext(&data)?;
            (sanitized, None)
        };

        let total_size = upload_data.len();

        if total_size <= VSS_CHUNK_SIZE {
            // Single chunk upload
            self.upload_single(upload_data, encryption_metadata, &fingerprint)
                .await
        } else {
            // Chunked upload for large backups
            self.upload_chunked(upload_data, encryption_metadata, &fingerprint)
                .await
        }
    }

    /// Upload a single backup (non-chunked)
    async fn upload_single(
        &self,
        data: Vec<u8>,
        encryption_metadata: Option<VssEncryptionMetadata>,
        fingerprint: &str,
    ) -> Result<i64, Error> {
        // VSS versioning: version field is the expected current version (optimistic locking)
        // For new keys: version = 0 (no current version)
        // For updates: version = current_version (server will increment to current_version + 1)
        let data_version = self
            .get_current_version(BACKUP_KEY_DATA)
            .await?
            .unwrap_or(0);

        let manifest = BackupManifest {
            chunk_count: 1,
            total_size: data.len(),
            encrypted: encryption_metadata.is_some(),
            version: VSS_BACKUP_VERSION,
        };
        let manifest_json = serde_json::to_vec(&manifest).map_err(|e| Error::Internal {
            details: format!("Failed to serialize manifest: {e}"),
        })?;

        let manifest_version = self
            .get_current_version(BACKUP_KEY_MANIFEST)
            .await?
            .unwrap_or(0);

        let fingerprint_version = self
            .get_current_version(BACKUP_KEY_FINGERPRINT)
            .await?
            .unwrap_or(0);

        let mut transaction_items = vec![
            KeyValue {
                key: BACKUP_KEY_DATA.to_string(),
                version: data_version,
                value: data,
            },
            KeyValue {
                key: BACKUP_KEY_MANIFEST.to_string(),
                version: manifest_version,
                value: manifest_json,
            },
            KeyValue {
                key: BACKUP_KEY_FINGERPRINT.to_string(),
                version: fingerprint_version,
                value: fingerprint.as_bytes().to_vec(),
            },
        ];

        // Add encryption metadata if present
        if let Some(metadata) = encryption_metadata {
            let metadata_json = serde_json::to_vec(&metadata).map_err(|e| Error::Internal {
                details: format!("Failed to serialize encryption metadata: {e}"),
            })?;
            let metadata_version = self
                .get_current_version(BACKUP_KEY_METADATA)
                .await?
                .unwrap_or(0);
            transaction_items.push(KeyValue {
                key: BACKUP_KEY_METADATA.to_string(),
                version: metadata_version,
                value: metadata_json,
            });
        }

        let request = PutObjectRequest {
            store_id: self.store_id.clone(),
            global_version: None,
            transaction_items,
            delete_items: vec![],
        };

        self.client
            .put_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        // Server increments version, so return expected new version
        Ok(data_version + 1)
    }

    /// Upload a chunked backup for large data
    ///
    /// Each chunk is uploaded in a separate request to avoid sending the entire
    /// backup in a single HTTP body. The manifest is uploaded last so that a
    /// partial failure leaves the previous manifest (and thus the previous
    /// valid backup) intact. Orphaned chunks from a failed partial upload are
    /// harmlessly overwritten on the next backup attempt.
    async fn upload_chunked(
        &self,
        data: Vec<u8>,
        encryption_metadata: Option<VssEncryptionMetadata>,
        fingerprint: &str,
    ) -> Result<i64, Error> {
        let chunks: Vec<&[u8]> = data.chunks(VSS_CHUNK_SIZE).collect();
        let chunk_count = chunks.len();
        let total_size = data.len();

        // Upload each chunk in a separate request
        for (i, chunk) in chunks.iter().enumerate() {
            let key = format!("{}{}", BACKUP_KEY_CHUNK_PREFIX, i);
            let chunk_version = self.get_current_version(&key).await?.unwrap_or(0);

            let request = PutObjectRequest {
                store_id: self.store_id.clone(),
                global_version: None,
                transaction_items: vec![KeyValue {
                    key,
                    version: chunk_version,
                    value: chunk.to_vec(),
                }],
                delete_items: vec![],
            };

            self.client
                .put_object(&request)
                .await
                .map_err(vss_error_to_rgb_error)?;
        }

        // Upload manifest + fingerprint + metadata atomically (small, logically related)
        let manifest = BackupManifest {
            chunk_count,
            total_size,
            encrypted: encryption_metadata.is_some(),
            version: VSS_BACKUP_VERSION,
        };
        let manifest_json = serde_json::to_vec(&manifest).map_err(|e| Error::Internal {
            details: format!("Failed to serialize manifest: {e}"),
        })?;
        let manifest_version = self
            .get_current_version(BACKUP_KEY_MANIFEST)
            .await?
            .unwrap_or(0);

        let fingerprint_version = self
            .get_current_version(BACKUP_KEY_FINGERPRINT)
            .await?
            .unwrap_or(0);

        let mut transaction_items = vec![
            KeyValue {
                key: BACKUP_KEY_MANIFEST.to_string(),
                version: manifest_version,
                value: manifest_json,
            },
            KeyValue {
                key: BACKUP_KEY_FINGERPRINT.to_string(),
                version: fingerprint_version,
                value: fingerprint.as_bytes().to_vec(),
            },
        ];

        if let Some(metadata) = encryption_metadata {
            let metadata_json = serde_json::to_vec(&metadata).map_err(|e| Error::Internal {
                details: format!("Failed to serialize encryption metadata: {e}"),
            })?;
            let metadata_version = self
                .get_current_version(BACKUP_KEY_METADATA)
                .await?
                .unwrap_or(0);
            transaction_items.push(KeyValue {
                key: BACKUP_KEY_METADATA.to_string(),
                version: metadata_version,
                value: metadata_json,
            });
        }

        let request = PutObjectRequest {
            store_id: self.store_id.clone(),
            global_version: None,
            transaction_items,
            delete_items: vec![],
        };

        self.client
            .put_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        Ok(manifest_version + 1)
    }

    /// Download backup data from VSS server
    ///
    /// If the backup was encrypted, it will be decrypted using a key derived from
    /// the signing key via HKDF-SHA256.
    pub async fn download_backup(&self) -> Result<Vec<u8>, Error> {
        // First get the manifest
        let manifest = self.get_manifest().await?;

        // Download the raw data
        let raw_data = if manifest.chunk_count == 1 {
            self.download_single().await?
        } else {
            self.download_chunked(&manifest).await?
        };

        // Decrypt if the backup was encrypted
        if manifest.encrypted {
            let metadata = self.get_encryption_metadata().await?;
            decrypt_data(&raw_data, &self.signing_key, &metadata)
        } else {
            Ok(raw_data)
        }
    }

    /// Download a single backup (non-chunked)
    async fn download_single(&self) -> Result<Vec<u8>, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: BACKUP_KEY_DATA.to_string(),
        };

        let response = self
            .client
            .get_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        response
            .value
            .map(|kv| kv.value)
            .ok_or(Error::VssBackupNotFound)
    }

    /// Download a chunked backup
    async fn download_chunked(&self, manifest: &BackupManifest) -> Result<Vec<u8>, Error> {
        let mut data = Vec::with_capacity(manifest.total_size);

        for i in 0..manifest.chunk_count {
            let key = format!("{}{}", BACKUP_KEY_CHUNK_PREFIX, i);
            let request = GetObjectRequest {
                store_id: self.store_id.clone(),
                key,
            };

            let response = self
                .client
                .get_object(&request)
                .await
                .map_err(vss_error_to_rgb_error)?;

            let chunk = response
                .value
                .map(|kv| kv.value)
                .ok_or(Error::VssBackupNotFound)?;

            data.extend(chunk);
        }

        Ok(data)
    }

    /// Get the backup manifest
    async fn get_manifest(&self) -> Result<BackupManifest, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: BACKUP_KEY_MANIFEST.to_string(),
        };

        let response = self
            .client
            .get_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        let manifest_bytes = response
            .value
            .map(|kv| kv.value)
            .ok_or(Error::VssBackupNotFound)?;

        serde_json::from_slice(&manifest_bytes).map_err(|e| Error::Internal {
            details: format!("Failed to parse backup manifest: {e}"),
        })
    }

    /// Get the encryption metadata
    async fn get_encryption_metadata(&self) -> Result<VssEncryptionMetadata, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: BACKUP_KEY_METADATA.to_string(),
        };

        let response = self
            .client
            .get_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        let metadata_bytes = response
            .value
            .map(|kv| kv.value)
            .ok_or(Error::VssBackupNotFound)?;

        serde_json::from_slice(&metadata_bytes).map_err(|e| Error::Internal {
            details: format!("Failed to parse encryption metadata: {e}"),
        })
    }

    /// Get the current version of a backup
    ///
    /// Returns `None` if no backup exists, otherwise returns the version number.
    pub async fn get_backup_version(&self) -> Result<Option<i64>, Error> {
        self.get_current_version(BACKUP_KEY_MANIFEST).await
    }

    /// Get the wallet fingerprint stored on the server
    async fn get_fingerprint(&self) -> Result<String, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: BACKUP_KEY_FINGERPRINT.to_string(),
        };

        let response = self
            .client
            .get_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        let fingerprint_bytes = response
            .value
            .map(|kv| kv.value)
            .ok_or(Error::VssBackupNotFound)?;

        String::from_utf8(fingerprint_bytes).map_err(|e| Error::Internal {
            details: format!("Invalid fingerprint encoding: {e}"),
        })
    }

    /// Get the current version of a key
    async fn get_current_version(&self, key: &str) -> Result<Option<i64>, Error> {
        let request = GetObjectRequest {
            store_id: self.store_id.clone(),
            key: key.to_string(),
        };

        match self.client.get_object(&request).await {
            Ok(response) => Ok(response.value.map(|kv| kv.version)),
            Err(VssError::NoSuchKeyError(_)) => Ok(None),
            Err(e) => Err(vss_error_to_rgb_error(e)),
        }
    }

    /// Delete the backup from VSS server
    pub async fn delete_backup(&self) -> Result<(), Error> {
        // Get manifest to know what to delete
        let manifest = match self.get_manifest().await {
            Ok(m) => m,
            Err(_) => return Ok(()), // No backup to delete
        };

        let mut delete_items = vec![];

        // Delete chunks if any
        if manifest.chunk_count > 1 {
            for i in 0..manifest.chunk_count {
                let key = format!("{}{}", BACKUP_KEY_CHUNK_PREFIX, i);
                if let Some(version) = self.get_current_version(&key).await? {
                    delete_items.push(KeyValue {
                        key,
                        version,
                        value: vec![],
                    });
                }
            }
        } else {
            // Delete single data key
            if let Some(version) = self.get_current_version(BACKUP_KEY_DATA).await? {
                delete_items.push(KeyValue {
                    key: BACKUP_KEY_DATA.to_string(),
                    version,
                    value: vec![],
                });
            }
        }

        // Delete manifest
        if let Some(version) = self.get_current_version(BACKUP_KEY_MANIFEST).await? {
            delete_items.push(KeyValue {
                key: BACKUP_KEY_MANIFEST.to_string(),
                version,
                value: vec![],
            });
        }

        // Delete metadata if exists
        if let Some(version) = self.get_current_version(BACKUP_KEY_METADATA).await? {
            delete_items.push(KeyValue {
                key: BACKUP_KEY_METADATA.to_string(),
                version,
                value: vec![],
            });
        }

        // Delete fingerprint if exists
        if let Some(version) = self.get_current_version(BACKUP_KEY_FINGERPRINT).await? {
            delete_items.push(KeyValue {
                key: BACKUP_KEY_FINGERPRINT.to_string(),
                version,
                value: vec![],
            });
        }

        if delete_items.is_empty() {
            return Ok(());
        }

        let request = PutObjectRequest {
            store_id: self.store_id.clone(),
            global_version: None,
            transaction_items: vec![],
            delete_items,
        };

        self.client
            .put_object(&request)
            .await
            .map_err(vss_error_to_rgb_error)?;

        Ok(())
    }

    /// Check if encryption is enabled
    #[must_use]
    pub fn encryption_enabled(&self) -> bool {
        self.encryption_enabled
    }

    /// Check if auto-backup is enabled
    #[must_use]
    pub fn auto_backup(&self) -> bool {
        self.auto_backup
    }

    /// Get the configured backup mode
    #[must_use]
    pub fn backup_mode(&self) -> VssBackupMode {
        self.backup_mode
    }
}

/// HKDF info string for domain separation
const HKDF_INFO: &[u8] = b"rgb-lib-vss-backup-encryption-v1";

/// Derive encryption key from signing key using HKDF-SHA256
fn derive_encryption_key(
    signing_key: &SecretKey,
    metadata: &VssEncryptionMetadata,
) -> Result<Key, Error> {
    let salt_bytes = hex::decode(&metadata.salt).map_err(|e| Error::Internal {
        details: format!("Invalid salt hex: {e}"),
    })?;

    let hk = Hkdf::<Sha256>::new(Some(&salt_bytes), &signing_key.secret_bytes());

    let mut key_bytes = [0u8; BACKUP_KEY_LENGTH];
    hk.expand(HKDF_INFO, &mut key_bytes)
        .map_err(|e| Error::Internal {
            details: format!("HKDF expansion failed: {e}"),
        })?;

    Ok(Key::clone_from_slice(&key_bytes))
}

/// Encrypt data using XChaCha20-Poly1305
fn encrypt_data(
    data: &[u8],
    signing_key: &SecretKey,
    metadata: &VssEncryptionMetadata,
) -> Result<Vec<u8>, Error> {
    let key = derive_encryption_key(signing_key, metadata)?;
    let aead = XChaCha20Poly1305::new(&key);
    let nonce = metadata.nonce_bytes()?;
    let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce);

    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce);
    let mut encrypted = Vec::new();
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_ENCRYPT];
    let mut reader = std::io::Cursor::new(data);

    loop {
        let read_count = reader.read(&mut buffer).map_err(|e| Error::Internal {
            details: format!("Failed to read data: {e}"),
        })?;

        if read_count == BACKUP_BUFFER_LEN_ENCRYPT {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|e| Error::Internal {
                    details: format!("Encryption error: {e}"),
                })?;
            encrypted.extend(ciphertext);
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|e| Error::Internal {
                    details: format!("Encryption error: {e}"),
                })?;
            encrypted.extend(ciphertext);
            break;
        }
    }

    Ok(encrypted)
}

/// Decrypt data using XChaCha20-Poly1305
fn decrypt_data(
    encrypted: &[u8],
    signing_key: &SecretKey,
    metadata: &VssEncryptionMetadata,
) -> Result<Vec<u8>, Error> {
    let key = derive_encryption_key(signing_key, metadata)?;
    let aead = XChaCha20Poly1305::new(&key);
    let nonce = metadata.nonce_bytes()?;
    let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&nonce);

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

/// Convert VSS error to RGB-lib error
fn vss_error_to_rgb_error(e: VssError) -> Error {
    match e {
        VssError::NoSuchKeyError(_) => Error::VssBackupNotFound,
        VssError::ConflictError(msg) => Error::VssVersionConflict { details: msg },
        VssError::AuthError(msg) => Error::VssAuth { details: msg },
        VssError::InternalServerError(msg) => Error::VssError {
            details: format!("Server error: {msg}"),
        },
        VssError::InvalidRequestError(msg) => Error::VssError {
            details: format!("Invalid request: {msg}"),
        },
        _ => Error::VssError {
            details: e.to_string(),
        },
    }
}

/// VSS backup info returned by `vss_backup_info()`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssBackupInfo {
    /// Whether a backup exists on the server
    pub backup_exists: bool,
    /// Server-side version of the backup
    pub server_version: Option<i64>,
    /// Whether the local wallet has changes since last backup
    pub backup_required: bool,
}

/// Create a zip archive of a wallet directory in memory
fn zip_wallet_to_bytes(wallet_dir: &Path, logger: &Logger) -> Result<Vec<u8>, Error> {
    let mut buffer = std::io::Cursor::new(Vec::new());

    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);
        let mut file_buffer = [0u8; 4096];

        // Get the parent directory to preserve wallet fingerprint in zip
        let prefix = wallet_dir.parent().ok_or_else(|| Error::Internal {
            details: "Wallet directory has no parent".to_string(),
        })?;

        let entry_iterator = WalkDir::new(wallet_dir).into_iter().filter_map(|e| e.ok());

        for entry in entry_iterator {
            let path = entry.path();
            let name = path.strip_prefix(prefix).map_err(|e| Error::Internal {
                details: format!("Failed to strip prefix: {e}"),
            })?;
            let name_str = name.to_str().ok_or_else(|| Error::Internal {
                details: "Invalid path encoding".to_string(),
            })?;

            if path.is_file() {
                // Skip log file
                if path.ends_with(LOG_FILE) {
                    continue;
                }
                debug!(logger, "VSS backup: adding file {:?}", name);
                zip.start_file(name_str, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add file to zip: {e}"),
                    })?;

                let mut f = fs::File::open(path)?;
                loop {
                    let read_count = f.read(&mut file_buffer)?;
                    if read_count != 0 {
                        zip.write_all(&file_buffer[..read_count])?;
                    } else {
                        break;
                    }
                }
            } else if !name.as_os_str().is_empty() {
                debug!(logger, "VSS backup: adding directory {:?}", name);
                zip.add_directory(name_str, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add directory to zip: {e}"),
                    })?;
            }
        }

        zip.finish().map_err(|e| Error::Internal {
            details: format!("Failed to finalize zip: {e}"),
        })?;
    }

    Ok(buffer.into_inner())
}

/// Extract the wallet fingerprint from a zip archive
///
/// Wallet fingerprints are 4-byte BIP32 fingerprints displayed as 8 lowercase
/// hex characters (e.g., `"a1b2c3d4"`).
fn get_fingerprint_from_zip_bytes(data: &[u8]) -> Result<String, Error> {
    let reader = std::io::Cursor::new(data);
    let archive = zip::ZipArchive::new(reader).map_err(|e| Error::Internal {
        details: format!("Failed to read zip archive: {e}"),
    })?;

    let first_entry = archive.name_for_index(0).unwrap_or_default();
    let fingerprint = first_entry.trim_end_matches('/').to_string();

    // Validate: wallet fingerprints are 8 hex characters (4 bytes)
    if fingerprint.len() != 8 || hex::decode(&fingerprint).is_err() {
        return Err(Error::Internal {
            details: format!("Invalid wallet fingerprint in zip: '{fingerprint}'"),
        });
    }

    Ok(fingerprint)
}

/// Check if a zip entry path is a BDK database file (contains xpubs in descriptors)
fn is_bdk_db_file(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    filename == BDK_DB_NAME || filename == BDK_DB_WO_NAME
}

/// Sanitize a wallet zip for plaintext (unencrypted) backup
///
/// Removes sensitive data that should not be stored unencrypted:
/// - Replaces the master fingerprint directory name with a generic "wallet/" name
/// - Excludes BDK database files (bdk_db, bdk_db_watch_only) which contain xpubs
///
/// Returns the sanitized zip bytes and the extracted fingerprint.
fn sanitize_zip_for_plaintext(data: &[u8]) -> Result<(Vec<u8>, String), Error> {
    let fingerprint = get_fingerprint_from_zip_bytes(data)?;

    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| Error::Internal {
        details: format!("Failed to read zip archive: {e}"),
    })?;

    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip_writer = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);

        for i in 0..archive.len() {
            let mut file = archive.by_index(i).map_err(|e| Error::Internal {
                details: format!("Failed to read zip entry: {e}"),
            })?;

            let original_name = file.name().to_string();

            // Skip BDK database files (contain xpubs in descriptors)
            if is_bdk_db_file(&original_name) {
                continue;
            }

            // Replace fingerprint with generic directory name
            let sanitized_name = original_name.replacen(&fingerprint, SANITIZED_DIR_NAME, 1);

            if file.is_dir() {
                zip_writer
                    .add_directory(&sanitized_name, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add directory to sanitized zip: {e}"),
                    })?;
            } else {
                zip_writer
                    .start_file(&sanitized_name, options)
                    .map_err(|e| Error::Internal {
                        details: format!("Failed to add file to sanitized zip: {e}"),
                    })?;
                std::io::copy(&mut file, &mut zip_writer)?;
            }
        }

        zip_writer.finish().map_err(|e| Error::Internal {
            details: format!("Failed to finalize sanitized zip: {e}"),
        })?;
    }

    Ok((buffer.into_inner(), fingerprint))
}

/// Unzip wallet data to a target directory
fn unzip_wallet_from_bytes(data: &[u8], target_dir: &Path, logger: &Logger) -> Result<(), Error> {
    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| Error::Internal {
        details: format!("Failed to read zip archive: {e}"),
    })?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| Error::Internal {
            details: format!("Failed to read zip entry: {e}"),
        })?;

        let outpath = match file.enclosed_name() {
            Some(path) => target_dir.join(path),
            None => continue,
        };

        if file.name().ends_with('/') {
            debug!(logger, "VSS restore: creating directory {:?}", outpath);
            fs::create_dir_all(&outpath)?;
        } else {
            debug!(
                logger,
                "VSS restore: extracting file {:?} ({} bytes)",
                outpath,
                file.size()
            );
            if let Some(p) = outpath.parent()
                && !p.exists()
            {
                fs::create_dir_all(p)?;
            }
            let mut outfile = fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

/// Restore a wallet from VSS backup
///
/// Downloads the backup from the VSS server and extracts it to the target directory.
/// For encrypted backups, the fingerprint is embedded in the zip entry paths.
/// For plaintext backups, the fingerprint is fetched from a separate server key
/// and the sanitized "wallet/" directory is renamed to the actual fingerprint.
///
/// Returns the path to the restored wallet directory.
pub async fn restore_from_vss(config: VssBackupConfig, target_dir: &str) -> Result<PathBuf, Error> {
    fs::create_dir_all(target_dir)?;
    let log_dir = Path::new(target_dir);
    let log_name = format!("vss_restore_{}", OffsetDateTime::now_utc().unix_timestamp());
    let (logger, _logger_guard) = setup_logger(log_dir, Some(&log_name))?;

    info!(logger, "Starting VSS restore...");
    info!(logger, "Server URL: {}", config.server_url);
    info!(logger, "Store ID: {}", config.store_id);

    // Create VSS client and download backup
    let client = VssBackupClient::new(config)?;

    // Check manifest to determine if backup is encrypted
    let manifest = client.get_manifest().await?;

    info!(logger, "Downloading backup from VSS server...");
    let backup_data = client.download_backup().await?;
    info!(
        logger,
        "Downloaded {} bytes ({:.2} MB)",
        backup_data.len(),
        backup_data.len() as f64 / 1_000_000.0
    );

    // Get fingerprint from server (stored during upload)
    let fingerprint = client.get_fingerprint().await?;
    info!(logger, "Wallet fingerprint: {}", fingerprint);

    let target_dir_path = PathBuf::from(target_dir);
    let wallet_dir = target_dir_path.join(&fingerprint);

    // Check if wallet already exists
    if wallet_dir.exists() {
        return Err(Error::WalletDirAlreadyExists {
            path: wallet_dir.to_string_lossy().to_string(),
        });
    }

    // Extract backup
    info!(logger, "Extracting backup to {:?}", target_dir_path);
    unzip_wallet_from_bytes(&backup_data, &target_dir_path, &logger)?;

    // For non-encrypted backups, the zip uses "wallet/" as the directory name
    // instead of the real fingerprint. Rename it back.
    if !manifest.encrypted {
        let sanitized_dir = target_dir_path.join(SANITIZED_DIR_NAME);
        if sanitized_dir.exists() {
            info!(
                logger,
                "Renaming sanitized directory {:?} to {:?}", sanitized_dir, wallet_dir
            );
            fs::rename(&sanitized_dir, &wallet_dir)?;
        }
    }

    info!(logger, "VSS restore completed successfully");
    Ok(wallet_dir)
}

/// Create backup data from a wallet directory
///
/// This is a helper function used by Wallet::vss_backup()
pub fn create_backup_data(wallet_dir: &Path, logger: &Logger) -> Result<Vec<u8>, Error> {
    info!(logger, "Creating VSS backup data from {:?}", wallet_dir);
    let data = zip_wallet_to_bytes(wallet_dir, logger)?;
    info!(
        logger,
        "Backup data created: {} bytes ({:.2} MB)",
        data.len(),
        data.len() as f64 / 1_000_000.0
    );
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, rand::rngs::OsRng};

    fn test_signing_key() -> SecretKey {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut OsRng);
        sk
    }

    #[test]
    fn test_backup_manifest_serialization() {
        let manifest = BackupManifest {
            chunk_count: 5,
            total_size: 20_000_000,
            encrypted: true,
            version: 1,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: BackupManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.chunk_count, 5);
        assert_eq!(parsed.total_size, 20_000_000);
        assert!(parsed.encrypted);
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn test_encryption_metadata_serialization() {
        let metadata = VssEncryptionMetadata::new();

        let json = serde_json::to_string(&metadata).unwrap();
        let parsed: VssEncryptionMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, VSS_BACKUP_VERSION);
        assert_eq!(parsed.nonce.len(), BACKUP_NONCE_LENGTH * 2);
        assert!(!parsed.salt.is_empty());
        // Salt should be valid hex (64 chars for 32 bytes)
        assert_eq!(parsed.salt.len(), BACKUP_SALT_LENGTH * 2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original_data = b"Hello, this is test data for encryption!".to_vec();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        // Encrypt
        let encrypted = encrypt_data(&original_data, &key, &metadata).unwrap();
        assert_ne!(encrypted, original_data);

        // Decrypt
        let decrypted = decrypt_data(&encrypted, &key, &metadata).unwrap();
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_large_data() {
        // Test with data larger than buffer size
        let original_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_wrong_key_fails() {
        let original_data = b"Secret data".to_vec();
        let correct_key = test_signing_key();
        let wrong_key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &correct_key, &metadata).unwrap();
        let result = decrypt_data(&encrypted, &wrong_key, &metadata);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_empty_data() {
        let original_data: Vec<u8> = vec![];
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_exact_buffer_size() {
        // Test with data exactly at buffer boundary
        let original_data: Vec<u8> = (0..BACKUP_BUFFER_LEN_ENCRYPT)
            .map(|i| (i % 256) as u8)
            .collect();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_buffer_sizes() {
        // Test with data that spans multiple buffer reads
        let original_data: Vec<u8> = (0..(BACKUP_BUFFER_LEN_ENCRYPT * 3 + 50))
            .map(|i| (i % 256) as u8)
            .collect();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let encrypted = encrypt_data(&original_data, &key, &metadata).unwrap();
        let decrypted = decrypt_data(&encrypted, &key, &metadata).unwrap();

        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_decrypt_corrupted_data_fails() {
        let original_data = b"Test data for corruption test".to_vec();
        let key = test_signing_key();

        let metadata = VssEncryptionMetadata::new();

        let mut encrypted = encrypt_data(&original_data, &key, &metadata).unwrap();

        // Corrupt the encrypted data
        if !encrypted.is_empty() {
            let mid = encrypted.len() / 2;
            encrypted[mid] ^= 0xFF;
        }

        let result = decrypt_data(&encrypted, &key, &metadata);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_salts_produce_different_keys() {
        let key = test_signing_key();
        let metadata1 = VssEncryptionMetadata::new();
        let metadata2 = VssEncryptionMetadata::new();

        let derived1 = derive_encryption_key(&key, &metadata1).unwrap();
        let derived2 = derive_encryption_key(&key, &metadata2).unwrap();

        // Different random salts should produce different derived keys
        assert_ne!(derived1, derived2);
    }

    #[test]
    fn test_backup_manifest_chunk_calculation() {
        // Test that chunk count calculation is correct
        let small_size = VSS_CHUNK_SIZE - 1;
        let exact_size = VSS_CHUNK_SIZE;
        let large_size = VSS_CHUNK_SIZE * 2 + 100;

        assert_eq!(small_size.div_ceil(VSS_CHUNK_SIZE), 1);
        assert_eq!(exact_size.div_ceil(VSS_CHUNK_SIZE), 1);
        assert_eq!(large_size.div_ceil(VSS_CHUNK_SIZE), 3);
    }

    #[test]
    fn test_is_bdk_db_file() {
        assert!(is_bdk_db_file("bdk_db"));
        assert!(is_bdk_db_file("bdk_db_watch_only"));
        assert!(is_bdk_db_file("abc123/bdk_db"));
        assert!(is_bdk_db_file("abc123/bdk_db_watch_only"));
        assert!(is_bdk_db_file("some/deep/path/bdk_db"));

        assert!(!is_bdk_db_file("bdk_db_other"));
        assert!(!is_bdk_db_file("not_bdk_db"));
        assert!(!is_bdk_db_file("abc123/some_file.txt"));
        assert!(!is_bdk_db_file(""));
    }

    /// Helper: create a test zip with a fingerprint directory structure
    fn create_test_zip(fingerprint: &str) -> Vec<u8> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

            // Add fingerprint directory
            zip.add_directory(format!("{fingerprint}/"), options)
                .unwrap();

            // Add a normal file
            zip.start_file(format!("{fingerprint}/some_file.txt"), options)
                .unwrap();
            zip.write_all(b"test content").unwrap();

            // Add bdk_db file
            zip.start_file(format!("{fingerprint}/bdk_db"), options)
                .unwrap();
            zip.write_all(b"xpub_sensitive_data").unwrap();

            // Add bdk_db_watch_only file
            zip.start_file(format!("{fingerprint}/bdk_db_watch_only"), options)
                .unwrap();
            zip.write_all(b"xpub_watch_only_data").unwrap();

            // Add a nested file
            zip.add_directory(format!("{fingerprint}/subdir/"), options)
                .unwrap();
            zip.start_file(format!("{fingerprint}/subdir/nested.dat"), options)
                .unwrap();
            zip.write_all(b"nested data").unwrap();

            zip.finish().unwrap();
        }
        buffer.into_inner()
    }

    #[test]
    fn test_sanitize_zip_for_plaintext() {
        let fingerprint = "a1b2c3d4";
        let zip_data = create_test_zip(fingerprint);

        let (sanitized, extracted_fp) = sanitize_zip_for_plaintext(&zip_data).unwrap();
        assert_eq!(extracted_fp, fingerprint);

        // Inspect sanitized zip
        let reader = std::io::Cursor::new(&sanitized);
        let mut archive = zip::ZipArchive::new(reader).unwrap();

        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();

        // Fingerprint should be replaced with "wallet"
        assert!(names.iter().any(|n| n.starts_with("wallet/")));
        assert!(!names.iter().any(|n| n.contains(fingerprint)));

        // BDK files should be excluded
        assert!(!names.iter().any(|n| n.ends_with("bdk_db")));
        assert!(!names.iter().any(|n| n.ends_with("bdk_db_watch_only")));

        // Normal files should be present
        assert!(names.contains(&"wallet/some_file.txt".to_string()));
        assert!(names.contains(&"wallet/subdir/nested.dat".to_string()));

        // Verify file content is preserved
        let mut some_file = archive.by_name("wallet/some_file.txt").unwrap();
        let mut content = String::new();
        some_file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_get_fingerprint_from_zip_bytes() {
        let fingerprint = "deadbeef";
        let zip_data = create_test_zip(fingerprint);

        let extracted = get_fingerprint_from_zip_bytes(&zip_data).unwrap();
        assert_eq!(extracted, fingerprint);
    }
}
