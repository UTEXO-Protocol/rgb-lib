use super::*;

const BACKUP_BUFFER_LEN_ENCRYPT: usize = 239; // 255 max, leaving 16 for the checksum
const BACKUP_BUFFER_LEN_DECRYPT: usize = BACKUP_BUFFER_LEN_ENCRYPT + 16;
const BACKUP_KEY_LENGTH: usize = 32;
const BACKUP_NONCE_LENGTH: usize = 19;
const BACKUP_VERSION: u8 = 1;

pub(crate) struct BackupPaths {
    encrypted: PathBuf,
    pub(crate) backup_pub_data: PathBuf,
    pub(crate) tempdir: TempDir,
    zip: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScryptParams {
    log_n: u8,
    r: u32,
    p: u32,
    len: usize,
    version: Option<u32>,
    algorithm: Option<String>,
}

impl ScryptParams {
    pub(crate) fn new(log_n: Option<u8>, r: Option<u32>, p: Option<u32>) -> ScryptParams {
        ScryptParams {
            log_n: log_n.unwrap_or(Params::RECOMMENDED_LOG_N),
            r: r.unwrap_or(Params::RECOMMENDED_R),
            p: p.unwrap_or(Params::RECOMMENDED_P),
            len: BACKUP_KEY_LENGTH,
            version: None,
            algorithm: None,
        }
    }
}

impl Default for ScryptParams {
    fn default() -> ScryptParams {
        ScryptParams::new(None, None, None)
    }
}

impl TryInto<Params> for ScryptParams {
    type Error = Error;

    fn try_into(self: ScryptParams) -> Result<Params, Error> {
        Params::new(self.log_n, self.r, self.p, self.len).map_err(|e| Error::Internal {
            details: format!("invalid params {e}"),
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BackupPubData {
    scrypt_params: ScryptParams,
    salt: String,
    nonce: String,
    pub(crate) version: u8,
}

impl BackupPubData {
    fn nonce(&self) -> Result<[u8; BACKUP_NONCE_LENGTH], InternalError> {
        let nonce_bytes = self.nonce.as_bytes();
        nonce_bytes[0..BACKUP_NONCE_LENGTH]
            .try_into()
            .map_err(|_| InternalError::Unexpected)
    }
}

#[allow(async_fn_in_trait)]
pub trait WalletBackup: WalletCore {
    /// For now setting the scrypt params is done only for testing purposes,
    /// a few details should be refined before allowing to set this in the public API:
    /// - Which parameters should we allow users to change? Should we set sensible minimums?
    /// - Can we guarantee old backups can always be recovered in the future?
    fn backup_customize(
        &self,
        backup_path: &str,
        password: &str,
        scrypt_params: Option<ScryptParams>,
    ) -> Result<(), Error> {
        let prev_backup_info = self.update_backup_info(true)?;
        match self.backup_raw(backup_path, password, scrypt_params) {
            Ok(()) => Ok(()),
            Err(e) => {
                error!(self.logger(), "Error during backup: {e:?}");
                if let Some(prev_backup_info) = prev_backup_info {
                    let mut prev_backup_info: DbBackupInfoActMod = prev_backup_info.into();
                    self.database().update_backup_info(&mut prev_backup_info)?;
                } else {
                    self.database().del_backup_info()?;
                }
                Err(e)
            }
        }
    }

    fn backup_raw(
        &self,
        backup_path: &str,
        password: &str,
        scrypt_params: Option<ScryptParams>,
    ) -> Result<(), Error> {
        // setup
        info!(self.logger(), "starting backup...");
        let backup_file = PathBuf::from(&backup_path);
        if backup_file.exists() {
            return Err(Error::FileAlreadyExists {
                path: backup_path.to_string(),
            })?;
        }
        let tmp_base_path = get_parent_path(&backup_file)?;
        let files = get_backup_paths(&tmp_base_path)?;
        let scrypt_params = scrypt_params.unwrap_or_default();
        let salt = SaltString::generate(&mut OsRng);
        let str_params = serde_json::to_string(&scrypt_params).map_err(InternalError::from)?;
        debug!(
            self.logger(),
            "using generated scrypt params: {}", str_params
        );
        let nonce: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(BACKUP_NONCE_LENGTH)
            .map(char::from)
            .collect();
        debug!(self.logger(), "using generated nonce: {}", &nonce);
        let backup_pub_data = BackupPubData {
            scrypt_params,
            salt: salt.to_string(),
            nonce,
            version: BACKUP_VERSION,
        };

        // create zip archive of wallet data
        debug!(
            self.logger(),
            "\nzipping {:?} to {:?}",
            &self.wallet_dir(),
            &files.zip
        );
        zip_dir(self.wallet_dir(), &files.zip, true, self.logger())?;

        // encrypt the backup file
        debug!(
            self.logger(),
            "\nencrypting {:?} to {:?}", &files.zip, &files.encrypted
        );
        encrypt_file(&files.zip, &files.encrypted, password, &backup_pub_data)?;

        // add backup nonce + salt + version to final zip file
        fs::write(
            files.backup_pub_data,
            serde_json::to_string(&backup_pub_data).unwrap(),
        )?;
        debug!(
            self.logger(),
            "\nzipping {:?} to {:?}", &files.tempdir, &backup_file
        );
        zip_dir(
            &PathBuf::from(files.tempdir.path()),
            &backup_file,
            false,
            self.logger(),
        )?;

        info!(self.logger(), "backup completed");
        Ok(())
    }

    fn get_backup_info(&self) -> Result<bool, Error> {
        Ok(
            if let Some(backup_info) = self.database().get_backup_info()? {
                backup_info
                    .last_operation_timestamp
                    .parse::<i128>()
                    .unwrap()
                    > backup_info.last_backup_timestamp.parse::<i128>().unwrap()
            } else {
                false
            },
        )
    }

    fn update_backup_info_with_op_idx(
        &self,
        doing_backup: bool,
        last_processed_operation_idx: Option<i32>,
    ) -> Result<Option<DbBackupInfo>, Error> {
        let now = ActiveValue::Set(now().unix_timestamp_nanos().to_string());
        let last_processed_operation_idx = if last_processed_operation_idx.is_some() {
            ActiveValue::Set(last_processed_operation_idx)
        } else {
            ActiveValue::NotSet
        };
        if let Some(backup_info) = self.database().get_backup_info()? {
            let prev_backup_info = backup_info.clone();
            let mut backup_info: DbBackupInfoActMod = backup_info.into();
            if doing_backup {
                backup_info.last_backup_timestamp = now;
            } else {
                backup_info.last_operation_timestamp = now;
            }
            backup_info.last_processed_operation_idx = last_processed_operation_idx;
            self.database().update_backup_info(&mut backup_info)?;
            Ok(Some(prev_backup_info))
        } else {
            let (last_backup_timestamp, last_operation_timestamp) = if doing_backup {
                (now, ActiveValue::Set(s!("0")))
            } else {
                (ActiveValue::Set(s!("0")), now)
            };
            let backup_info = DbBackupInfoActMod {
                last_backup_timestamp,
                last_operation_timestamp,
                last_processed_operation_idx,
                ..Default::default()
            };
            self.database().set_backup_info(backup_info)?;
            Ok(None)
        }
    }

    /// Perform a VSS backup of the wallet
    ///
    /// Creates a backup of the wallet directory and uploads it to the VSS server.
    /// Returns the server-side version number of the uploaded backup.
    #[cfg(feature = "vss")]
    async fn vss_backup(&self, client: &super::vss::VssBackupClient) -> Result<i64, Error> {
        self.update_backup_info(true)?;
        match self._vss_backup(client).await {
            Ok(version) => Ok(version),
            Err(e) => {
                // Reset: mark wallet as needing a backup again so backup_info() returns true.
                let _ = self.update_backup_info(false);
                Err(e)
            }
        }
    }

    #[cfg(feature = "vss")]
    async fn _vss_backup(&self, client: &super::vss::VssBackupClient) -> Result<i64, Error> {
        info!(self.logger(), "Starting VSS backup...");
        let backup_data = super::vss::create_backup_data(self.wallet_dir(), self.logger())?;

        info!(self.logger(), "Uploading to VSS server...");
        let version = client.upload_backup(backup_data).await?;

        info!(self.logger(), "VSS backup completed, version: {}", version);
        Ok(version)
    }

    /// Configure VSS backup for this wallet, enabling automatic backups
    /// after state-changing operations.
    ///
    /// Once configured, the wallet will automatically upload backups to the
    /// VSS server after operations like send, receive, issue, etc.
    #[cfg(feature = "vss")]
    fn configure_vss_backup(&mut self, config: super::vss::VssBackupConfig) -> Result<(), Error> {
        let client = super::vss::VssBackupClient::new(config)?;
        self.set_vss_client(Some(Arc::new(client)));
        info!(self.logger(), "VSS auto-backup configured");
        Ok(())
    }

    /// Disable VSS auto-backup.
    #[cfg(feature = "vss")]
    fn disable_vss_auto_backup(&mut self) {
        self.set_vss_client(None);
        info!(self.logger(), "VSS auto-backup disabled");
    }

    /// Trigger an automatic VSS backup if configured.
    ///
    /// This is called internally after state-changing operations. It creates
    /// the backup data synchronously, then spawns an async task for the upload.
    /// Errors are logged but not propagated (auto-backup is best-effort).
    /// If a backup is already in progress, the call is skipped.
    ///
    /// **Note:** The backup data (zip of the wallet directory) is created
    /// synchronously before the async upload task is spawned. This adds
    /// latency proportional to wallet directory size to the calling
    /// operation. The upload itself runs asynchronously and does not block.
    #[cfg(feature = "vss")]
    fn trigger_auto_backup(&self) {
        use std::sync::atomic::Ordering;

        /// Guard that resets the `AtomicBool` on drop, ensuring the flag is
        /// cleared even if the async task panics.
        struct BackupGuard(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for BackupGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }

        let Some(client) = self.vss_client() else {
            return;
        };

        if !client.auto_backup() {
            return;
        }

        // Skip if a backup is already in progress (swap returns the previous value;
        // if it was already true, another backup is running so we skip this one).
        if self.auto_backup_in_progress().swap(true, Ordering::SeqCst) {
            debug!(
                self.logger(),
                "VSS auto-backup: skipping, already in progress"
            );
            return;
        }

        let handle = client.handle().clone();

        // Create backup data synchronously (zip the wallet directory)
        let backup_data = match super::vss::create_backup_data(self.wallet_dir(), self.logger()) {
            Ok(data) => data,
            Err(e) => {
                error!(
                    self.logger(),
                    "VSS auto-backup: failed to create data: {}", e
                );
                self.auto_backup_in_progress()
                    .store(false, Ordering::SeqCst);
                return;
            }
        };

        // Clone what the spawned task needs
        let client = Arc::clone(client);
        let backup_mode = client.backup_mode();
        let logger = self.logger().clone();
        let database = Arc::clone(self.database_arc());
        let guard = BackupGuard(Arc::clone(self.auto_backup_in_progress()));

        let upload_future = async move {
            let _guard = guard;
            debug!(logger, "VSS auto-backup: uploading...");
            match client.upload_backup(backup_data).await {
                Ok(version) => {
                    info!(logger, "VSS auto-backup completed, version: {}", version);
                    // Update backup timestamp on success
                    if let Some(backup_info) = database.get_backup_info().ok().flatten() {
                        let mut backup_info: DbBackupInfoActMod = backup_info.into();
                        backup_info.last_backup_timestamp = sea_orm::ActiveValue::Set(
                            time::OffsetDateTime::now_utc()
                                .unix_timestamp_nanos()
                                .to_string(),
                        );
                        let _ = database.update_backup_info(&mut backup_info);
                    }
                }
                Err(e) => {
                    error!(logger, "VSS auto-backup failed: {}", e);
                }
            }
        };

        match backup_mode {
            super::vss::VssBackupMode::Async => {
                handle.spawn(upload_future);
            }
            super::vss::VssBackupMode::Blocking => {
                // Use an OS thread so block_on() is safe even when called
                // from within a tokio worker thread.
                let _ = std::thread::spawn(move || handle.block_on(upload_future)).join();
            }
        }
    }

    /// Get VSS backup info
    ///
    /// Returns information about the current VSS backup state, including
    /// whether a backup exists on the server and if a new backup is needed.
    #[cfg(feature = "vss")]
    async fn vss_backup_info(
        &self,
        client: &super::vss::VssBackupClient,
    ) -> Result<super::vss::VssBackupInfo, Error> {
        let server_version = client.get_backup_version().await?;
        let backup_exists = server_version.is_some();
        let backup_required = self.get_backup_info()?;

        Ok(super::vss::VssBackupInfo {
            backup_exists,
            server_version,
            backup_required,
        })
    }

    /// No-op auto-backup trigger when VSS feature is not enabled.
    #[cfg(not(feature = "vss"))]
    fn trigger_auto_backup(&self) {}

    fn update_backup_info(&self, doing_backup: bool) -> Result<Option<DbBackupInfo>, Error> {
        self.update_backup_info_with_op_idx(doing_backup, None)
    }
}

/// Restore a backup from the given file and password to the provided target directory.
pub fn restore_backup(backup_path: &str, password: &str, target_dir: &str) -> Result<(), Error> {
    // setup
    fs::create_dir_all(target_dir)?;
    let log_dir = Path::new(&target_dir);
    let log_name = format!("restore_{}", now().unix_timestamp());
    let (logger, _logger_guard) = setup_logger(log_dir, Some(&log_name))?;
    info!(logger, "starting restore...");
    let backup_file = PathBuf::from(backup_path);
    let tmp_base_path = get_parent_path(&backup_file)?;
    let files = get_backup_paths(&tmp_base_path)?;
    let target_dir_path = PathBuf::from(&target_dir);

    // unpack given zip file and retrieve backup data
    info!(logger, "unzipping {:?}", backup_file);
    unzip(&backup_file, &PathBuf::from(files.tempdir.path()), &logger)?;
    let json_pub_data = fs::read_to_string(files.backup_pub_data)?;
    debug!(logger, "using retrieved backup_pub_data: {}", json_pub_data);
    let backup_pub_data: BackupPubData =
        serde_json::from_str(json_pub_data.as_str()).map_err(InternalError::from)?;
    let version = backup_pub_data.version;
    debug!(logger, "retrieved version: {}", &version);
    if version != BACKUP_VERSION {
        return Err(Error::UnsupportedBackupVersion {
            version: version.to_string(),
        });
    }

    // decrypt backup
    info!(
        logger.clone(),
        "decrypting {:?} to {:?}", files.encrypted, files.zip
    );
    decrypt_file(&files.encrypted, &files.zip, password, &backup_pub_data)?;

    // check the target wallet directory doesn't already exist
    let fingerprint = get_fingerprint_from_zip(&files.zip)?;
    let wallet_dir = target_dir_path.join(fingerprint);
    if wallet_dir.exists() {
        return Err(Error::WalletDirAlreadyExists {
            path: wallet_dir.to_string_lossy().to_string(),
        });
    }

    // restore files
    info!(
        logger.clone(),
        "unzipping {:?} to {:?}", &files.zip, &target_dir_path
    );
    unzip(&files.zip, &target_dir_path, &logger)?;

    info!(logger, "restore completed");
    Ok(())
}

pub(crate) fn get_backup_paths(tmp_base_path: &Path) -> Result<BackupPaths, Error> {
    fs::create_dir_all(tmp_base_path)?;
    let tempdir = tempfile::tempdir_in(tmp_base_path)?;
    let encrypted = tempdir.path().join("backup.enc");
    let backup_pub_data = tempdir.path().join("backup.pub_data");
    let zip = tempdir.path().join("backup.zip");
    Ok(BackupPaths {
        encrypted,
        backup_pub_data,
        tempdir,
        zip,
    })
}

fn get_parent_path(file: &Path) -> Result<PathBuf, Error> {
    if let Some(parent) = file.parent() {
        Ok(parent.to_path_buf())
    } else {
        Err(Error::IO {
            details: "provided file path has no parent".to_string(),
        })
    }
}

pub(crate) fn zip_dir(
    path_in: &PathBuf,
    path_out: &PathBuf,
    keep_last_path_component: bool,
    logger: &Logger,
) -> Result<(), Error> {
    // setup
    let writer = fs::File::create(path_out)?;
    let mut zip = zip::ZipWriter::new(writer);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);
    let mut buffer = [0u8; 4096];

    // archive
    let prefix = if keep_last_path_component {
        if let Some(parent) = path_in.parent() {
            parent
        } else {
            return Err(Error::Internal {
                details: "no parent directory".to_string(),
            });
        }
    } else {
        path_in
    };
    let entry_iterator = WalkDir::new(path_in).into_iter().filter_map(|e| e.ok());
    for entry in entry_iterator {
        let path = entry.path();
        let name = path.strip_prefix(prefix).map_err(InternalError::from)?;
        let name_str = name.to_str().ok_or_else(|| InternalError::Unexpected)?;
        if path.is_file() {
            if path.ends_with(LOG_FILE) {
                continue;
            }; // skip log file
            debug!(logger, "adding file {path:?} as {name:?}");
            zip.start_file(name_str, options)
                .map_err(InternalError::from)?;
            let mut f = fs::File::open(path)?;
            loop {
                let read_count = f.read(&mut buffer)?;
                if read_count != 0 {
                    zip.write_all(&buffer[..read_count])?;
                } else {
                    break;
                }
            }
        } else if !name.as_os_str().is_empty() {
            debug!(logger, "adding directory {path:?} as {name:?}");
            zip.add_directory(name_str, options)
                .map_err(InternalError::from)?;
        }
    }

    // finalize
    let mut file = zip.finish().map_err(InternalError::from)?;
    file.flush()?;
    file.sync_all()?;

    Ok(())
}

fn get_zip_archive(zip_path: &PathBuf) -> Result<zip::ZipArchive<std::fs::File>, Error> {
    let file = fs::File::open(zip_path).map_err(InternalError::from)?;
    Ok(zip::ZipArchive::new(file).map_err(InternalError::from)?)
}

fn get_fingerprint_from_zip(zip_path: &PathBuf) -> Result<String, Error> {
    let archive = get_zip_archive(zip_path)?;
    let fingerprint = archive.name_for_index(0).unwrap_or_default();
    Ok(fingerprint.to_string().replace("/", ""))
}

pub(crate) fn unzip(zip_path: &PathBuf, path_out: &Path, logger: &Logger) -> Result<(), Error> {
    let mut archive = get_zip_archive(zip_path)?;
    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(InternalError::from)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path_out.join(path),
            None => continue,
        };
        if file.name().ends_with('/') {
            debug!(logger, "creating directory {i} as {}", outpath.display());
            fs::create_dir_all(&outpath)?;
        } else {
            debug!(
                logger,
                "extracting file {i} to {} ({} bytes)",
                outpath.display(),
                file.size()
            );
            if let Some(p) = outpath.parent()
                && !p.exists()
            {
                debug!(logger, "creating parent dir {}", p.display());
                fs::create_dir_all(p)?;
            }
            let mut outfile = fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

fn get_cypher_secrets(
    password: &str,
    backup_pub_data: &BackupPubData,
) -> Result<GenericArray<u8, U32>, Error> {
    // hash password using scrypt with the provided salt
    let password_bytes = password.as_bytes();
    let salt = Salt::from_b64(&backup_pub_data.salt).map_err(InternalError::from)?;
    let password_hash = Scrypt
        .hash_password_customized(
            password_bytes,
            None,
            None,
            backup_pub_data.scrypt_params.clone().try_into()?,
            salt,
        )
        .map_err(InternalError::from)?;
    let hash_output = password_hash
        .hash
        .ok_or_else(|| InternalError::NoPasswordHashError)?;
    let hash = hash_output.as_bytes();

    // get key from password hash
    let key = Key::clone_from_slice(hash);

    Ok(key)
}

fn encrypt_file(
    path_cleartext: &PathBuf,
    path_encrypted: &PathBuf,
    password: &str,
    backup_pub_data: &BackupPubData,
) -> Result<(), Error> {
    let key = get_cypher_secrets(password, backup_pub_data)?;

    // - XChacha20Poly1305 is fast, requires no special hardware and supports stream operation
    // - stream mode required as files to encrypt may be big, so avoiding a memory buffer

    // setup
    let aead = XChaCha20Poly1305::new(&key);
    let nonce = backup_pub_data.nonce()?;
    let nonce = GenericArray::from_slice(&nonce);
    let mut stream_encryptor = stream::EncryptorBE32::from_aead(aead, nonce);
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_ENCRYPT];
    let mut source_file = fs::File::open(path_cleartext)?;
    let mut destination_file = fs::File::create(path_encrypted)?;

    // encrypt file
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BACKUP_BUFFER_LEN_ENCRYPT {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|e| InternalError::AeadError(e.to_string()))?;
            destination_file.write_all(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|e| InternalError::AeadError(e.to_string()))?;
            destination_file.write_all(&ciphertext)?;
            break;
        }
    }

    // remove cleartext source file
    fs::remove_file(path_cleartext)?;

    Ok(())
}

fn decrypt_file(
    path_encrypted: &PathBuf,
    path_cleartext: &PathBuf,
    password: &str,
    backup_pub_data: &BackupPubData,
) -> Result<(), Error> {
    let key = get_cypher_secrets(password, backup_pub_data)?;

    // setup
    let aead = XChaCha20Poly1305::new(&key);
    let nonce = backup_pub_data.nonce()?;
    let nonce = GenericArray::from_slice(&nonce);
    let mut stream_decryptor = stream::DecryptorBE32::from_aead(aead, nonce);
    let mut buffer = [0u8; BACKUP_BUFFER_LEN_DECRYPT];
    let mut source_file = fs::File::open(path_encrypted)?;
    let mut destination_file = fs::File::create(path_cleartext)?;

    // decrypt file
    loop {
        let read_count = source_file.read(&mut buffer)?;
        if read_count == BACKUP_BUFFER_LEN_DECRYPT {
            let cleartext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|_| Error::WrongPassword)?;
            destination_file.write_all(&cleartext)?;
        } else if read_count == 0 {
            break;
        } else {
            let cleartext = stream_decryptor
                .decrypt_last(&buffer[..read_count])
                .map_err(|_| Error::WrongPassword)?;
            destination_file.write_all(&cleartext)?;
            break;
        }
    }

    Ok(())
}
