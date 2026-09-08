//! Core wallet functionality.
//!
//! This module defines abstractions to implement common methods across different wallet types.

use super::*;

const BDK_DB_NAME: &str = "bdk_db";

pub(crate) const NUM_KNOWN_SCHEMAS: usize = 5;

pub(crate) const RGB_LIB_DB_NAME: &str = "rgb_lib_db";

pub(crate) const ASSETS_DIR: &str = "assets";
pub(crate) const MEDIA_DIR: &str = "media_files";

pub(crate) const WALLET_MANIFEST_FILE: &str = "wallet_manifest.json";
pub(crate) const WALLET_MANIFEST_VERSION: u8 = 1;

// Only the version field, so an unsupported manifest reports its version instead of failing to
// deserialize.
#[derive(Deserialize)]
struct WalletManifestVersion {
    version: u8,
}

// The non-secret parts of a WalletData and a SinglesigKeys, persisted inside the wallet
// directory so the wallet can be re-opened via Wallet::load without re-supplying them.
//
// The mnemonic must never be stored here: it's the wallet's only secret and the manifest sits in
// plaintext next to the databases.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct WalletManifest {
    pub(crate) version: u8,
    pub(crate) bitcoin_network: BitcoinNetwork,
    pub(crate) database_type: DatabaseType,
    pub(crate) max_allocations_per_utxo: u32,
    pub(crate) supported_schemas: Vec<AssetSchema>,
    #[serde(default)]
    pub(crate) reuse_addresses: bool,
    pub(crate) account_xpub_vanilla: String,
    pub(crate) account_xpub_colored: String,
    pub(crate) vanilla_keychain: u8,
    pub(crate) master_fingerprint: String,
    pub(crate) witness_version: WitnessVersion,
}

impl WalletManifest {
    pub(crate) fn new(wallet_data: &WalletData, keys: &SinglesigKeys) -> Self {
        Self {
            version: WALLET_MANIFEST_VERSION,
            bitcoin_network: wallet_data.bitcoin_network,
            database_type: wallet_data.database_type.clone(),
            max_allocations_per_utxo: wallet_data.max_allocations_per_utxo,
            supported_schemas: wallet_data.supported_schemas.clone(),
            reuse_addresses: wallet_data.reuse_addresses,
            account_xpub_vanilla: keys.account_xpub_vanilla.clone(),
            account_xpub_colored: keys.account_xpub_colored.clone(),
            vanilla_keychain: keys.vanilla_keychain.unwrap_or(KEYCHAIN_BTC),
            master_fingerprint: keys.master_fingerprint.clone(),
            witness_version: keys.witness_version,
        }
    }

    fn path(wallet_dir: &Path) -> PathBuf {
        wallet_dir.join(WALLET_MANIFEST_FILE)
    }

    pub(crate) fn write(&self, wallet_dir: &Path) -> Result<(), Error> {
        let json = serde_json::to_string_pretty(self).map_err(InternalError::from)?;
        let path = Self::path(wallet_dir);
        if let Ok(existing) = fs::read_to_string(&path)
            && existing == json
        {
            return Ok(());
        }
        // atomic replace so a crash mid-write can't leave a torn manifest
        let tmp_path = wallet_dir.join(format!("{WALLET_MANIFEST_FILE}.tmp"));
        fs::write(&tmp_path, json)?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    pub(crate) fn read(wallet_dir: &Path) -> Result<Self, Error> {
        let manifest_path = Self::path(wallet_dir);
        if !manifest_path.exists() {
            return Err(Error::InexistentWalletManifest {
                path: manifest_path.to_string_lossy().to_string(),
            });
        }
        let json = fs::read_to_string(&manifest_path)?;
        let manifest_version: WalletManifestVersion =
            serde_json::from_str(&json).map_err(InternalError::from)?;
        if manifest_version.version != WALLET_MANIFEST_VERSION {
            return Err(Error::UnsupportedWalletManifestVersion {
                version: manifest_version.version.to_string(),
            });
        }
        serde_json::from_str(&json).map_err(|e| InternalError::from(e).into())
    }

    // Fail if wallet_data or keys disagree with settings fixed at wallet creation. Settings that
    // are allowed to change are not checked on purpose.
    pub(crate) fn check_settings_unchanged(
        wallet_dir: &Path,
        wallet_data: &WalletData,
        keys: &SinglesigKeys,
    ) -> Result<(), Error> {
        if !Self::path(wallet_dir).exists() {
            // skip when no manifest exists (legacy directory or first creation)
            return Ok(());
        }
        let created_with = Self::read(wallet_dir)?;
        let requested = Self::new(wallet_data, keys);

        if created_with.bitcoin_network != requested.bitcoin_network {
            return Err(Error::BitcoinNetworkMismatch);
        }

        macro_rules! check {
            ($($field:ident),+ $(,)?) => {
                $(if created_with.$field != requested.$field {
                    return Err(Error::WalletSettingMismatch {
                        setting: stringify!($field).to_string(),
                        expected: format!("{:?}", created_with.$field),
                        provided: format!("{:?}", requested.$field),
                    });
                })+
            };
        }

        // ordered so the root cause is reported ahead of what it derives: a changed witness
        // version also changes the account xpubs it produces
        check!(
            master_fingerprint,
            witness_version,
            vanilla_keychain,
            account_xpub_colored,
            account_xpub_vanilla,
        );
        Ok(())
    }

    pub(crate) fn into_parts(
        self,
        data_dir: String,
        mnemonic: Option<String>,
    ) -> (WalletData, SinglesigKeys) {
        (
            WalletData {
                data_dir,
                bitcoin_network: self.bitcoin_network,
                database_type: self.database_type,
                max_allocations_per_utxo: self.max_allocations_per_utxo,
                supported_schemas: self.supported_schemas,
                reuse_addresses: self.reuse_addresses,
            },
            SinglesigKeys {
                account_xpub_vanilla: self.account_xpub_vanilla,
                account_xpub_colored: self.account_xpub_colored,
                vanilla_keychain: Some(self.vanilla_keychain),
                master_fingerprint: self.master_fingerprint,
                mnemonic,
                witness_version: self.witness_version,
            },
        )
    }
}

/// Which keychain contributes SPKs to the sync request.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncKeychain {
    /// Sync the colored keychain
    Colored,
    /// Sync the vanilla keychain
    Vanilla {
        /// Number of addresses preceding the lookback anchor (last used or, if none, last
        /// revealed) to scan
        lookback: u32,
    },
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl SyncKeychain {
    fn keychain(&self) -> KeychainKind {
        match self {
            SyncKeychain::Colored => KeychainKind::External,
            SyncKeychain::Vanilla { .. } => KeychainKind::Internal,
        }
    }
}

/// Strategy used to build the indexer sync request.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncStrategy {
    /// BIP44 stop-gap full scan
    FullScan,
    /// Sync all revealed SPKs
    FullSync,
    /// Sync only SPKs we strictly need to observe:
    /// - colored: SPKs used in pending transfers or unconfirmed transactions
    /// - vanilla: a tail of recently revealed SPKs
    FastSync,
}

/// Options driving a single sync invocation.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOptions {
    /// Which keychain to sync
    pub keychain: SyncKeychain,
    /// Sync strategy
    pub strategy: SyncStrategy,
}

pub struct WalletInternals {
    pub(crate) wallet_data: WalletData,
    pub(crate) logger: Logger,
    pub(crate) _logger_guard: AsyncGuard,
    pub(crate) database: Arc<RgbLibDatabase>,
    pub(crate) wallet_dir: PathBuf,
    pub(crate) bdk_wallet: PersistedWallet<Store<ChangeSet>>,
    pub(crate) bdk_database: Store<ChangeSet>,
    /// Pinned derivation index per keychain for address reuse.
    pub(crate) reuse_address_index: HashMap<KeychainKind, u32>,
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) online_data: Option<OnlineData>,
    #[cfg(feature = "vss")]
    pub(crate) vss_client: Option<Arc<super::vss::VssBackupClient>>,
    #[cfg(feature = "vss")]
    pub(crate) auto_backup_in_progress: Arc<std::sync::atomic::AtomicBool>,
}

pub(crate) fn setup_rgb<P: AsRef<Path>>(
    wallet_dir: P,
    supported_schemas: Vec<AssetSchema>,
    bitcoin_network: BitcoinNetwork,
) -> Result<(), Error> {
    if supported_schemas.is_empty() {
        return Err(Error::NoSupportedSchemas);
    }
    if bitcoin_network == BitcoinNetwork::Mainnet && supported_schemas.contains(&AssetSchema::Ifa) {
        return Err(Error::CannotUseIfaOnMainnet);
    }
    let mut runtime = load_rgb_runtime(wallet_dir)?;
    let known_schemas = runtime.schemata()?;
    if known_schemas.len() < NUM_KNOWN_SCHEMAS {
        let known: HashSet<_> = known_schemas.iter().map(|s| s.id).collect();
        for schema in supported_schemas {
            if !known.contains(&SchemaId::from(schema)) {
                schema.import_kit(&mut runtime)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn setup_db<P: AsRef<Path>>(wallet_dir: P) -> Result<RgbLibDatabase, Error> {
    let db_path = wallet_dir.as_ref().join(RGB_LIB_DB_NAME);
    let display_db_path = adjust_canonicalization(db_path);
    let connection_string = format!("sqlite:{display_db_path}?mode=rwc");
    let mut opt = ConnectOptions::new(connection_string);
    opt.max_connections(1)
        .min_connections(0)
        .connect_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8));
    let db_cnn = block_on(Database::connect(opt));
    let connection = db_cnn?;
    block_on(Migrator::up(&connection, None))?;
    Ok(RgbLibDatabase::new(connection))
}

/// Open the BDK changeset store, self-healing a corrupt tail.
///
/// The store is an append-only `bincode` log; an interrupted `persist` can leave
/// an undecodable trailing record that makes a plain load fail. When BDK reports
/// such corruption it still returns the changeset aggregated before the bad
/// record, so we rebuild a clean store from it (keeping the corrupt file aside as
/// `<name>.corrupt` for forensics) and carry on. Corruption with nothing
/// recoverable (bad magic / first record) is surfaced unchanged — we never wipe a
/// file we could not read at all. Returns the recovered store and, when a repair
/// happened, the path of the preserved corrupt copy.
pub(crate) fn load_or_recover_bdk_store(
    magic: &[u8],
    path: &Path,
) -> Result<(Store<ChangeSet>, Option<PathBuf>), Error> {
    match Store::<ChangeSet>::load_or_create(magic, path) {
        Ok((store, _)) => Ok((store, None)),
        Err(bdk_wallet::file_store::StoreErrorWithDump {
            changeset: Some(recovered),
            ..
        }) => {
            let tmp_path = path.with_extension("recovering");
            let _ = fs::remove_file(&tmp_path);
            {
                let mut rebuilt =
                    Store::<ChangeSet>::create(magic, &tmp_path).map_err(|e| Error::IO {
                        details: e.to_string(),
                    })?;
                rebuilt.append(recovered.as_ref())?;
            }
            let backup_path = unique_corrupt_path(path);
            fs::copy(path, &backup_path)?;
            fs::rename(&tmp_path, path)?;
            let (store, _) = Store::<ChangeSet>::load_or_create(magic, path)?;
            Ok((store, Some(backup_path)))
        }
        Err(e) => Err(e.into()),
    }
}

/// First non-existing `<name>.corrupt[.N]` sibling of `path`.
fn unique_corrupt_path(path: &Path) -> PathBuf {
    let base = path.with_extension("corrupt");
    if !base.exists() {
        return base;
    }
    let mut n = 1u32;
    loop {
        let candidate = path.with_extension(format!("corrupt.{n}"));
        if !candidate.exists() {
            return candidate;
        }
        n += 1;
    }
}

pub(crate) fn setup_bdk<P: AsRef<Path>>(
    wallet_data: &WalletData,
    wallet_dir: P,
    desc_colored: String,
    desc_vanilla: String,
    watch_only: bool,
    bdk_network: BdkNetwork,
    logger: &Logger,
) -> Result<(PersistedWallet<Store<ChangeSet>>, Store<ChangeSet>), Error> {
    let chain_net: ChainNet = wallet_data.bitcoin_network.into();
    let mut wallet_params = BdkWallet::load()
        .descriptor(KeychainKind::External, Some(desc_colored.clone()))
        .descriptor(KeychainKind::Internal, Some(desc_vanilla.clone()))
        .check_genesis_hash(BlockHash::from_byte_array(
            chain_net.chain_hash().to_bytes(),
        ));
    let bdk_db_name = if watch_only {
        format!("{BDK_DB_NAME}_watch_only")
    } else {
        wallet_params = wallet_params.extract_keys();
        BDK_DB_NAME.to_string()
    };
    let bdk_db_path = wallet_dir.as_ref().join(bdk_db_name);
    let (mut bdk_database, recovered_from) =
        load_or_recover_bdk_store(BDK_DB_NAME.as_bytes(), &bdk_db_path)?;
    if let Some(backup) = recovered_from {
        warn!(
            logger,
            "Recovered corrupted BDK store '{:?}'; corrupt copy saved to '{:?}'",
            bdk_db_path,
            backup
        );
    }
    let bdk_wallet = match wallet_params.load_wallet(&mut bdk_database)? {
        Some(wallet) => wallet,
        None => BdkWallet::create(desc_colored, desc_vanilla)
            .network(bdk_network)
            .create_wallet(&mut bdk_database)?,
    };
    Ok((bdk_wallet, bdk_database))
}

pub(crate) fn setup_new_wallet(
    wallet_data: &WalletData,
    fingerprint: &str,
) -> Result<(PathBuf, Logger, AsyncGuard), Error> {
    if wallet_data.max_allocations_per_utxo == 0 {
        return Err(Error::NoMaxAllocationsPerUtxo);
    }
    let data_dir_path = Path::new(&wallet_data.data_dir);
    if !data_dir_path.exists() {
        return Err(Error::InexistentDataDir);
    }
    let data_dir_path = fs::canonicalize(data_dir_path)?;
    let wallet_dir = data_dir_path.join(fingerprint);
    if !wallet_dir.exists() {
        fs::create_dir(&wallet_dir)?;
        fs::create_dir(wallet_dir.join(ASSETS_DIR))?;
        fs::create_dir(wallet_dir.join(MEDIA_DIR))?;
    }
    let (logger, logger_guard) = setup_logger(&wallet_dir, None)?;
    info!(logger.clone(), "New wallet in '{:?}'", wallet_dir);
    let panic_logger = logger.clone();
    let prev_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        error!(panic_logger.clone(), "PANIC: {:?}", info);
        prev_hook(info);
    }));
    Ok((wallet_dir, logger, logger_guard))
}

pub trait WalletCore {
    fn internals(&self) -> &WalletInternals;

    fn internals_mut(&mut self) -> &mut WalletInternals;

    fn bdk_wallet(&self) -> &PersistedWallet<Store<ChangeSet>> {
        &self.internals().bdk_wallet
    }

    fn bdk_wallet_mut(&mut self) -> &mut PersistedWallet<Store<ChangeSet>> {
        &mut self.internals_mut().bdk_wallet
    }

    /// Whether a transaction is already known to the wallet's BDK graph
    /// (broadcast or confirmed as of the latest sync).
    ///
    /// Used to make multisig SendEnd idempotent: an operation whose transaction
    /// is already on-chain must be completed without requiring this party to
    /// re-finalize the (possibly under-signed) PSBT.
    fn tx_known_to_wallet(&self, txid: &bdk_wallet::bitcoin::Txid) -> bool {
        self.bdk_wallet()
            .transactions()
            .any(|canonical_tx| canonical_tx.tx_node.txid == *txid)
    }

    fn bdk_wallet_db_mut(
        &mut self,
    ) -> (
        &mut PersistedWallet<Store<ChangeSet>>,
        &mut Store<ChangeSet>,
    ) {
        let internals_mut = self.internals_mut();
        (
            &mut internals_mut.bdk_wallet,
            &mut internals_mut.bdk_database,
        )
    }

    fn database(&self) -> &RgbLibDatabase {
        &self.internals().database
    }

    fn database_arc(&self) -> &Arc<RgbLibDatabase> {
        &self.internals().database
    }

    fn logger(&self) -> &Logger {
        &self.internals().logger
    }

    fn wallet_data(&self) -> &WalletData {
        &self.internals().wallet_data
    }

    fn wallet_dir(&self) -> &PathBuf {
        &self.internals().wallet_dir
    }

    #[cfg(feature = "vss")]
    fn vss_client(&self) -> &Option<Arc<super::vss::VssBackupClient>> {
        &self.internals().vss_client
    }

    #[cfg(feature = "vss")]
    fn set_vss_client(&mut self, client: Option<Arc<super::vss::VssBackupClient>>) {
        self.internals_mut().vss_client = client;
    }

    #[cfg(feature = "vss")]
    fn auto_backup_in_progress(&self) -> &Arc<std::sync::atomic::AtomicBool> {
        &self.internals().auto_backup_in_progress
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn online_data(&self) -> &Option<OnlineData> {
        &self.internals().online_data
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn online_data_mut(&mut self) -> &mut Option<OnlineData> {
        &mut self.internals_mut().online_data
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn indexer(&self) -> &Indexer {
        &self.online_data().as_ref().unwrap().indexer
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn vanilla_sync_lookback(&self) -> u32 {
        self.online_data().as_ref().unwrap().vanilla_sync_lookback
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn eth_rpc_url(&self) -> &Option<String> {
        &self.online_data().as_ref().unwrap().eth_rpc_url
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn check_online(&self, online: Online) -> Result<(), Error> {
        if let Some(online_data) = &self.online_data() {
            if online_data.id != online.id {
                error!(self.logger(), "Cannot change online object");
                return Err(Error::CannotChangeOnline);
            }
        } else {
            error!(self.logger(), "Wallet is offline");
            return Err(Error::Offline);
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn fast_sync_colored_spks(&self, txn: &DbTxn) -> Result<HashSet<ScriptBuf>, Error> {
        let mut spks: HashSet<ScriptBuf> = HashSet::new();
        for pws in txn.iter_pending_witness_scripts()? {
            spks.insert(ScriptBuf::from_hex(&pws.script).expect("valid script"));
        }
        Ok(spks)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn fast_sync_vanilla_spks(&self, lookback: u32) -> HashSet<ScriptBuf> {
        let spk_index = self.bdk_wallet().spk_index();
        let Some(last_revealed) = spk_index.last_revealed_index(KeychainKind::Internal) else {
            return HashSet::new();
        };
        let lookback_anchor = spk_index
            .last_used_index(KeychainKind::Internal)
            .unwrap_or(last_revealed);
        let start = lookback_anchor.saturating_sub(lookback);
        spk_index
            .revealed_keychain_spks(KeychainKind::Internal)
            .filter(|(i, _)| *i >= start && *i <= last_revealed)
            .map(|(_, spk)| spk)
            .collect()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn unconfirmed_colored_spks(&self) -> HashSet<ScriptBuf> {
        let spk_index = self.bdk_wallet().spk_index();
        let mut spks: HashSet<ScriptBuf> = HashSet::new();
        for tx in self
            .bdk_wallet()
            .transactions()
            .filter(|tx| matches!(tx.chain_position, ChainPosition::Unconfirmed { .. }))
        {
            // first input is enough for the indexer's to return the TX info
            for input in tx.tx_node.tx.input.iter() {
                if let Some(((kc, _), txout)) = spk_index.txout(input.previous_output)
                    && kc == KeychainKind::External
                {
                    spks.insert(txout.script_pubkey.clone());
                    break;
                }
            }
        }
        spks
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn sync_bdk_and_db_txos(
        &mut self,
        txn: &DbTxn,
        options: SyncOptions,
        include_spent: bool,
    ) -> Result<(), Error> {
        debug!(self.logger(), "Syncing {:?}...", options);

        let kc = options.keychain.keychain();
        let latest_checkpoint = self.bdk_wallet().latest_checkpoint();
        let update: Update = match options.strategy {
            SyncStrategy::FullScan => {
                let mut iters = self.bdk_wallet().spk_index().all_unbounded_spk_iters();
                let iter = iters.remove(&kc).expect("keychain must exist");
                let request = FullScanRequest::builder()
                    .chain_tip(latest_checkpoint)
                    .spks_for_keychain(kc, iter);
                self.indexer().full_scan(request)?.into()
            }
            SyncStrategy::FullSync => {
                let spks: Vec<ScriptBuf> = self
                    .bdk_wallet()
                    .spk_index()
                    .revealed_keychain_spks(kc)
                    .map(|(_, spk)| spk)
                    .collect();
                let request = SyncRequest::builder()
                    .chain_tip(latest_checkpoint)
                    .spks(spks);
                self.indexer().sync(request)?.into()
            }
            SyncStrategy::FastSync => {
                let mut spks: HashSet<ScriptBuf> = HashSet::new();
                match options.keychain {
                    SyncKeychain::Colored => {
                        spks.extend(self.fast_sync_colored_spks(txn)?);
                        spks.extend(self.unconfirmed_colored_spks());
                    }
                    SyncKeychain::Vanilla { lookback } => {
                        spks.extend(self.fast_sync_vanilla_spks(lookback));
                    }
                }
                let request = SyncRequest::builder()
                    .chain_tip(latest_checkpoint)
                    .spks(spks);
                self.indexer().sync(request)?.into()
            }
        };
        let (bdk_wallet, bdk_db) = self.bdk_wallet_db_mut();
        bdk_wallet
            .apply_update(update)
            .map_err(|e| Error::FailedBdkSync {
                details: e.to_string(),
            })?;
        bdk_wallet.persist(bdk_db)?;

        if matches!(options.keychain, SyncKeychain::Colored) {
            self.update_db_colored_txos_from_bdk(txn, include_spent)?;
        }

        debug!(self.logger(), "Synced");
        Ok(())
    }

    /// Mark any rgb-lib `Txo` row currently held as `exists && !spent && !pending_witness`
    /// whose outpoint is not in BDK's `list_unspent` after sync.
    ///
    /// This closes the divergence window where rgb-lib's DB and BDK's persisted store
    /// disagree on whether a UTXO is still spendable (e.g. after a snapshot restore,
    /// an out-of-band spend, or a non-graceful shutdown). The function never marks a
    /// row unspent — only spent — so it cannot revive UTXOs that rgb-lib has already
    /// observed being consumed.
    ///
    /// This is intentionally NOT called from `sync_bdk_and_db_txos`: the singlesig
    /// consistency check at `go_online` time relies on the raw divergence being
    /// visible so it can refuse to come online in the cross-device-wallet case
    /// (where healing would silently lose RGB allocations). The reconcile runs only
    /// on the user-facing `Wallet::sync` path, after the wallet is already online.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn reconcile_orphaned_colored_txos(&self, txn: &DbTxn) -> Result<(), Error> {
        let bdk_unspent_outpoints: HashSet<String> = self
            .bdk_wallet()
            .list_unspent()
            .filter(|u| u.keychain == KeychainKind::External)
            .map(|u| u.outpoint.to_string())
            .collect();

        for txo in txn.iter_txos()? {
            if !(txo.exists && !txo.spent && !txo.pending_witness) {
                continue;
            }
            if bdk_unspent_outpoints.contains(&txo.outpoint().to_string()) {
                continue;
            }
            let mut active: DbTxoActMod = txo.into();
            active.spent = ActiveValue::Set(true);
            txn.update_txo(active)?;
        }

        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn update_db_colored_txos_from_bdk(
        &mut self,
        txn: &DbTxn,
        include_spent: bool,
    ) -> Result<(), Error> {
        let db_txos = txn.iter_txos()?;

        let db_outpoints: HashSet<String> = db_txos
            .into_iter()
            .filter(|t| t.exists && (include_spent || !t.spent))
            .map(|u| u.outpoint().to_string())
            .collect();

        let pending_witness_scripts: Vec<String> = txn
            .iter_pending_witness_scripts()?
            .into_iter()
            .map(|s| s.script)
            .collect();

        let iter: Box<dyn Iterator<Item = LocalOutput>> = if include_spent {
            Box::new(self.bdk_wallet().list_output())
        } else {
            Box::new(self.bdk_wallet().list_unspent())
        };

        for new_utxo in iter
            .filter(|u| u.keychain == KeychainKind::External)
            .filter(|u| !db_outpoints.contains(&u.outpoint.to_string()))
        {
            let mut new_db_utxo: DbTxoActMod = new_utxo.clone().into();
            if !pending_witness_scripts.is_empty() {
                let pending_witness_script = new_utxo.txout.script_pubkey.to_hex_string();
                if pending_witness_scripts.contains(&pending_witness_script) {
                    new_db_utxo.pending_witness = ActiveValue::Set(true);
                    let in_flight =
                        txn.count_in_flight_witness_transfers_for_script(&pending_witness_script)?;
                    if in_flight <= 1 {
                        txn.del_pending_witness_script(pending_witness_script)?;
                    }
                }
            }
            txn.set_txo(new_db_utxo.clone())?;
        }

        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn sync_wallet(
        &mut self,
        txn: &DbTxn,
        options: SyncOptions,
        include_spent: bool,
    ) -> Result<(), Error> {
        self.sync_bdk_and_db_txos(txn, options, include_spent)
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;

    const MAGIC: &[u8] = b"bdk_db";
    const DESC_COLORED: &str = "tr(tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN/0/*,multi_a(2,[05472fdd/86'/827167'/0']tpubDCxjuzxcTK8oYxkCcYdkLc9kJvtiY8RyAcP682DAsscutn5MwVHonbEm4cx9DgtcY6ctED6d3PaGHpZGuGvecAhH7kZTyh4WFmPm9GPqQj5/0/*,[43239ae4/86'/827167'/0']tpubDDcUi4u4JBPgDZquTt1gpHhhia2G8Fmqh5LKzjfiFptWPSATcVxq2v6YaJBEmv34jyGDHGkiyYg77nWyhPzEhqNqYWqX9Ga3eP8x5D2VrbP/0/*,[ca57bd4d/86'/827167'/0']tpubDCN3iBXTTJkKd1scjkrhURLEN3wKNFDbfSaTkWR5Lf6Cxet7e9yvwMxmfV8DQeSL1rX7yuTPBt7DJiyzhWxFjvpShCxuVQUvcAMoYHt4k2a/0/*))";
    const DESC_VANILLA: &str = "tr(tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN/0/*,multi_a(2,[05472fdd/86'/1'/0']tpubDChjb8FBE6RWmMv6W8aL9PysAgZeGELfLmQuDu9VEGycLG8onyN9gwfUwATeSgfWoFmBFr4rd3u4GWpYGBTHGzDkJsjKZPs1AX1krrU5Rig/0/*,[43239ae4/86'/1'/0']tpubDD1u9fzdBAq5G4UiYEgEF8XQdp8go6Ff5ipUBqj4HZqVChLT61vHSEAv3HXeEPgPF85rZrgvfNgb2we1Rje7zTPT5m9BEXDxX9csyW7QGaR/0/*,[ca57bd4d/86'/1'/0']tpubDCmjBvTZXrTatWiUSLKqCWPeA61TAhDpndcKSyAuoWc8EDAagikf4z9hgA3AvXZDPqkB6kEkb5vXTh141ao4ZUePkEERNFEQrmQuzwmJPuF/0/*))";

    /// Persist a real watch-only BDK wallet, like `setup_bdk` + a `persist`.
    fn write_valid_store(path: &Path) {
        let mut store = Store::<ChangeSet>::create(MAGIC, path).unwrap();
        let mut wallet = BdkWallet::create(DESC_COLORED.to_string(), DESC_VANILLA.to_string())
            .network(BdkNetwork::Signet)
            .create_wallet(&mut store)
            .unwrap();
        let _ = wallet.reveal_next_address(KeychainKind::External);
        wallet.persist(&mut store).unwrap();
    }

    /// A torn trailing record (recoverable dump) self-heals and preserves the
    /// corrupt file, leaving a store that loads cleanly with its data intact.
    #[test]
    fn recovers_corrupt_bdk_store_from_tail_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bdk_db_watch_only");
        write_valid_store(&path);
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0x0e]).unwrap();
        drop(f);

        // Today's plain load fails on this file.
        assert!(Store::<ChangeSet>::load_or_create(MAGIC, &path).is_err());

        let (mut store, backup) =
            load_or_recover_bdk_store(MAGIC, &path).expect("torn tail should recover");
        let backup = backup.expect("corrupt file should be preserved");
        assert!(backup.exists(), "corrupt backup kept for forensics");
        let recovered = store
            .dump()
            .expect("clean dump")
            .expect("non-empty changeset");
        assert!(
            recovered.descriptor.is_some(),
            "descriptor survives recovery"
        );
        assert!(
            Store::<ChangeSet>::load_or_create(MAGIC, &path).is_ok(),
            "file on disk now loads cleanly"
        );
    }

    /// Corruption with no recoverable data must surface as an error, never a
    /// silent wipe.
    #[test]
    fn keeps_erroring_when_nothing_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bdk_db_watch_only");
        let _ = Store::<ChangeSet>::create(MAGIC, &path).unwrap();
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[0x0e]).unwrap();
        drop(f);

        let before = std::fs::read(&path).unwrap();
        assert!(load_or_recover_bdk_store(MAGIC, &path).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "unreadable file left untouched"
        );
    }

    /// A healthy store loads unchanged and creates no backup.
    #[test]
    fn passes_through_clean_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bdk_db_watch_only");
        write_valid_store(&path);
        let (_store, backup) = load_or_recover_bdk_store(MAGIC, &path).expect("clean load");
        assert!(backup.is_none(), "no backup for a healthy store");
    }
}
