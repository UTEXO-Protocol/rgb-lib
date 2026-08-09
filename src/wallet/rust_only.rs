//! Rust-only functionality.
//!
//! This module defines additional utility methods that are not exposed via FFI.

use super::*;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::utils::{
    OperationResolver, RgbRuntime, RgbRuntimeLock, acquire_rgb_runtime_lock, hash_bytes_hex,
    load_rgb_runtime_for_operation, prefetch_consignment_witnesses,
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use amplify::confinement::U32 as U32MAX;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use nonasync::persistence::{PersistenceError, PersistenceProvider};
use rgbstd::Operation as _;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use rgbstd::persistence::{MemIndex, MemStash, MemState};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use strict_encoding::StrictSerialize;

#[cfg(all(test, any(feature = "electrum", feature = "esplora")))]
static RGB_PERSISTENCE_STEP: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(test, any(feature = "electrum", feature = "esplora")))]
fn rgb_persistence_checkpoint(name: &str) {
    use std::io::Write as _;
    use std::sync::atomic::Ordering;

    let step = RGB_PERSISTENCE_STEP.fetch_add(1, Ordering::SeqCst) + 1;
    if let Ok(path) = std::env::var("RGB_ACCEPTANCE_TRACE_PATH") {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("open RGB acceptance trace");
        writeln!(file, "{step}:{name}").expect("write RGB acceptance trace");
        file.sync_all().expect("sync RGB acceptance trace");
    }
    let target = std::env::var("RGB_ACCEPTANCE_CRASH_AFTER_STEP")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    if target == Some(step) {
        let path = std::env::var("RGB_ACCEPTANCE_CRASH_READY_PATH")
            .expect("RGB acceptance crash-ready path");
        let mut file = fs::File::create(path).expect("create RGB acceptance crash-ready file");
        writeln!(file, "{step}:{name}").expect("write RGB acceptance crash-ready file");
        file.sync_all()
            .expect("sync RGB acceptance crash-ready file");
        loop {
            std::thread::park();
        }
    }
}

#[cfg(all(not(test), any(feature = "electrum", feature = "esplora")))]
#[inline]
fn rgb_persistence_checkpoint(_name: &str) {}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Clone, Debug)]
struct AcceptanceFsBinStore(FsBinStore);

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl AcceptanceFsBinStore {
    fn new(path: PathBuf) -> Result<Self, Error> {
        rgb_persistence_checkpoint("before-stage-directory-create");
        fs::create_dir(&path)?;
        rgb_persistence_checkpoint("after-stage-directory-create");
        Ok(Self(FsBinStore {
            stash: path.join("stash.dat"),
            state: path.join("state.dat"),
            index: path.join("index.dat"),
        }))
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn write_all_checkpointed(
    file: &mut fs::File,
    bytes: &[u8],
    checkpoint: &str,
) -> std::io::Result<()> {
    const WRITE_CHUNK_SIZE: usize = 4096;

    for (chunk_index, chunk) in bytes.chunks(WRITE_CHUNK_SIZE).enumerate() {
        let mut written = 0;
        while written < chunk.len() {
            rgb_persistence_checkpoint(&format!(
                "before-{checkpoint}-write-{chunk_index}-{written}"
            ));
            let count = file.write(&chunk[written..])?;
            rgb_persistence_checkpoint(&format!(
                "after-{checkpoint}-write-{chunk_index}-{written}"
            ));
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to persist RGB acceptance data",
                ));
            }
            written += count;
        }
    }
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn write_file_durably(path: &Path, bytes: &[u8], checkpoint: &str) -> std::io::Result<()> {
    rgb_persistence_checkpoint(&format!("before-{checkpoint}-create"));
    let mut file = fs::File::create(path)?;
    rgb_persistence_checkpoint(&format!("after-{checkpoint}-create"));
    write_all_checkpointed(&mut file, bytes, checkpoint)?;
    rgb_persistence_checkpoint(&format!("before-{checkpoint}-sync"));
    file.sync_all()?;
    rgb_persistence_checkpoint(&format!("after-{checkpoint}-sync"));
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
macro_rules! impl_acceptance_store {
    ($object:ty, $field:ident, $name:literal) => {
        impl PersistenceProvider<$object> for AcceptanceFsBinStore {
            fn load(&self) -> Result<$object, PersistenceError> {
                <FsBinStore as PersistenceProvider<$object>>::load(&self.0)
            }

            fn store(&self, object: &$object) -> Result<(), PersistenceError> {
                let bytes = object
                    .to_strict_serialized::<U32MAX>()
                    .map_err(PersistenceError::with)?;
                write_file_durably(
                    &self.0.$field,
                    bytes.as_slice(),
                    concat!("stage-store-", $name),
                )
                .map_err(PersistenceError::with)
            }
        }
    };
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl_acceptance_store!(MemStash, stash, "stash");
#[cfg(any(feature = "electrum", feature = "esplora"))]
impl_acceptance_store!(MemState, state, "state");
#[cfg(any(feature = "electrum", feature = "esplora"))]
impl_acceptance_store!(MemIndex, index, "index");

#[cfg(any(feature = "electrum", feature = "esplora"))]
const RGB_ACCEPTANCE_JOURNAL_FILE: &str = "rgb_acceptance_journal.json";

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
enum RgbAcceptanceJournalPhase {
    Prepared,
    Promoting,
    Promoted,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct RgbAcceptanceJournal {
    version: u8,
    operation_id: String,
    phase: RgbAcceptanceJournalPhase,
    stage_dir_name: String,
    backup_dir_name: String,
    #[serde(default)]
    asset_metadata: Option<LocalAssetData>,
}

/// Resolution to apply to a previously promoted RGB transfer acceptance.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RgbAcceptanceResolution {
    /// Keep the promoted RGB stock after the associated protocol state is known to be durable.
    Finalize,
    /// Restore the exact RGB stock that preceded the interrupted protocol operation.
    Rollback,
}

/// Durable metadata for an RGB transfer acceptance awaiting protocol reconciliation.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRgbAcceptance {
    operation_id: String,
    promoted: bool,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl PendingRgbAcceptance {
    /// Stable identifier supplied when the acceptance was prepared.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Whether the staged RGB stock has replaced the previous live stock.
    pub fn promoted(&self) -> bool {
        self.promoted
    }
}

/// A validated RGB transfer whose resulting stock is staged but not visible to the wallet.
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub struct PreparedRgbTransferAcceptance {
    journal: RgbAcceptanceJournal,
    wallet_dir: PathBuf,
    live_runtime: Option<RgbRuntime>,
    consignment: Option<RgbTransfer>,
    assignments: Option<Vec<Assignment>>,
    finished: bool,
}

/// A promoted RGB transfer acceptance awaiting a durable protocol decision.
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub struct PromotedRgbTransferAcceptance {
    journal: RgbAcceptanceJournal,
    wallet_dir: PathBuf,
    consignment: RgbTransfer,
    assignments: Vec<Assignment>,
}

/// A staged RGB fascia whose resulting stock is not yet visible to the wallet.
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub struct PreparedRgbFasciaTransition {
    journal: RgbAcceptanceJournal,
    wallet_dir: PathBuf,
    live_runtime: Option<RgbRuntime>,
    finished: bool,
}

/// A promoted RGB fascia awaiting a durable protocol decision.
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub struct PromotedRgbFasciaTransition {
    journal: RgbAcceptanceJournal,
    wallet_dir: PathBuf,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl PromotedRgbFasciaTransition {
    /// Stable identifier supplied when the fascia was prepared.
    pub fn operation_id(&self) -> &str {
        &self.journal.operation_id
    }

    /// Reconciles the promoted stock with the associated durable protocol state.
    pub fn resolve(self, resolution: RgbAcceptanceResolution) -> Result<(), Error> {
        resolve_rgb_acceptance(&self.wallet_dir, &self.journal.operation_id, resolution)
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl PromotedRgbTransferAcceptance {
    /// Stable identifier supplied when the acceptance was prepared.
    pub fn operation_id(&self) -> &str {
        &self.journal.operation_id
    }

    /// Transfer consignment accepted into the promoted RGB stock.
    pub fn consignment(&self) -> &RgbTransfer {
        &self.consignment
    }

    /// Assignments addressed to the receiving wallet.
    pub fn assignments(&self) -> &[Assignment] {
        &self.assignments
    }

    /// Reconciles the promoted stock with the associated durable protocol state.
    pub fn resolve(self, resolution: RgbAcceptanceResolution) -> Result<(), Error> {
        resolve_rgb_acceptance(&self.wallet_dir, &self.journal.operation_id, resolution)
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl PreparedRgbTransferAcceptance {
    /// Stable identifier supplied when the acceptance was prepared.
    pub fn operation_id(&self) -> &str {
        &self.journal.operation_id
    }

    /// Transfer consignment accepted into the staged RGB stock.
    pub fn consignment(&self) -> &RgbTransfer {
        self.consignment
            .as_ref()
            .expect("prepared consignment must be present")
    }

    /// Assignments addressed to the receiving wallet.
    pub fn assignments(&self) -> &[Assignment] {
        self.assignments
            .as_deref()
            .expect("prepared assignments must be present")
    }

    /// Atomically promotes the staged RGB stock while retaining a rollback snapshot.
    pub fn promote(mut self) -> Result<PromotedRgbTransferAcceptance, Error> {
        promote_staged_rgb_stock(&self.wallet_dir, &mut self.journal, &mut self.live_runtime)?;

        let consignment = self.consignment.take().ok_or_else(|| Error::Internal {
            details: s!("prepared RGB acceptance is missing its consignment"),
        })?;
        let assignments = self.assignments.take().ok_or_else(|| Error::Internal {
            details: s!("prepared RGB acceptance is missing its assignments"),
        })?;
        self.finished = true;
        Ok(PromotedRgbTransferAcceptance {
            journal: self.journal.clone(),
            wallet_dir: self.wallet_dir.clone(),
            consignment,
            assignments,
        })
    }

    /// Discards the staged result without changing the live RGB stock.
    pub fn abort(mut self) -> Result<(), Error> {
        let runtime = self.live_runtime.as_ref().ok_or_else(|| Error::Internal {
            details: s!("prepared RGB acceptance is missing its live runtime"),
        })?;
        rollback_rgb_acceptance_locked(&self.wallet_dir, &self.journal, runtime.lock())?;
        self.finished = true;
        Ok(())
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl PreparedRgbFasciaTransition {
    /// Stable identifier supplied when the fascia was prepared.
    pub fn operation_id(&self) -> &str {
        &self.journal.operation_id
    }

    /// Atomically promotes the staged RGB stock while retaining a rollback snapshot.
    pub fn promote(mut self) -> Result<PromotedRgbFasciaTransition, Error> {
        promote_staged_rgb_stock(&self.wallet_dir, &mut self.journal, &mut self.live_runtime)?;
        self.finished = true;
        Ok(PromotedRgbFasciaTransition {
            journal: self.journal.clone(),
            wallet_dir: self.wallet_dir.clone(),
        })
    }

    /// Discards the staged result without changing the live RGB stock.
    pub fn abort(mut self) -> Result<(), Error> {
        let runtime = self.live_runtime.as_ref().ok_or_else(|| Error::Internal {
            details: s!("prepared RGB acceptance is missing its live runtime"),
        })?;
        rollback_rgb_acceptance_locked(&self.wallet_dir, &self.journal, runtime.lock())?;
        self.finished = true;
        Ok(())
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl Drop for PreparedRgbFasciaTransition {
    fn drop(&mut self) {
        if !self.finished
            && let Some(runtime) = self.live_runtime.as_ref()
        {
            let _ = rollback_rgb_acceptance_locked(&self.wallet_dir, &self.journal, runtime.lock());
        }
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl Drop for PreparedRgbTransferAcceptance {
    fn drop(&mut self) {
        if !self.finished
            && let Some(runtime) = self.live_runtime.as_ref()
        {
            let _ = rollback_rgb_acceptance_locked(&self.wallet_dir, &self.journal, runtime.lock());
        }
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn rgb_acceptance_journal_path(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join(RGB_ACCEPTANCE_JOURNAL_FILE)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn sync_directory(path: &Path, checkpoint: &str) -> Result<(), Error> {
    rgb_persistence_checkpoint(&format!("before-{checkpoint}-open"));
    let directory = fs::File::open(path)?;
    rgb_persistence_checkpoint(&format!("after-{checkpoint}-open"));
    rgb_persistence_checkpoint(&format!("before-{checkpoint}-sync"));
    directory.sync_all()?;
    rgb_persistence_checkpoint(&format!("after-{checkpoint}-sync"));
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn rename_path(from: &Path, to: &Path, checkpoint: &str) -> Result<(), Error> {
    rgb_persistence_checkpoint(&format!("before-{checkpoint}"));
    fs::rename(from, to)?;
    rgb_persistence_checkpoint(&format!("after-{checkpoint}"));
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn promote_staged_rgb_stock_filesystem(
    wallet_dir: &Path,
    journal: &mut RgbAcceptanceJournal,
) -> Result<(), Error> {
    journal.phase = RgbAcceptanceJournalPhase::Promoting;
    write_rgb_acceptance_journal(wallet_dir, journal)?;

    let live_dir = wallet_dir.join(crate::utils::RGB_RUNTIME_DIR);
    let stage_dir = wallet_dir.join(&journal.stage_dir_name);
    let backup_dir = wallet_dir.join(&journal.backup_dir_name);
    if !live_dir.is_dir() || !stage_dir.is_dir() || backup_dir.exists() {
        return Err(Error::Internal {
            details: s!("invalid RGB stock promotion filesystem state"),
        });
    }

    rename_path(&live_dir, &backup_dir, "promote-live-to-backup")?;
    // The rollback copy must be durable before the staged stock can replace the live stock.
    sync_directory(wallet_dir, "promote-sync-backup-installed")?;
    if let Err(error) = rename_path(&stage_dir, &live_dir, "promote-stage-to-live") {
        rename_path(&backup_dir, &live_dir, "promote-restore-live-after-error")?;
        sync_directory(wallet_dir, "promote-sync-error-restore")?;
        return Err(error);
    }
    sync_directory(wallet_dir, "promote-sync-installed-live")?;

    journal.phase = RgbAcceptanceJournalPhase::Promoted;
    write_rgb_acceptance_journal(wallet_dir, journal)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn promote_staged_rgb_stock(
    wallet_dir: &Path,
    journal: &mut RgbAcceptanceJournal,
    live_runtime: &mut Option<RgbRuntime>,
) -> Result<(), Error> {
    live_runtime
        .as_mut()
        .ok_or_else(|| Error::Internal {
            details: s!("prepared RGB acceptance is missing its live runtime"),
        })?
        .suppress_persistence();
    promote_staged_rgb_stock_filesystem(wallet_dir, journal)?;
    drop(live_runtime.take());
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn persist_staged_rgb_stock(
    wallet_dir: &Path,
    operation_id: String,
    mut staged_stock: Stock,
    asset_metadata: Option<LocalAssetData>,
) -> Result<RgbAcceptanceJournal, Error> {
    let digest = hash_bytes_hex(operation_id.as_bytes());
    let journal = RgbAcceptanceJournal {
        version: 1,
        operation_id,
        phase: RgbAcceptanceJournalPhase::Prepared,
        stage_dir_name: format!(".rgb-acceptance-{digest}-stage"),
        backup_dir_name: format!(".rgb-acceptance-{digest}-backup"),
        asset_metadata,
    };
    validate_rgb_acceptance_journal(&journal)?;
    cleanup_orphaned_rgb_acceptance_artifacts(wallet_dir)?;
    let stage_dir = wallet_dir.join(&journal.stage_dir_name);
    let backup_dir = wallet_dir.join(&journal.backup_dir_name);
    remove_path_if_present(&stage_dir, "stale-stage-removed")?;
    remove_path_if_present(&backup_dir, "stale-backup-removed")?;
    let provider = AcceptanceFsBinStore::new(stage_dir.clone())?;
    rgb_persistence_checkpoint("before-stage-provider-attach");
    staged_stock
        .make_persistent(provider, false)
        .map_err(|error| Error::IO {
            details: error.to_string(),
        })?;
    rgb_persistence_checkpoint("after-stage-provider-attach");
    rgb_persistence_checkpoint("before-stage-stock-store");
    staged_stock.store().map_err(|error| Error::IO {
        details: error.to_string(),
    })?;
    rgb_persistence_checkpoint("after-stage-stock-store");
    sync_directory(&stage_dir, "stage-sync-directory")?;
    write_rgb_acceptance_journal(wallet_dir, &journal)?;
    Ok(journal)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn write_rgb_acceptance_journal(
    wallet_dir: &Path,
    journal: &RgbAcceptanceJournal,
) -> Result<(), Error> {
    let path = rgb_acceptance_journal_path(wallet_dir);
    let temporary_path = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec(journal).map_err(|error| Error::IO {
        details: error.to_string(),
    })?;
    write_file_durably(&temporary_path, &bytes, "journal-temp")?;
    rename_path(&temporary_path, &path, "journal-installed")?;
    sync_directory(wallet_dir, "journal-parent-synced")
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn read_rgb_acceptance_journal(wallet_dir: &Path) -> Result<Option<RgbAcceptanceJournal>, Error> {
    let path = rgb_acceptance_journal_path(wallet_dir);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let journal = serde_json::from_slice(&bytes).map_err(|error| Error::IO {
        details: error.to_string(),
    })?;
    Ok(Some(journal))
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn pending_rgb_acceptance_operation(wallet_dir: &Path) -> Result<Option<String>, Error> {
    let Some(journal) = read_rgb_acceptance_journal(wallet_dir)? else {
        return Ok(None);
    };
    validate_rgb_acceptance_journal(&journal)?;
    Ok(Some(journal.operation_id))
}

#[cfg(not(any(feature = "electrum", feature = "esplora")))]
pub(crate) fn pending_rgb_acceptance_operation(
    _wallet_dir: &Path,
) -> Result<Option<String>, Error> {
    Ok(None)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn validate_rgb_runtime_access(
    wallet_dir: &Path,
    operation_id: Option<&str>,
) -> Result<(), Error> {
    let Some(journal) = read_rgb_acceptance_journal(wallet_dir)? else {
        return Ok(());
    };
    validate_rgb_acceptance_journal(&journal)?;
    if operation_id == Some(journal.operation_id.as_str())
        && journal.phase == RgbAcceptanceJournalPhase::Promoted
    {
        return Ok(());
    }
    Err(Error::RgbOperationInProgress {
        operation_id: journal.operation_id,
    })
}

#[cfg(not(any(feature = "electrum", feature = "esplora")))]
pub(crate) fn validate_rgb_runtime_access(
    _wallet_dir: &Path,
    _operation_id: Option<&str>,
) -> Result<(), Error> {
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn validate_rgb_acceptance_journal(journal: &RgbAcceptanceJournal) -> Result<(), Error> {
    let digest = hash_bytes_hex(journal.operation_id.as_bytes());
    let expected_stage = format!(".rgb-acceptance-{digest}-stage");
    let expected_backup = format!(".rgb-acceptance-{digest}-backup");
    if journal.version != 1
        || journal.stage_dir_name != expected_stage
        || journal.backup_dir_name != expected_backup
    {
        return Err(Error::Internal {
            details: s!("invalid RGB acceptance journal"),
        });
    }
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn remove_path_if_present(path: &Path, checkpoint: &str) -> Result<(), Error> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            remove_path_if_present(&entry.path(), checkpoint)?;
        }
        rgb_persistence_checkpoint(&format!("before-{checkpoint}-remove-directory"));
        fs::remove_dir(path)?;
        rgb_persistence_checkpoint(&format!("after-{checkpoint}-remove-directory"));
    } else {
        rgb_persistence_checkpoint(&format!("before-{checkpoint}-remove-file"));
        fs::remove_file(path)?;
        rgb_persistence_checkpoint(&format!("after-{checkpoint}-remove-file"));
    }
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn cleanup_orphaned_rgb_acceptance_artifacts(wallet_dir: &Path) -> Result<(), Error> {
    if rgb_acceptance_journal_path(wallet_dir).exists() {
        return Ok(());
    }
    let mut removed = false;
    for entry in fs::read_dir(wallet_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_acceptance_artifact = name.starts_with(".rgb-acceptance-")
            && (name.ends_with("-stage")
                || name.ends_with("-backup")
                || name.ends_with("-stage.discarded"));
        if is_acceptance_artifact {
            remove_path_if_present(&entry.path(), "orphan-artifact-removed")?;
            removed = true;
        }
    }
    let temporary_journal = rgb_acceptance_journal_path(wallet_dir).with_extension("json.tmp");
    if temporary_journal.exists() {
        remove_path_if_present(&temporary_journal, "orphan-journal-temp-removed")?;
        removed = true;
    }
    if removed {
        sync_directory(wallet_dir, "orphan-cleanup-synced")?;
    }
    Ok(())
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn rollback_rgb_acceptance_locked(
    wallet_dir: &Path,
    journal: &RgbAcceptanceJournal,
    _lock: &RgbRuntimeLock,
) -> Result<(), Error> {
    validate_rgb_acceptance_journal(journal)?;
    let live_dir = wallet_dir.join(crate::utils::RGB_RUNTIME_DIR);
    let stage_dir = wallet_dir.join(&journal.stage_dir_name);
    let backup_dir = wallet_dir.join(&journal.backup_dir_name);

    if backup_dir.exists() {
        let discarded_dir = wallet_dir.join(format!("{}.discarded", journal.stage_dir_name));
        remove_path_if_present(&discarded_dir, "rollback-old-discarded-removed")?;
        if live_dir.exists() {
            rename_path(&live_dir, &discarded_dir, "rollback-live-to-discarded")?;
        }
        rename_path(&backup_dir, &live_dir, "rollback-backup-to-live")?;
        sync_directory(wallet_dir, "rollback-restored-live-synced")?;
        remove_path_if_present(&discarded_dir, "rollback-discarded-removed")?;
    } else if !live_dir.is_dir() {
        return Err(Error::Internal {
            details: s!("RGB rollback has neither live stock nor backup stock"),
        });
    } else {
        let discarded_dir = wallet_dir.join(format!("{}.discarded", journal.stage_dir_name));
        remove_path_if_present(&discarded_dir, "rollback-orphan-discarded-removed")?;
    }
    remove_path_if_present(&stage_dir, "rollback-stage-removed")?;
    let journal_path = rgb_acceptance_journal_path(wallet_dir);
    if journal_path.exists() {
        rgb_persistence_checkpoint("before-rollback-journal-remove");
        fs::remove_file(journal_path)?;
        rgb_persistence_checkpoint("after-rollback-journal-remove");
    }
    sync_directory(wallet_dir, "rollback-cleanup-synced")
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn rollback_rgb_acceptance(wallet_dir: &Path, journal: &RgbAcceptanceJournal) -> Result<(), Error> {
    let lock = acquire_rgb_runtime_lock(wallet_dir)?;
    rollback_rgb_acceptance_locked(wallet_dir, journal, &lock)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn finalize_rgb_acceptance(wallet_dir: &Path, journal: &RgbAcceptanceJournal) -> Result<(), Error> {
    let _lock = acquire_rgb_runtime_lock(wallet_dir)?;
    validate_rgb_acceptance_journal(journal)?;
    if journal.phase != RgbAcceptanceJournalPhase::Promoted
        || !wallet_dir.join(crate::utils::RGB_RUNTIME_DIR).exists()
    {
        return Err(Error::Internal {
            details: s!("RGB acceptance has not been promoted"),
        });
    }
    remove_path_if_present(
        &wallet_dir.join(&journal.stage_dir_name),
        "finalize-stage-removed",
    )?;
    remove_path_if_present(
        &wallet_dir.join(&journal.backup_dir_name),
        "finalize-backup-removed",
    )?;
    sync_directory(wallet_dir, "finalize-stock-cleanup-synced")?;
    let journal_path = rgb_acceptance_journal_path(wallet_dir);
    if journal_path.exists() {
        rgb_persistence_checkpoint("before-finalize-journal-remove");
        fs::remove_file(journal_path)?;
        rgb_persistence_checkpoint("after-finalize-journal-remove");
    }
    sync_directory(wallet_dir, "finalize-journal-removal-synced")
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn resolve_rgb_acceptance(
    wallet_dir: &Path,
    operation_id: &str,
    resolution: RgbAcceptanceResolution,
) -> Result<(), Error> {
    let journal = read_rgb_acceptance_journal(wallet_dir)?.ok_or_else(|| Error::Internal {
        details: s!("RGB acceptance journal not found"),
    })?;
    validate_rgb_acceptance_journal(&journal)?;
    if journal.operation_id != operation_id {
        return Err(Error::Internal {
            details: s!("RGB acceptance operation ID mismatch"),
        });
    }
    match resolution {
        RgbAcceptanceResolution::Finalize if journal.asset_metadata.is_some() => {
            Err(Error::Internal {
                details: s!("RGB transfer acceptance must be finalized through the wallet"),
            })
        }
        RgbAcceptanceResolution::Finalize => finalize_rgb_acceptance(wallet_dir, &journal),
        RgbAcceptanceResolution::Rollback => rollback_rgb_acceptance(wallet_dir, &journal),
    }
}

/// RGB asset-specific information to color a transaction
#[derive(Debug, Clone)]
pub struct AssetColoringInfo {
    /// Map of vouts and asset amounts to color the transaction outputs
    pub output_map: HashMap<u32, u64>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
}

/// RGB information to color a transaction
#[derive(Debug, Clone)]
pub struct ColoringInfo {
    /// Asset-specific information
    pub asset_info_map: HashMap<ContractId, AssetColoringInfo>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
    /// Nonce for offchain TXs ordering
    pub nonce: Option<u64>,
}

/// Result of importing an RGB contract without receiving asset allocations.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportAssetContractResult {
    /// Imported contract ID.
    pub asset_id: String,
    /// Whether the wallet already knew this contract before the call.
    pub already_imported: bool,
    /// Metadata derived from the validated contract.
    pub metadata: Metadata,
}

/// Map of contract ID and list of its beneficiaries
pub type AssetBeneficiariesMap = BTreeMap<ContractId, Vec<BuilderSeal<GraphSeal>>>;

/// Indexer protocol
#[derive(Debug, Clone)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub enum IndexerProtocol {
    /// An indexer implementing the electrum protocol
    Electrum,
    /// An indexer implementing the esplora protocol
    Esplora,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl fmt::Display for IndexerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Return the indexer protocol for the provided URL.
/// An error is raised if the provided indexer URL is invalid or if the service is for the wrong
/// network or doesn't have the required functionality.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn check_indexer_url(
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<IndexerProtocol, Error> {
    let (indexer, _) = get_indexer_and_resolver(indexer_url, bitcoin_network)?;
    let indexer_protocol = match indexer {
        #[cfg(feature = "electrum")]
        Indexer::Electrum(_) => IndexerProtocol::Electrum,
        #[cfg(feature = "esplora")]
        Indexer::Esplora(_) => IndexerProtocol::Esplora,
    };

    Ok(indexer_protocol)
}

/// Return an [`AnyResolver`] for the provided indexer URL, auto-detecting the protocol
/// (Electrum or Esplora).
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn get_resolver(
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<AnyResolver, Error> {
    let (_, resolver) = get_indexer_and_resolver(indexer_url, bitcoin_network)?;
    Ok(resolver)
}

/// Check whether the provided URL points to a valid proxy.
/// An error is raised if the provided proxy URL is invalid or if the service is running an
/// unsupported protocol version.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn check_proxy_url(proxy_url: &str) -> Result<(), Error> {
    check_proxy(proxy_url)
}

/// Validate a consignment using the witness bundled in the consignment (offchain).
/// This works before the witness transaction is broadcast, unlike [`get_resolver`]-based
/// validation which requires the TX to be in the indexer.
///
/// The `txid` is the witness transaction ID (from consignment.post params).
/// The `indexer_url` is used as fallback when the witness is not found in the consignment.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn validate_consignment_offchain(
    file_path: &str,
    txid: &str,
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<ValidateConsignmentResult, Error> {
    use rgbstd::validation::ValidationError;

    let consignment = RgbTransfer::load_file(file_path).map_err(|e| Error::Internal {
        details: format!("Failed to load consignment: {e}"),
    })?;

    let witness_id = RgbTxid::from_str(txid).map_err(|_| Error::InvalidTxid)?;
    let chain_net: ChainNet = bitcoin_network.into();
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let trusted_typesystem = asset_schema.types();

    let fallback_resolver = get_resolver(indexer_url, bitcoin_network)?;

    let resolver = crate::utils::OffchainResolver {
        witness_id,
        consignment: &consignment,
        fallback: &fallback_resolver,
    };

    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem,
        ..Default::default()
    };

    match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid_consignment) => {
            let status = valid_consignment.validation_status();
            Ok(ValidateConsignmentResult {
                valid: true,
                warnings: Some(
                    status
                        .warnings
                        .iter()
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>(),
                ),
                error: None,
                details: None,
            })
        }
        Err(ValidationError::InvalidConsignment(failure)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some(failure.to_string()),
        }),
        Err(ValidationError::ResolverError(e)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("resolver".to_string()),
            details: Some(e.to_string()),
        }),
    }
}

/// Result of consignment validation (offchain or indexer-based).
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct ValidateConsignmentResult {
    /// Whether the consignment is valid.
    pub valid: bool,
    /// Warnings from validation (when valid).
    pub warnings: Option<Vec<String>>,
    /// Error type when invalid ("invalid" or "resolver").
    pub error: Option<String>,
    /// Error details when invalid.
    pub details: Option<String>,
}

/// Validate a consignment using the indexer only (witness TX must be visible to the indexer).
///
/// For transfers where the witness is not on-chain yet, use [`validate_consignment_offchain`].
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn validate_consignment(
    file_path: &str,
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<ValidateConsignmentResult, Error> {
    use rgbstd::validation::ValidationError;

    let consignment = RgbTransfer::load_file(file_path).map_err(|e| Error::Internal {
        details: format!("Failed to load consignment: {e}"),
    })?;

    let chain_net: ChainNet = bitcoin_network.into();
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let trusted_typesystem = asset_schema.types();

    let resolver = get_resolver(indexer_url, bitcoin_network)?;

    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem,
        ..Default::default()
    };

    match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid_consignment) => {
            let status = valid_consignment.validation_status();
            Ok(ValidateConsignmentResult {
                valid: true,
                warnings: Some(
                    status
                        .warnings
                        .iter()
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>(),
                ),
                error: None,
                details: None,
            })
        }
        Err(ValidationError::InvalidConsignment(failure)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some(failure.to_string()),
        }),
        Err(ValidationError::ResolverError(e)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("resolver".to_string()),
            details: Some(e.to_string()),
        }),
    }
}

/// Rust-only APIs of the wallet.
impl Wallet {
    /// Export an RGB contract known to this wallet.
    ///
    /// The returned consignment contains contract identity and history, but no transfer to a new
    /// owner. It can be distributed as public contract metadata and imported with
    /// [`import_asset_contract`](Wallet::import_asset_contract).
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed,
    /// use it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn export_asset_contract(&self, asset_id: String) -> Result<RgbContract, Error> {
        let contract_id = ContractId::from_str(&asset_id).map_err(|error| Error::Internal {
            details: format!("invalid asset ID: {error}"),
        })?;
        self.rgb_runtime()?
            .export_contract(contract_id)
            .map_err(Error::from)
    }

    /// Validate and import an RGB contract without importing any asset allocations.
    ///
    /// This registers the contract and its metadata in the wallet. It does not transfer ownership
    /// and the imported asset therefore starts with a zero balance. Re-importing a known contract
    /// is idempotent and returns the existing metadata.
    ///
    /// Contract attachments are not embedded in a contract consignment. Contracts declaring
    /// attachments must be imported through a flow that supplies and verifies those files.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed,
    /// use it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn import_asset_contract(
        &self,
        contract: RgbContract,
    ) -> Result<ImportAssetContractResult, Error> {
        let contract_id = contract.contract_id();
        let asset_id = contract_id.to_string();

        match self.get_asset_metadata(asset_id.clone()) {
            Ok(metadata) => {
                return Ok(ImportAssetContractResult {
                    asset_id,
                    already_imported: true,
                    metadata,
                });
            }
            Err(Error::AssetNotFound { .. }) => {}
            Err(error) => return Err(error),
        }

        let asset_schema: AssetSchema = contract.schema_id().try_into()?;
        self.check_schema_support(&asset_schema)?;
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem: asset_schema.types(),
            ..Default::default()
        };
        let valid_contract = contract
            .validate(&DumbResolver, &validation_config)
            .map_err(|_| Error::InvalidConsignment)?;

        if !self
            .extract_attachments(&valid_contract, asset_schema)
            .is_empty()
        {
            return Err(Error::InvalidAttachments {
                details: "contract import requires the declared attachment files".to_string(),
            });
        }

        let mut runtime = self.rgb_runtime()?;
        if runtime.export_contract(contract_id).is_err() {
            runtime.import_contract(valid_contract.clone(), &DumbResolver)?;
        }

        let txn = self.database().begin_transaction()?;
        self.save_new_asset_internal(
            &txn,
            &runtime,
            contract_id,
            asset_schema,
            valid_contract,
            None,
        )?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        drop(runtime);
        self.trigger_auto_backup();

        Ok(ImportAssetContractResult {
            asset_id: asset_id.clone(),
            already_imported: false,
            metadata: self.get_asset_metadata(asset_id)?,
        })
    }

    /// Color a PSBT.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger(), "Coloring PSBT...");
        let runtime = self.rgb_runtime()?;
        let result = self.color_psbt_with_runtime(psbt, coloring_info, &runtime)?;
        info!(self.logger(), "Color PSBT completed");
        Ok(result)
    }

    fn color_psbt_with_runtime(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        runtime: &RgbRuntime,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        let mut transaction = match psbt.clone().extract_tx() {
            Ok(tx) => tx,
            Err(ExtractTxError::MissingInputValue { tx }) => tx, // required for non-standard TXs
            Err(e) => return Err(InternalError::from(e).into()),
        };
        let mut opreturn_first = false;
        if transaction.output.iter().any(|o| o.script_pubkey.is_p2tr()) {
            opreturn_first = true;
        }

        if !transaction
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
        {
            let opreturn_output = TxOut {
                value: BdkAmount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            };
            if opreturn_first {
                transaction.output.insert(0, opreturn_output);
            } else {
                transaction.output.push(opreturn_output);
            }
            *psbt = Psbt::from_unsigned_tx(transaction).unwrap();
        }

        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();

        let mut all_transitions: HashMap<ContractId, Transition> = HashMap::new();
        let mut asset_beneficiaries: AssetBeneficiariesMap = bmap![];
        let assignment_name = FieldName::from(RGB_STATE_ASSET_OWNER);

        for (contract_id, asset_coloring_info) in coloring_info.asset_info_map.clone() {
            let schema = AssetSchema::get_from_contract_id(contract_id, runtime)?;

            let mut asset_transition_builder =
                runtime.transition_builder(contract_id, "transfer")?;

            let mut asset_available_amt = 0;
            let mut uda_state = None;
            for (_, opout_state_map) in
                runtime.contract_assignments_for(contract_id, prev_outputs.iter().copied())?
            {
                for (opout, state) in opout_state_map {
                    if let AllocatedState::Amount(amt) = &state {
                        asset_available_amt += amt.as_u64();
                    } else if let AllocatedState::Data(_) = &state {
                        asset_available_amt = 1;
                        // there can be only a single state when contract is UDA
                        uda_state = Some(state.clone());
                    }
                    asset_transition_builder = asset_transition_builder.add_input(opout, state)?;
                }
            }

            let mut beneficiaries = vec![];
            let mut sending_amt = 0;
            for (mut vout, amount) in asset_coloring_info.output_map {
                if amount == 0 {
                    continue;
                }
                if opreturn_first {
                    vout += 1;
                }
                sending_amt += amount;
                if vout as usize > psbt.outputs.len() {
                    return Err(Error::InvalidColoringInfo {
                        details: s!("invalid vout in output_map, does not exist in the given PSBT"),
                    });
                }
                let graph_seal = if let Some(blinding) = asset_coloring_info.static_blinding {
                    GraphSeal::with_blinded_vout(vout, blinding)
                } else {
                    GraphSeal::new_random_vout(vout)
                };
                let seal = BuilderSeal::Revealed(graph_seal);
                beneficiaries.push(seal);

                match schema {
                    AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => {
                        asset_transition_builder = asset_transition_builder.add_fungible_state(
                            assignment_name.clone(),
                            seal,
                            amount,
                        )?;
                    }
                    AssetSchema::Uda => {
                        if let AllocatedState::Data(state) = uda_state.clone().unwrap() {
                            asset_transition_builder = asset_transition_builder
                                .add_data(assignment_name.clone(), seal, Allocation::from(state))
                                .map_err(Error::from)?;
                        }
                    }
                }
            }
            if sending_amt > asset_available_amt {
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "total amount in output_map ({sending_amt}) greater than available ({asset_available_amt})"
                    ),
                });
            }

            if let Some(nonce) = coloring_info.nonce {
                asset_transition_builder = asset_transition_builder.set_nonce(nonce);
            }

            let transition = asset_transition_builder.complete_transition()?;
            all_transitions.insert(contract_id, transition);
            asset_beneficiaries.insert(contract_id, beneficiaries);
        }

        let opreturn_index = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.is_op_return())
            .expect("psbt should have an op_return output")
            .0;
        let opreturn_output = psbt.outputs.get_mut(opreturn_index).unwrap();
        opreturn_output.set_opret_host();
        if let Some(blinding) = coloring_info.static_blinding {
            opreturn_output
                .set_mpc_entropy(blinding)
                .map_err(InternalError::from)?;
        }

        for (contract_id, transition) in all_transitions {
            for opout in transition.inputs() {
                psbt.set_rgb_contract_consumer(contract_id, opout, transition.id())
                    .map_err(InternalError::from)?;
            }
            psbt.push_rgb_transition(transition)
                .map_err(InternalError::from)?;
        }

        psbt.set_rgb_close_method(CloseMethod::OpretFirst);
        psbt.set_as_unmodifiable();
        let fascia = psbt.rgb_commit().map_err(InternalError::from)?;

        Ok((fascia, asset_beneficiaries))
    }

    /// Color a PSBT, consume the RGB fascia and return the related consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt_and_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<Vec<RgbTransfer>, Error> {
        info!(self.logger(), "Coloring PSBT and consuming...");
        let mut runtime = self.rgb_runtime()?;
        let (fascia, asset_beneficiaries) =
            self.color_psbt_with_runtime(psbt, coloring_info, &runtime)?;

        let witness_txid = psbt.get_txid();

        runtime.consume_fascia(fascia, None)?;

        let mut transfers = vec![];
        for (contract_id, beneficiaries) in asset_beneficiaries {
            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer(
                contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                Some(witness_txid),
            )?);
        }

        info!(self.logger(), "Color PSBT and consume completed");
        Ok(transfers)
    }

    /// Color and consume a PSBT while participating in a protocol-owned RGB operation.
    ///
    /// Normal access is preserved when no acceptance journal exists. While a promoted acceptance
    /// is pending, access is granted only when `operation_id` exactly matches that journal. The
    /// stock lock is retained across coloring, transaction extraction validation, consumption, and
    /// persistence so no unrelated wallet operation can observe an intermediate state.
    ///
    /// <div class="warning">This method is meant for protocol integrations that provide their own
    /// durable commit decision.</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn color_psbt_and_consume_for_operation(
        &self,
        operation_id: &str,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        if operation_id.is_empty() {
            return Err(Error::Internal {
                details: s!("RGB protocol operation ID cannot be empty"),
            });
        }

        info!(self.logger(), "Coloring PSBT for RGB protocol operation...");
        let mut runtime = load_rgb_runtime_for_operation(self.wallet_dir(), operation_id)?;
        let (fascia, _) = self.color_psbt_with_runtime(psbt, coloring_info, &runtime)?;
        match psbt.clone().extract_tx() {
            Ok(_) | Err(ExtractTxError::MissingInputValue { .. }) => {}
            Err(error) => return Err(InternalError::from(error).into()),
        }
        runtime.consume_fascia(fascia, witness_ord)?;
        info!(self.logger(), "RGB protocol PSBT coloring completed");
        Ok(())
    }

    /// Create consignments for a PSBT created with the [`send_begin`](Wallet::send_begin) method.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn create_consignments(&self, psbt: String) -> Result<(), Error> {
        info!(self.logger(), "Creating consignments...");

        let psbt = Psbt::from_str(&psbt)?;
        let (_, transfer_dir, info_contents, fascia) = self.get_transfer_end_data(&psbt)?;
        self.gen_consignments(&fascia, &info_contents.transfers, &transfer_dir)?;

        info!(self.logger(), "Create consignments completed");
        Ok(())
    }

    /// Accept an RGB transfer using a TXID to retrieve its consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer(
        &mut self,
        txid: String,
        vout: u32,
        consignment_endpoint: RgbTransport,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        info!(self.logger(), "Accepting transfer...");
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let proxy_url = TransportEndpoint::try_from(consignment_endpoint)?.endpoint;

        let consignment_res = self.get_consignment(&proxy_url, txid.clone())?;
        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;

        let schema_id = consignment.schema_id().to_string();
        let asset_schema: AssetSchema = schema_id.try_into()?;
        self.check_schema_support(&asset_schema)?;
        debug!(
            self.logger(),
            "Got consignment for asset with {} schema", asset_schema
        );

        let fallback_resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };
        let prefetched = prefetch_consignment_witnesses(
            &self.online_data().as_ref().unwrap().indexer_url,
            self.bitcoin_network(),
            &consignment,
            witness_id,
        )?;
        let resolver = OperationResolver::new(&fallback_resolver, prefetched);

        let mut runtime = self.rgb_runtime()?;

        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        runtime.store_secret_seal(graph_seal)?;

        debug!(self.logger(), "Validating consignment...");
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        let trusted_typesystem = asset_schema.types();
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem,
            ..Default::default()
        };
        let valid_consignment = match consignment.clone().validate(&resolver, &validation_config) {
            Ok(consignment) => consignment,
            Err(ValidationError::InvalidConsignment(e)) => {
                error!(self.logger(), "Consignment is invalid: {}", e);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(e)) => {
                warn!(self.logger(), "Network error during consignment validation");
                return Err(Error::Network {
                    details: e.to_string(),
                });
            }
        };
        let validity = valid_consignment.validation_status().validity();
        debug!(self.logger(), "Consignment validity: {:?}", validity);

        let valid_contract = valid_consignment.clone().into_valid_contract();
        runtime.import_contract(valid_contract, &resolver)?;

        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);

        runtime.accept_transfer(valid_consignment, &resolver)?;

        info!(self.logger(), "Accept transfer completed");
        Ok((
            consignment,
            received_rgb_assignments.into_values().collect(),
        ))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn prepare_accept_transfer_consignment(
        &mut self,
        operation_id: String,
        txid: String,
        vout: u32,
        consignment: RgbTransfer,
        blinding: u64,
    ) -> Result<PreparedRgbTransferAcceptance, Error> {
        info!(self.logger(), "Preparing transfer acceptance...");
        if operation_id.is_empty() {
            return Err(Error::Internal {
                details: s!("RGB acceptance operation ID cannot be empty"),
            });
        }
        let wallet_dir = self.wallet_dir().clone();
        if let Some(existing) = read_rgb_acceptance_journal(&wallet_dir)? {
            return Err(Error::Internal {
                details: format!(
                    "RGB acceptance operation '{}' requires reconciliation",
                    existing.operation_id
                ),
            });
        }

        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let asset_schema: AssetSchema = consignment.schema_id().to_string().try_into()?;
        self.check_schema_support(&asset_schema)?;
        let fallback_resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };
        let prefetched = prefetch_consignment_witnesses(
            &self.online_data().as_ref().unwrap().indexer_url,
            self.bitcoin_network(),
            &consignment,
            witness_id,
        )?;
        let resolver = OperationResolver::new(&fallback_resolver, prefetched);

        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem: asset_schema.types(),
            ..Default::default()
        };
        let valid_consignment = match consignment.clone().validate(&resolver, &validation_config) {
            Ok(consignment) => consignment,
            Err(ValidationError::InvalidConsignment(error)) => {
                error!(self.logger(), "Consignment is invalid: {}", error);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(error)) => {
                return Err(Error::Network {
                    details: error.to_string(),
                });
            }
        };
        let assignments = self
            .extract_received_assignments(&consignment, witness_id, Some(vout), None)
            .into_values()
            .collect();
        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        let runtime = self.rgb_runtime()?;
        let contract_id = valid_consignment.contract_id();
        let asset_metadata = {
            let txn = self.database().begin_transaction()?;
            let metadata = if txn.get_asset(contract_id.to_string())?.is_none() {
                Some(self.extract_asset_data(
                    &runtime,
                    contract_id,
                    asset_schema,
                    valid_consignment.clone().into_valid_contract(),
                    Some(valid_consignment.clone()),
                )?)
            } else {
                None
            };
            txn.commit()?;
            metadata
        };
        let staged_stock = runtime.stage_transfer(graph_seal, valid_consignment, &resolver)?;

        let journal =
            persist_staged_rgb_stock(&wallet_dir, operation_id, staged_stock, asset_metadata)?;

        info!(self.logger(), "Prepare transfer acceptance completed");
        Ok(PreparedRgbTransferAcceptance {
            journal,
            wallet_dir,
            live_runtime: Some(runtime),
            consignment: Some(consignment),
            assignments: Some(assignments),
            finished: false,
        })
    }

    /// Validates an RGB transfer and persists its resulting stock in an isolated staging area.
    ///
    /// The live RGB stock remains byte-for-byte unchanged until
    /// [`PreparedRgbTransferAcceptance::promote`] is called. The operation ID must be stable for
    /// the surrounding protocol operation and is used to reconcile interrupted promotion.
    ///
    /// <div class="warning">This method is meant for protocol integrations that provide their
    /// own durable commit decision.</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn prepare_accept_transfer(
        &mut self,
        operation_id: String,
        txid: String,
        vout: u32,
        consignment_endpoint: RgbTransport,
        blinding: u64,
    ) -> Result<PreparedRgbTransferAcceptance, Error> {
        if operation_id.is_empty() {
            return Err(Error::Internal {
                details: s!("RGB acceptance operation ID cannot be empty"),
            });
        }
        if let Some(existing) = read_rgb_acceptance_journal(self.wallet_dir())? {
            return Err(Error::Internal {
                details: format!(
                    "RGB acceptance operation '{}' requires reconciliation",
                    existing.operation_id
                ),
            });
        }

        let proxy_url = TransportEndpoint::try_from(consignment_endpoint)?.endpoint;
        let consignment_res = self.get_consignment(&proxy_url, txid.clone())?;
        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;
        self.prepare_accept_transfer_consignment(operation_id, txid, vout, consignment, blinding)
    }

    /// Validates persisted RGB transfer bytes into the same isolated staging area used by live
    /// transfer acceptance.
    ///
    /// This is intended for deterministic protocol recovery when the surrounding journal already
    /// contains the exact transfer consignment. It does not fetch or trust replacement data from a
    /// transport endpoint.
    ///
    /// <div class="warning">This method is meant for protocol integrations that provide their
    /// own durable commit decision.</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn prepare_accept_transfer_from_consignment(
        &mut self,
        operation_id: String,
        txid: String,
        vout: u32,
        consignment_bytes: Vec<u8>,
        blinding: u64,
    ) -> Result<PreparedRgbTransferAcceptance, Error> {
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;
        self.prepare_accept_transfer_consignment(operation_id, txid, vout, consignment, blinding)
    }

    /// Returns whether the live RGB stock already contains the given contract witness.
    ///
    /// A missing contract is reported as `false`; malformed identifiers and stock corruption are
    /// returned as errors.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn has_accepted_transfer(&self, asset_id: String, txid: String) -> Result<bool, Error> {
        let contract_id = ContractId::from_str(&asset_id).map_err(|error| Error::Internal {
            details: format!("invalid asset ID: {error}"),
        })?;
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        self.rgb_runtime()?
            .contains_transfer_witness(contract_id, witness_id)
            .map_err(Error::from)
    }

    /// Stages a fascia in an isolated RGB stock for a protocol-controlled commit.
    ///
    /// The operation must be finalized or rolled back after the surrounding protocol has made a
    /// durable decision. Until promotion, the live wallet stock is unchanged.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn prepare_consume_fascia(
        &self,
        operation_id: String,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<PreparedRgbFasciaTransition, Error> {
        if operation_id.is_empty() {
            return Err(Error::Internal {
                details: s!("RGB fascia operation ID cannot be empty"),
            });
        }
        let wallet_dir = self.wallet_dir().clone();
        if let Some(existing) = read_rgb_acceptance_journal(&wallet_dir)? {
            return Err(Error::Internal {
                details: format!(
                    "RGB operation '{}' requires reconciliation",
                    existing.operation_id
                ),
            });
        }

        let runtime = self.rgb_runtime()?;
        let staged_stock = runtime.stage_fascia(fascia, witness_ord)?;
        let journal = persist_staged_rgb_stock(&wallet_dir, operation_id, staged_stock, None)?;
        Ok(PreparedRgbFasciaTransition {
            journal,
            wallet_dir,
            live_runtime: Some(runtime),
            finished: false,
        })
    }

    /// Returns a durable RGB acceptance operation awaiting protocol reconciliation, if any.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn pending_rgb_acceptance(&self) -> Result<Option<PendingRgbAcceptance>, Error> {
        let Some(journal) = read_rgb_acceptance_journal(self.wallet_dir())? else {
            return Ok(None);
        };
        validate_rgb_acceptance_journal(&journal)?;
        Ok(Some(PendingRgbAcceptance {
            operation_id: journal.operation_id,
            promoted: journal.phase == RgbAcceptanceJournalPhase::Promoted,
        }))
    }

    /// Resolves a durable RGB acceptance after inspecting the associated protocol state.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn resolve_pending_rgb_acceptance(
        &self,
        operation_id: &str,
        resolution: RgbAcceptanceResolution,
    ) -> Result<(), Error> {
        let journal =
            read_rgb_acceptance_journal(self.wallet_dir())?.ok_or_else(|| Error::Internal {
                details: s!("RGB acceptance journal not found"),
            })?;
        validate_rgb_acceptance_journal(&journal)?;
        if journal.operation_id != operation_id {
            return Err(Error::Internal {
                details: s!("RGB acceptance operation ID mismatch"),
            });
        }

        match resolution {
            RgbAcceptanceResolution::Finalize => {
                if let Some(asset_metadata) = journal.asset_metadata.as_ref() {
                    let txn = self.database().begin_transaction()?;
                    rgb_persistence_checkpoint("metadata-transaction-begun");
                    match txn.get_asset(asset_metadata.asset_id.clone())? {
                        Some(existing) => {
                            if existing.schema != asset_metadata.asset_schema
                                || existing.name != asset_metadata.name
                                || existing.precision != asset_metadata.precision
                                || existing.ticker != asset_metadata.ticker
                                || existing.details != asset_metadata.details
                                || existing.initial_supply
                                    != asset_metadata.initial_supply.to_string()
                                || existing.max_supply
                                    != asset_metadata.max_supply.map(|value| value.to_string())
                                || existing.timestamp != asset_metadata.timestamp
                                || existing.reject_list_url != asset_metadata.reject_list_url
                            {
                                return Err(Error::Internal {
                                    details: format!(
                                        "stored metadata for RGB asset '{}' does not match the validated transfer",
                                        asset_metadata.asset_id
                                    ),
                                });
                            }
                            rgb_persistence_checkpoint("metadata-existing-asset-verified");
                        }
                        None => {
                            self.add_asset_to_db(&txn, asset_metadata)?;
                            rgb_persistence_checkpoint("metadata-asset-inserted");
                            self.update_backup_info(&txn, false)?;
                            rgb_persistence_checkpoint("metadata-backup-info-updated");
                        }
                    }
                    rgb_persistence_checkpoint("metadata-transaction-commit-starting");
                    txn.commit()?;
                    rgb_persistence_checkpoint("metadata-transaction-committed");
                    // Re-notifying is intentional. A process may have died after the database
                    // commit but before the original notification reached the backup worker.
                    rgb_persistence_checkpoint("metadata-backup-notification-starting");
                    self.trigger_auto_backup();
                    rgb_persistence_checkpoint("metadata-backup-notification-completed");
                }
                finalize_rgb_acceptance(self.wallet_dir(), &journal)
            }
            RgbAcceptanceResolution::Rollback => {
                rollback_rgb_acceptance(self.wallet_dir(), &journal)
            }
        }
    }

    /// Consume an RGB fascia.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn consume_fascia(
        &self,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        info!(self.logger(), "Consuming fascia...");
        self.rgb_runtime()?
            .consume_fascia(fascia.clone(), witness_ord)?;
        info!(self.logger(), "Consume fascia completed");
        Ok(())
    }

    /// Get the height for a Bitcoin TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn get_tx_height(&self, txid: String) -> Result<Option<u32>, Error> {
        info!(self.logger(), "Getting TX height...");
        let height = self.tx_height(txid)?;
        info!(self.logger(), "Get TX height completed");
        Ok(height)
    }

    /// Return whether a Bitcoin transaction is visible to the configured indexer.
    ///
    /// Unlike [`Wallet::get_tx_height`], this also returns `true` for a transaction in the
    /// mempool. Protocol recovery code must use this distinction before deciding whether a
    /// staged RGB state transition can be rolled back.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn is_tx_known(&self, txid: String) -> Result<bool, Error> {
        let txid = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        Ok(self
            .indexer()
            .get_tx_confirmations(&txid.to_string())?
            .is_some())
    }

    /// Update RGB witnesses.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn update_witnesses(
        &self,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, Error> {
        info!(self.logger(), "Updating witnesses...");
        let update_res = self.rgb_runtime()?.update_witnesses(
            self.blockchain_resolver(),
            after_height,
            force_witnesses,
        )?;
        info!(self.logger(), "Update witnesses completed");
        Ok(update_res)
    }

    /// Manually set the [`WitnessOrd`] of a witness TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn upsert_witness(
        &self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Error> {
        let mut runtime = self.rgb_runtime()?;
        runtime.upsert_witness(witness_id, witness_ord)?;
        Ok(())
    }

    /// Post a consignment to the proxy server.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn post_consignment<P: AsRef<Path>>(
        &self,
        proxy_url: &str,
        recipient_id: String,
        consignment_path: P,
        txid: String,
        vout: Option<u32>,
    ) -> Result<(), Error> {
        info!(self.logger(), "Posting consignment...");
        let proxy_client = ProxyClient::new(proxy_url)?;
        self.post_consignment_to_proxy(&proxy_client, recipient_id, consignment_path, txid, vout)?;
        info!(self.logger(), "Post consignment completed");
        Ok(())
    }

    /// Extract the metadata of a new RGB asset and save the asset into the DB.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn save_new_asset(
        &self,
        consignment: RgbTransfer,
        offchain_txid: String,
    ) -> Result<(), Error> {
        info!(self.logger(), "Saving new asset...");
        let runtime = self.rgb_runtime()?;

        let contract_id = consignment.contract_id();

        let witness_id = RgbTxid::from_str(&offchain_txid).map_err(|_| Error::InvalidTxid)?;
        let fallback_resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };
        let prefetched = prefetch_consignment_witnesses(
            &self.online_data().as_ref().unwrap().indexer_url,
            self.bitcoin_network(),
            &consignment,
            witness_id,
        )?;
        let resolver = OperationResolver::new(&fallback_resolver, prefetched);
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        let trusted_typesystem = asset_schema.types();
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem,
            ..Default::default()
        };
        let valid_transfer = consignment
            .clone()
            .validate(&resolver, &validation_config)
            .expect("valid consignment");
        let valid_contract = valid_transfer.clone().into_valid_contract();

        let txn = self.database().begin_transaction()?;
        self.save_new_asset_internal(
            &txn,
            &runtime,
            contract_id,
            asset_schema,
            valid_contract,
            Some(valid_transfer),
        )?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();

        info!(self.logger(), "Save new asset completed");
        Ok(())
    }

    /// List the Bitcoin unspents of the vanilla wallet, using BDK's objects, filtered by
    /// `min_confirmations`.
    ///
    /// <div class="warning">This method is meant for special usage, for most cases the method
    /// <code>list_unspents</code> is sufficient</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn list_unspents_vanilla(
        &mut self,
        online: Online,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<Vec<LocalOutput>, Error> {
        info!(self.logger(), "Listing unspents vanilla...");
        let txn = self.database().begin_transaction()?;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::Internal)?;
        txn.commit()?;

        let unspents = self.internal_unspents();

        let res = if min_confirmations > 0 {
            unspents
                .filter_map(|u| {
                    match self
                        .indexer()
                        .get_tx_confirmations(&u.outpoint.txid.to_string())
                    {
                        Ok(confirmations) => {
                            if let Some(confirmations) = confirmations
                                && confirmations >= min_confirmations as u64
                            {
                                return Some(Ok(u));
                            }
                            None
                        }
                        Err(e) => Some(Err(e)),
                    }
                })
                .collect::<Result<Vec<LocalOutput>, Error>>()
        } else {
            Ok(unspents.collect())
        };

        info!(self.logger(), "List unspents vanilla completed");
        res
    }

    /// Return the consignment file path for a send transfer of an asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn get_send_consignment_path(&self, asset_id: &str, transfer_id: &str) -> PathBuf {
        self.send_consignment_path(asset_id, transfer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn acceptance_journal(
        operation_id: &str,
        phase: RgbAcceptanceJournalPhase,
    ) -> RgbAcceptanceJournal {
        let digest = hash_bytes_hex(operation_id.as_bytes());
        RgbAcceptanceJournal {
            version: 1,
            operation_id: operation_id.to_owned(),
            phase,
            stage_dir_name: format!(".rgb-acceptance-{digest}-stage"),
            backup_dir_name: format!(".rgb-acceptance-{digest}-backup"),
            asset_metadata: None,
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn write_marker(directory: &Path, value: &str) {
        fs::create_dir_all(directory).unwrap();
        fs::write(directory.join("marker"), value).unwrap();
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn read_marker(directory: &Path) -> String {
        fs::read_to_string(directory.join("marker")).unwrap()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn run_crash_child(
        mode: &str,
        wallet_dir: &Path,
        crash_after_step: Option<usize>,
        trace_path: Option<&Path>,
        ready_path: Option<&Path>,
    ) -> std::process::ExitStatus {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("--ignored")
            .arg("--exact")
            .arg("wallet::rust_only::tests::rgb_acceptance_crash_child")
            .arg("--nocapture")
            .env("RGB_ACCEPTANCE_CHILD_MODE", mode)
            .env("RGB_ACCEPTANCE_CHILD_WALLET_DIR", wallet_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(step) = crash_after_step {
            command.env("RGB_ACCEPTANCE_CRASH_AFTER_STEP", step.to_string());
        }
        if let Some(path) = trace_path {
            command.env("RGB_ACCEPTANCE_TRACE_PATH", path);
        }
        if let Some(path) = ready_path {
            command.env("RGB_ACCEPTANCE_CRASH_READY_PATH", path);
        }

        let mut child = command.spawn().unwrap();
        if let Some(ready_path) = ready_path {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if ready_path.exists() {
                    child.kill().expect("kill RGB acceptance child");
                    return child.wait().expect("wait for killed RGB acceptance child");
                }
                if let Some(status) = child.try_wait().expect("poll RGB acceptance child") {
                    panic!(
                        "RGB acceptance child exited before crash checkpoint with status {status}"
                    );
                }
                assert!(
                    Instant::now() < deadline,
                    "RGB acceptance child did not reach crash checkpoint"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        child.wait().expect("wait for RGB acceptance child")
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn checkpoint_trace(mode: &str, setup: impl Fn(&Path)) -> Vec<String> {
        let directory = tempfile::tempdir().unwrap();
        setup(directory.path());
        let trace_path = directory.path().join("trace");
        let status = run_crash_child(mode, directory.path(), None, Some(&trace_path), None);
        assert!(
            status.success(),
            "RGB acceptance trace child failed in mode '{mode}'"
        );
        fs::read_to_string(trace_path)
            .unwrap()
            .lines()
            .map(|line| {
                line.split_once(':')
                    .expect("numbered RGB persistence checkpoint")
                    .1
                    .to_owned()
            })
            .collect()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn checkpoint_count(mode: &str, setup: impl Fn(&Path)) -> usize {
        checkpoint_trace(mode, setup).len()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn kill_at_each_checkpoint(
        mode: &str,
        setup: impl Fn(&Path),
        recover_and_assert: impl Fn(&Path),
    ) {
        let checkpoints = checkpoint_count(mode, &setup);
        assert!(
            checkpoints > 0,
            "crash scenario has no persistence checkpoints"
        );
        for step in 1..=checkpoints {
            let directory = tempfile::tempdir().unwrap();
            setup(directory.path());
            let ready_path = directory.path().join("crash-ready");
            let status =
                run_crash_child(mode, directory.path(), Some(step), None, Some(&ready_path));
            assert!(!status.success(), "crash child unexpectedly succeeded");
            recover_and_assert(directory.path());
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn stock_fixture(wallet_dir: &Path, operation_id: &str, phase: RgbAcceptanceJournalPhase) {
        let journal = acceptance_journal(operation_id, phase);
        write_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR), "old");
        write_marker(&wallet_dir.join(&journal.stage_dir_name), "new");
        write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn metadata_test_wallet(data_dir: &Path) -> Wallet {
        const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let keys = crate::keys::restore_keys(
            BitcoinNetwork::Regtest,
            MNEMONIC.to_owned(),
            crate::keys::WitnessVersion::Taproot,
        )
        .unwrap();
        Wallet::new(
            WalletData {
                data_dir: data_dir.to_string_lossy().into_owned(),
                bitcoin_network: BitcoinNetwork::Regtest,
                database_type: DatabaseType::Sqlite,
                max_allocations_per_utxo: 5,
                supported_schemas: AssetSchema::VALUES.to_vec(),
                reuse_addresses: false,
            },
            SinglesigKeys::from_keys(&keys, None),
        )
        .unwrap()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn acceptance_asset_metadata() -> LocalAssetData {
        LocalAssetData {
            asset_id: "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E".to_owned(),
            name: "Crash consistency asset".to_owned(),
            asset_schema: AssetSchema::Nia,
            precision: 2,
            ticker: Some("CRSH".to_owned()),
            details: None,
            media: None,
            initial_supply: 10_000,
            max_supply: None,
            known_circulating_supply: Some(10_000),
            reject_list_url: None,
            token: None,
            timestamp: 1_700_000_000,
            added_at: 1_700_000_000,
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn metadata_finalize_fixture(data_dir: &Path) {
        let wallet = metadata_test_wallet(data_dir);
        let wallet_dir = wallet.wallet_dir();
        let mut journal = acceptance_journal(
            "metadata-finalize-operation",
            RgbAcceptanceJournalPhase::Promoted,
        );
        journal.asset_metadata = Some(acceptance_asset_metadata());
        fs::create_dir_all(wallet_dir.join(&journal.backup_dir_name)).unwrap();
        write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn recover_and_assert_metadata_finalize(data_dir: &Path) {
        let wallet = metadata_test_wallet(data_dir);
        if read_rgb_acceptance_journal(wallet.wallet_dir())
            .unwrap()
            .is_some()
        {
            wallet
                .resolve_pending_rgb_acceptance(
                    "metadata-finalize-operation",
                    RgbAcceptanceResolution::Finalize,
                )
                .unwrap();
        }
        let txn = wallet.database().begin_transaction().unwrap();
        let metadata = acceptance_asset_metadata();
        let stored = txn.get_asset(metadata.asset_id.clone()).unwrap().unwrap();
        assert_eq!(stored.id, metadata.asset_id);
        assert_eq!(stored.schema, metadata.asset_schema);
        assert_eq!(stored.initial_supply, metadata.initial_supply.to_string());
        txn.commit().unwrap();
        assert!(!rgb_acceptance_journal_path(wallet.wallet_dir()).exists());
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    #[ignore = "subprocess used by rgb_acceptance_os_kill_matrix"]
    fn rgb_acceptance_crash_child() {
        RGB_PERSISTENCE_STEP.store(0, std::sync::atomic::Ordering::SeqCst);
        let mode = std::env::var("RGB_ACCEPTANCE_CHILD_MODE").unwrap();
        let wallet_dir = PathBuf::from(std::env::var("RGB_ACCEPTANCE_CHILD_WALLET_DIR").unwrap());
        match mode.as_str() {
            "persist" => {
                persist_staged_rgb_stock(
                    &wallet_dir,
                    "persist-operation".to_owned(),
                    Stock::in_memory(),
                    None,
                )
                .unwrap();
            }
            "promote" => {
                let mut journal = read_rgb_acceptance_journal(&wallet_dir).unwrap().unwrap();
                promote_staged_rgb_stock_filesystem(&wallet_dir, &mut journal).unwrap();
            }
            "rollback" => {
                let journal = read_rgb_acceptance_journal(&wallet_dir).unwrap().unwrap();
                rollback_rgb_acceptance(&wallet_dir, &journal).unwrap();
            }
            "finalize" => {
                let journal = read_rgb_acceptance_journal(&wallet_dir).unwrap().unwrap();
                finalize_rgb_acceptance(&wallet_dir, &journal).unwrap();
            }
            "finalize-metadata" => {
                let wallet = metadata_test_wallet(&wallet_dir);
                wallet
                    .resolve_pending_rgb_acceptance(
                        "metadata-finalize-operation",
                        RgbAcceptanceResolution::Finalize,
                    )
                    .unwrap();
            }
            _ => panic!("unknown RGB acceptance crash mode"),
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn rgb_acceptance_os_kill_matrix() {
        kill_at_each_checkpoint(
            "persist",
            |wallet_dir| write_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR), "old"),
            |wallet_dir| {
                if let Some(journal) = read_rgb_acceptance_journal(wallet_dir).unwrap() {
                    rollback_rgb_acceptance(wallet_dir, &journal).unwrap();
                } else {
                    cleanup_orphaned_rgb_acceptance_artifacts(wallet_dir).unwrap();
                }
                assert_eq!(
                    read_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR)),
                    "old"
                );
            },
        );
        kill_at_each_checkpoint(
            "promote",
            |wallet_dir| {
                stock_fixture(
                    wallet_dir,
                    "promote-operation",
                    RgbAcceptanceJournalPhase::Prepared,
                )
            },
            |wallet_dir| {
                let journal =
                    acceptance_journal("promote-operation", RgbAcceptanceJournalPhase::Promoting);
                rollback_rgb_acceptance(wallet_dir, &journal).unwrap();
                assert_eq!(
                    read_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR)),
                    "old"
                );
            },
        );
        kill_at_each_checkpoint(
            "rollback",
            |wallet_dir| {
                let journal =
                    acceptance_journal("rollback-operation", RgbAcceptanceJournalPhase::Promoted);
                write_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR), "new");
                write_marker(&wallet_dir.join(&journal.backup_dir_name), "old");
                write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();
            },
            |wallet_dir| {
                let journal =
                    acceptance_journal("rollback-operation", RgbAcceptanceJournalPhase::Promoted);
                rollback_rgb_acceptance(wallet_dir, &journal).unwrap();
                assert_eq!(
                    read_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR)),
                    "old"
                );
            },
        );
        kill_at_each_checkpoint(
            "finalize",
            |wallet_dir| {
                let journal =
                    acceptance_journal("finalize-operation", RgbAcceptanceJournalPhase::Promoted);
                write_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR), "new");
                write_marker(&wallet_dir.join(&journal.backup_dir_name), "old");
                write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();
            },
            |wallet_dir| {
                let journal =
                    acceptance_journal("finalize-operation", RgbAcceptanceJournalPhase::Promoted);
                finalize_rgb_acceptance(wallet_dir, &journal).unwrap();
                assert_eq!(
                    read_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR)),
                    "new"
                );
            },
        );
        kill_at_each_checkpoint(
            "finalize-metadata",
            metadata_finalize_fixture,
            recover_and_assert_metadata_finalize,
        );
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn rgb_acceptance_trace_covers_owned_persistence_syscalls() {
        let persist_trace = checkpoint_trace("persist", |wallet_dir| {
            write_marker(&wallet_dir.join(crate::utils::RGB_RUNTIME_DIR), "old")
        });
        for checkpoint in persist_trace
            .iter()
            .filter_map(|checkpoint| checkpoint.strip_prefix("before-"))
        {
            assert!(
                persist_trace.contains(&format!("after-{checkpoint}")),
                "persistence checkpoint '{checkpoint}' has no post-syscall boundary"
            );
        }
        for object in ["stash", "state", "index"] {
            for operation in ["create", "sync"] {
                assert!(
                    persist_trace.contains(&format!("before-stage-store-{object}-{operation}"))
                );
                assert!(persist_trace.contains(&format!("after-stage-store-{object}-{operation}")));
            }
            assert!(persist_trace.iter().any(|checkpoint| {
                checkpoint.starts_with(&format!("before-stage-store-{object}-write-"))
            }));
        }
        for operation in ["create", "sync"] {
            assert!(persist_trace.contains(&format!("before-journal-temp-{operation}")));
            assert!(persist_trace.contains(&format!("after-journal-temp-{operation}")));
        }
        assert!(
            persist_trace
                .iter()
                .any(|checkpoint| checkpoint.starts_with("before-journal-temp-write-"))
        );

        let promotion_trace = checkpoint_trace("promote", |wallet_dir| {
            stock_fixture(
                wallet_dir,
                "promote-operation",
                RgbAcceptanceJournalPhase::Prepared,
            )
        });
        for checkpoint in [
            "before-promote-live-to-backup",
            "after-promote-live-to-backup",
            "before-promote-sync-backup-installed-sync",
            "after-promote-sync-backup-installed-sync",
            "before-promote-stage-to-live",
            "after-promote-stage-to-live",
            "before-promote-sync-installed-live-sync",
            "after-promote-sync-installed-live-sync",
        ] {
            assert!(
                promotion_trace.iter().any(|entry| entry == checkpoint),
                "promotion trace is missing '{checkpoint}'"
            );
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn acceptance_store_is_upstream_fs_bin_store_compatible() {
        let directory = tempfile::tempdir().unwrap();
        write_marker(&directory.path().join(crate::utils::RGB_RUNTIME_DIR), "old");
        let journal = persist_staged_rgb_stock(
            directory.path(),
            "compatibility-operation".to_owned(),
            Stock::in_memory(),
            None,
        )
        .unwrap();
        let provider = FsBinStore::new(directory.path().join(&journal.stage_dir_name)).unwrap();
        let _: Stock =
            Stock::load(provider, false).expect("checkpointed stock bytes load through FsBinStore");
        rollback_rgb_acceptance(directory.path(), &journal).unwrap();
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn live_runtime_is_gated_until_acceptance_is_reconciled() {
        let directory = tempfile::tempdir().unwrap();
        let journal =
            acceptance_journal("exclusive-operation", RgbAcceptanceJournalPhase::Promoted);
        write_rgb_acceptance_journal(directory.path(), &journal).unwrap();

        assert_matches!(
            crate::utils::load_rgb_runtime(directory.path()),
            Err(Error::RgbOperationInProgress { operation_id })
                if operation_id == "exclusive-operation"
        );

        fs::remove_file(rgb_acceptance_journal_path(directory.path())).unwrap();
        assert!(crate::utils::load_rgb_runtime(directory.path()).is_ok());
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn protocol_operation_runtime_access_requires_exact_promoted_owner() {
        let directory = tempfile::tempdir().unwrap();

        drop(
            crate::utils::load_rgb_runtime_for_operation(directory.path(), "normal-operation")
                .unwrap(),
        );

        let promoted = acceptance_journal("funding-operation", RgbAcceptanceJournalPhase::Promoted);
        write_rgb_acceptance_journal(directory.path(), &promoted).unwrap();

        assert_matches!(
            crate::utils::load_rgb_runtime_for_operation(directory.path(), "foreign-operation"),
            Err(Error::RgbOperationInProgress { operation_id })
                if operation_id == "funding-operation"
        );
        assert_matches!(
            crate::utils::load_rgb_runtime(directory.path()),
            Err(Error::RgbOperationInProgress { operation_id })
                if operation_id == "funding-operation"
        );
        drop(
            crate::utils::load_rgb_runtime_for_operation(directory.path(), "funding-operation")
                .unwrap(),
        );

        let prepared = acceptance_journal("funding-operation", RgbAcceptanceJournalPhase::Prepared);
        write_rgb_acceptance_journal(directory.path(), &prepared).unwrap();
        assert_matches!(
            crate::utils::load_rgb_runtime_for_operation(directory.path(), "funding-operation"),
            Err(Error::RgbOperationInProgress { operation_id })
                if operation_id == "funding-operation"
        );
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn protocol_operation_waiter_rechecks_owner_after_acquiring_lock() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_dir = directory.path().to_path_buf();
        let mut active_runtime = crate::utils::load_rgb_runtime(&wallet_dir).unwrap();
        active_runtime.suppress_persistence();
        let journal = acceptance_journal(
            "contended-funding-operation",
            RgbAcceptanceJournalPhase::Promoted,
        );
        write_rgb_acceptance_journal(&wallet_dir, &journal).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiting_wallet_dir = wallet_dir.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            crate::utils::load_rgb_runtime_for_operation(
                waiting_wallet_dir,
                "contended-funding-operation",
            )
        });
        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "protocol operation did not wait for the stock lock"
        );

        drop(active_runtime);
        drop(waiter.join().unwrap().unwrap());
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn runtime_waiter_rechecks_acceptance_journal_after_acquiring_lock() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_dir = directory.path().to_path_buf();
        let mut active_runtime = crate::utils::load_rgb_runtime(&wallet_dir).unwrap();
        active_runtime.suppress_persistence();
        let journal =
            acceptance_journal("contended-operation", RgbAcceptanceJournalPhase::Promoted);
        write_rgb_acceptance_journal(&wallet_dir, &journal).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let waiting_wallet_dir = wallet_dir.clone();
        let waiter = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            crate::utils::load_rgb_runtime(waiting_wallet_dir)
        });
        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !waiter.is_finished(),
            "second runtime did not wait for the lock"
        );

        drop(active_runtime);
        let waiter_result = waiter.join().unwrap();
        assert_matches!(
            waiter_result,
            Err(Error::RgbOperationInProgress { operation_id })
                if operation_id == "contended-operation"
        );

        finalize_rgb_acceptance(&wallet_dir, &journal).unwrap();
        assert!(crate::utils::load_rgb_runtime(wallet_dir).is_ok());
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn display_indexer_protocol() {
        assert_eq!(IndexerProtocol::Electrum.to_string(), "Electrum");
        assert_eq!(IndexerProtocol::Esplora.to_string(), "Esplora");
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn prepared_acceptance_rollback_leaves_live_stock_unchanged() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_dir = directory.path();
        let journal = acceptance_journal("prepared", RgbAcceptanceJournalPhase::Prepared);
        let live_dir = wallet_dir.join(crate::utils::RGB_RUNTIME_DIR);
        let stage_dir = wallet_dir.join(&journal.stage_dir_name);
        write_marker(&live_dir, "old");
        write_marker(&stage_dir, "new");
        write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();

        rollback_rgb_acceptance(wallet_dir, &journal).unwrap();

        assert_eq!(read_marker(&live_dir), "old");
        assert!(!stage_dir.exists());
        assert!(!rgb_acceptance_journal_path(wallet_dir).exists());
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn interrupted_promotion_before_live_install_restores_backup() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_dir = directory.path();
        let journal = acceptance_journal("before-install", RgbAcceptanceJournalPhase::Promoting);
        let live_dir = wallet_dir.join(crate::utils::RGB_RUNTIME_DIR);
        let stage_dir = wallet_dir.join(&journal.stage_dir_name);
        let backup_dir = wallet_dir.join(&journal.backup_dir_name);
        write_marker(&backup_dir, "old");
        write_marker(&stage_dir, "new");
        write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();

        rollback_rgb_acceptance(wallet_dir, &journal).unwrap();

        assert_eq!(read_marker(&live_dir), "old");
        assert!(!stage_dir.exists());
        assert!(!backup_dir.exists());
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn interrupted_promotion_after_live_install_restores_backup() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_dir = directory.path();
        let journal = acceptance_journal("after-install", RgbAcceptanceJournalPhase::Promoting);
        let live_dir = wallet_dir.join(crate::utils::RGB_RUNTIME_DIR);
        let backup_dir = wallet_dir.join(&journal.backup_dir_name);
        write_marker(&backup_dir, "old");
        write_marker(&live_dir, "new");
        write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();

        rollback_rgb_acceptance(wallet_dir, &journal).unwrap();

        assert_eq!(read_marker(&live_dir), "old");
        assert!(!backup_dir.exists());
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn finalized_promotion_keeps_new_stock_and_removes_rollback_state() {
        let directory = tempfile::tempdir().unwrap();
        let wallet_dir = directory.path();
        let journal = acceptance_journal("finalize", RgbAcceptanceJournalPhase::Promoted);
        let live_dir = wallet_dir.join(crate::utils::RGB_RUNTIME_DIR);
        let backup_dir = wallet_dir.join(&journal.backup_dir_name);
        write_marker(&backup_dir, "old");
        write_marker(&live_dir, "new");
        write_rgb_acceptance_journal(wallet_dir, &journal).unwrap();

        finalize_rgb_acceptance(wallet_dir, &journal).unwrap();

        assert_eq!(read_marker(&live_dir), "new");
        assert!(!backup_dir.exists());
        assert!(!rgb_acceptance_journal_path(wallet_dir).exists());
    }
}
