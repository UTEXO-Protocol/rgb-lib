use super::*;

use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use bdk_wallet::bitcoin::secp256k1::rand::rngs::OsRng;
use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};

use std::collections::HashMap;
use std::sync::Arc;

use crate::wallet::vss::{VssBackupClient, VssBackupConfig};
use vss_client::util::retry::{
    ExponentialBackoffRetryPolicy, MaxAttemptsRetryPolicy, MaxTotalDelayRetryPolicy, RetryPolicy,
};

pub(crate) const DEFAULT_VSS_SERVER_URL: &str = "http://localhost:8081/vss";

// Common VSS object keys used by rgb-lib backups.
pub(crate) const VSS_KEY_DATA: &str = "backup/data";
pub(crate) const VSS_KEY_METADATA: &str = "backup/metadata";
pub(crate) const VSS_KEY_MANIFEST: &str = "backup/manifest";
pub(crate) const VSS_KEY_FINGERPRINT: &str = "backup/fingerprint";
pub(crate) const VSS_KEY_CHUNK_PREFIX: &str = "backup/chunk/";
pub(crate) const VSS_KEY_CHUNK0: &str = "backup/chunk/0";

// -------- Wallet state summaries (restore assertions) --------

#[cfg(feature = "electrum")]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WalletStateSnapshot {
    pub(crate) asset_inventory: Vec<(u8, String)>,
    pub(crate) rgb_balance: Balance,
    pub(crate) rgb_metadata: Metadata,
    pub(crate) transfers: Vec<TransferSummary>,
    pub(crate) transactions: Vec<(u8, String, u64, u64, u64)>,
    pub(crate) btc_balance: BtcBalance,
    pub(crate) unspents_colorable: usize,
}

#[cfg(feature = "electrum")]
pub(crate) fn snapshot_wallet_state(
    wallet: &mut Wallet,
    online: &Online,
    asset_id: &str,
) -> Result<WalletStateSnapshot, Error> {
    let assets = wallet.list_assets(vec![])?;
    let mut asset_inventory: Vec<(u8, String)> = Vec::new();
    if let Some(nia) = assets.nia {
        asset_inventory.extend(
            nia.into_iter()
                .map(|a| (AssetSchema::Nia as u8, a.asset_id)),
        );
    }
    if let Some(uda) = assets.uda {
        asset_inventory.extend(
            uda.into_iter()
                .map(|a| (AssetSchema::Uda as u8, a.asset_id)),
        );
    }
    if let Some(cfa) = assets.cfa {
        asset_inventory.extend(
            cfa.into_iter()
                .map(|a| (AssetSchema::Cfa as u8, a.asset_id)),
        );
    }
    if let Some(ifa) = assets.ifa {
        asset_inventory.extend(
            ifa.into_iter()
                .map(|a| (AssetSchema::Ifa as u8, a.asset_id)),
        );
    }
    asset_inventory.sort();

    let rgb_balance = wallet.get_asset_balance(asset_id.to_string())?;
    let rgb_metadata = wallet.get_asset_metadata(asset_id.to_string())?;
    let transfers = summarize_transfers(wallet, asset_id)?;
    let transactions = summarize_transactions(wallet, online)?;
    let btc_balance = wallet.get_btc_balance(Some(*online), false)?;

    // Unspents summary (DB-level): avoid extra network sync; `refresh()` should have been called by
    // the test already.
    let unspents = wallet.list_unspents(None, false, true)?;
    let unspents_colorable = unspents.iter().filter(|u| u.utxo.colorable).count();
    Ok(WalletStateSnapshot {
        asset_inventory,
        rgb_balance,
        rgb_metadata,
        transfers,
        transactions,
        btc_balance,
        unspents_colorable,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransferSummary {
    pub(crate) status: TransferStatus,
    pub(crate) kind: TransferKind,
    pub(crate) txid: Option<String>,
    pub(crate) requested_assignment: Option<Assignment>,
    pub(crate) assignments: Vec<Assignment>,
    pub(crate) recipient_id: Option<String>,
    pub(crate) receive_utxo: Option<Outpoint>,
    pub(crate) change_utxo: Option<Outpoint>,
}

fn kind_order(kind: &TransferKind) -> u8 {
    match kind {
        TransferKind::Issuance => 0,
        TransferKind::ReceiveBlind => 1,
        TransferKind::ReceiveWitness => 2,
        TransferKind::Send => 3,
        TransferKind::Inflation => 4,
    }
}

pub(crate) fn summarize_transfers(
    wallet: &Wallet,
    asset_id: &str,
) -> Result<Vec<TransferSummary>, Error> {
    let mut transfers = wallet.list_transfers(Some(asset_id.to_string()))?;
    transfers.sort_by_key(|t| (kind_order(&t.kind), t.txid.clone().unwrap_or_default()));
    Ok(transfers
        .into_iter()
        .map(|t| TransferSummary {
            status: t.status,
            kind: t.kind,
            txid: t.txid,
            requested_assignment: t.requested_assignment,
            assignments: t.assignments,
            recipient_id: t.recipient_id,
            receive_utxo: t.receive_utxo,
            change_utxo: t.change_utxo,
        })
        .collect())
}

fn transaction_type_code(ty: &TransactionType) -> u8 {
    match ty {
        TransactionType::RgbSend => 0,
        TransactionType::Drain => 1,
        TransactionType::CreateUtxos => 2,
        TransactionType::User => 3,
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn summarize_transactions(
    wallet: &mut Wallet,
    online: &Online,
) -> Result<Vec<(u8, String, u64, u64, u64)>, Error> {
    let mut txs = wallet.list_transactions(Some(*online), false)?;
    txs.sort_by_key(|t| t.txid.clone());
    Ok(txs
        .into_iter()
        .map(|t| {
            (
                transaction_type_code(&t.transaction_type),
                t.txid,
                t.received,
                t.sent,
                t.fee,
            )
        })
        .collect())
}

// -------- Raw VSS client helpers (key inspection) --------

type RawRetryPolicy = MaxTotalDelayRetryPolicy<
    MaxAttemptsRetryPolicy<ExponentialBackoffRetryPolicy<vss_client::error::VssError>>,
>;
pub(crate) type RawVssClient = vss_client::client::VssClient<RawRetryPolicy>;

pub(crate) fn build_raw_vss_client(server_url: &str, signing_key: SecretKey) -> RawVssClient {
    let auth_provider =
        vss_client::headers::sigs_auth::SigsAuthProvider::new(signing_key, HashMap::new());
    let retry_policy = ExponentialBackoffRetryPolicy::new(Duration::from_millis(100))
        .with_max_attempts(3)
        .with_max_total_delay(Duration::from_secs(5));
    vss_client::client::VssClient::new_with_headers(
        server_url.to_string(),
        retry_policy,
        Arc::new(auth_provider),
    )
}

pub(crate) async fn get_vss_key(
    raw: &RawVssClient,
    store_id: &str,
    key: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let req = vss_client::types::GetObjectRequest {
        store_id: store_id.to_string(),
        key: key.to_string(),
    };
    let resp = raw.get_object(&req).await?;
    let kv = resp
        .value
        .ok_or_else(|| format!("VSS key missing: {key}"))?;
    Ok(kv.value)
}

pub(crate) async fn vss_key_exists(
    raw: &RawVssClient,
    store_id: &str,
    key: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let req = vss_client::types::GetObjectRequest {
        store_id: store_id.to_string(),
        key: key.to_string(),
    };
    match raw.get_object(&req).await {
        Ok(resp) => Ok(resp.value.is_some()),
        Err(e) => {
            let msg = format!("{e:?}");
            if msg.contains("NoSuchKey")
                || msg.to_lowercase().contains("not found")
                || msg.contains("Requested key not found")
            {
                Ok(false)
            } else {
                Err(e.into())
            }
        }
    }
}

pub(crate) async fn assert_vss_key_missing(
    raw: &RawVssClient,
    store_id: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match get_vss_key(raw, store_id, key).await {
        Ok(_) => Err(format!("VSS key unexpectedly exists: {key}").into()),
        Err(e) => {
            let msg = format!("{e:?}");
            // Be tolerant: exact error text depends on VSS implementation.
            if msg.contains("NoSuchKey")
                || msg.to_lowercase().contains("not found")
                || msg.contains("Requested key not found")
            {
                Ok(())
            } else {
                Err(format!("unexpected error when checking missing key {key}: {msg}").into())
            }
        }
    }
}

pub(crate) fn list_zip_names(zip_bytes: &[u8]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader)?;
    let mut names = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        names.push(archive.by_index(i)?.name().to_string());
    }
    names.sort();
    Ok(names)
}

pub(crate) fn vss_server_url() -> String {
    std::env::var("VSS_SERVER_URL").unwrap_or_else(|_| DEFAULT_VSS_SERVER_URL.to_string())
}

pub(crate) fn generate_signing_key_and_store_id(prefix: &str) -> (SecretKey, String) {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    let suffix = hex::encode(&public_key.serialize()[0..8]);
    (secret_key, format!("{prefix}_{suffix}"))
}

pub(crate) fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
}

pub(crate) fn dir_has_any_subdir(root: &Path) -> bool {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for e in entries.flatten() {
        if let Ok(ft) = e.file_type()
            && ft.is_dir()
        {
            return true;
        }
    }
    false
}

pub(crate) fn write_random_file(
    path: &Path,
    bytes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use bdk_wallet::bitcoin::secp256k1::rand::RngCore;
    use std::io::Write;

    let mut f = std::fs::File::create(path)?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut rng = OsRng;
    let mut remaining = bytes;
    while remaining > 0 {
        rng.fill_bytes(&mut buf);
        let n = remaining.min(buf.len());
        f.write_all(&buf[..n])?;
        remaining -= n;
    }
    f.sync_all()?;
    Ok(())
}

pub(crate) fn parse_host_port_from_http_url(url: &str) -> Result<(String, u16), String> {
    let after_scheme = url
        .split("://")
        .nth(1)
        .ok_or_else(|| format!("unsupported url (missing scheme): {url}"))?;
    let host_port = after_scheme
        .split('/')
        .next()
        .ok_or_else(|| format!("unsupported url (missing host): {url}"))?;
    let mut it = host_port.split(':');
    let host = it
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("unsupported url host: {url}"))?
        .to_string();
    let port = it
        .next()
        .unwrap_or("80")
        .parse::<u16>()
        .map_err(|e| format!("unsupported url port in {url}: {e}"))?;
    Ok((host, port))
}

pub(crate) fn wait_tcp_up_http_url(
    url: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    let (host, port) = parse_host_port_from_http_url(url)?;
    let start = Instant::now();
    let mut last_err: Option<String> = None;
    while start.elapsed() < timeout {
        match TcpStream::connect_timeout(
            &(format!("{host}:{port}")
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| format!("cannot resolve {host}:{port}"))?),
            Duration::from_secs(1),
        ) {
            Ok(_) => return Ok(()),
            Err(e) => {
                last_err = Some(format!("{e}"));
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    Err(format!(
        "service at {host}:{port} did not become reachable within {timeout:?} (last error: {})",
        last_err.unwrap_or_else(|| "unknown".to_string())
    )
    .into())
}

pub(crate) fn docker_compose(args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("docker")
        .args(["compose", "-f", "./tests/compose.yaml"])
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("docker compose {:?} failed", args).into());
    }
    Ok(())
}

pub(crate) fn stop_vss_server() -> Result<(), Box<dyn std::error::Error>> {
    docker_compose(&["stop", "vss-server"])
}

pub(crate) fn start_vss_server() -> Result<(), Box<dyn std::error::Error>> {
    docker_compose(&["start", "vss-server"])
}

pub(crate) struct VssServerRestartGuard {
    restarted: bool,
}

impl VssServerRestartGuard {
    pub(crate) fn new() -> Self {
        Self { restarted: false }
    }

    pub(crate) fn mark_restarted(&mut self) {
        self.restarted = true;
    }
}

impl Drop for VssServerRestartGuard {
    fn drop(&mut self) {
        if self.restarted {
            return;
        }
        if let Err(e) = start_vss_server() {
            eprintln!("VssServerRestartGuard: fallback restart failed: {e}");
        }
    }
}

pub(crate) fn vss_backup_retry_on_version_conflict(
    rt: &tokio::runtime::Runtime,
    wallet: &Wallet,
    client: &VssBackupClient,
    attempts: u8,
) -> Result<i64, Error> {
    for i in 1..=attempts {
        match rt.block_on(wallet.vss_backup(client)) {
            Ok(v) => return Ok(v),
            Err(Error::VssVersionConflict { details }) if i < attempts => {
                eprintln!(
                    "Transient VssVersionConflict during vss_backup (attempt {i}/{attempts}): {details}"
                );
                std::thread::sleep(Duration::from_millis(200 * i as u64));
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::Internal {
        details: "vss_backup failed after retries".to_string(),
    })
}

/// Best-effort cleanup for VSS test data.
///
/// Use this guard in tests that create a VSS backup so that even if the test panics, we still try
/// to delete the backup objects from the server.
///
/// Notes:
/// - Cleanup is best-effort: errors are ignored.
/// - Do NOT use this guard for "bad URL"/unreachable URL tests, as the delete attempt may block on
///   network timeouts and make the test suite slower.
pub(crate) struct VssBackupDeleteGuard {
    config: Option<VssBackupConfig>,
}

impl VssBackupDeleteGuard {
    pub(crate) fn new(config: VssBackupConfig) -> Self {
        Self {
            config: Some(config),
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.config = None;
    }
}

impl Drop for VssBackupDeleteGuard {
    fn drop(&mut self) {
        let Some(config) = self.config.take() else {
            return;
        };
        let client = match VssBackupClient::new(config) {
            Ok(c) => c,
            Err(_) => return,
        };
        let _ = client.handle().block_on(client.delete_backup());
    }
}
