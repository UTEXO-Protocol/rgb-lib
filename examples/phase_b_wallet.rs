//! RGB lock/claim helper for local RFQ e2e.
//!
//! Usage:
//!   MNEMONIC=... WALLET_DIR=... cargo run --example phase_b_wallet --features electrum -- info
//!   ... -- sign <psbt_base64>
//!   ... -- broadcast <signed_psbt>
//!   ... -- lock-send <witness_invoice> [amount_sat]   # prints signed_psbt=; BROADCAST=1 to send_end
//!   ... -- register-htlc <script_pubkey_hex> <asset_id> <asset_amount>
//!   RESOLVER_PRIVKEY=02.. COLOR_RGB=1 ... -- claim <offer.json>
//!   REFUNDER_PRIVKEY=.. COLOR_RGB=1 ... -- refund <offer.json>

use std::collections::HashMap;
use std::env;
use std::fs;
use std::str::FromStr;

use rgb_lib::bitcoin::consensus::encode::{deserialize as deserialize_tx, serialize as serialize_tx};
use rgb_lib::bitcoin::hashes::Hash;
use rgb_lib::bitcoin::hashes::hex::FromHex;
use rgb_lib::bitcoin::key::Keypair;
use rgb_lib::bitcoin::psbt::Psbt;
use rgb_lib::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use rgb_lib::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use rgb_lib::bitcoin::taproot::LeafVersion;
use rgb_lib::bitcoin::{ScriptBuf, Transaction, TxOut, Witness};
use rgb_lib::keys::{WitnessVersion, restore_keys};
use rgb_lib::wallet::rust_only::{AssetColoringInfo, ColoringInfo};
use rgb_lib::wallet::{
    DatabaseType, Invoice, Online, OnlineOptions, Recipient, RgbWalletOpsOffline, RgbWalletOpsOnline,
    SinglesigKeys, SyncKeychain, SyncOptions, SyncStrategy, Wallet, WalletData, WitnessData,
};
use rgb_lib::{AssetSchema, Assignment, BitcoinNetwork, ContractId, FileContent};
use serde::Deserialize;

fn electrum_url() -> String {
    // romanz/electrs (verbose tx). NOT electrs-esplora on :50004 — rgb-lib rejects it.
    env::var("ELECTRUM_URL").unwrap_or_else(|_| "127.0.0.1:50001".to_owned())
}

fn esplora_api_base() -> String {
    env::var("ESPLORA_API_URL").unwrap_or_else(|_| "http://127.0.0.1:8094/regtest/api".to_owned())
}

fn open_wallet() -> Result<Wallet, Box<dyn std::error::Error>> {
    open_wallet_opts(None)
}

fn open_wallet_opts(force_reuse_addresses: Option<bool>) -> Result<Wallet, Box<dyn std::error::Error>> {
    let mnemonic = env::var("MNEMONIC").map_err(|_| "set MNEMONIC env var")?;
    let wallet_dir = env::var("WALLET_DIR").map_err(|_| "set WALLET_DIR env var")?;

    let keys = restore_keys(BitcoinNetwork::Regtest, mnemonic, WitnessVersion::Taproot)?;
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);

    let wallet_data = WalletData {
        data_dir: wallet_dir,
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: 5,
        supported_schemas: vec![
            AssetSchema::Nia,
            AssetSchema::Uda,
            AssetSchema::Cfa,
            AssetSchema::Ifa,
        ],
        // Default false so register-htlc can fetch lock consignments posted under
        // the bare script recipient_id. Claim/refund force reuse so each spend to
        // the same script gets a unique rid_nonce for proxy post_consignment.
        reuse_addresses: force_reuse_addresses.unwrap_or_else(|| {
            env::var("REUSE_ADDRESSES").ok().as_deref() == Some("1")
        }),
    };

    Ok(Wallet::new(wallet_data, wallet_keys)?)
}

fn go_online(wallet: &mut Wallet) -> Result<Online, Box<dyn std::error::Error>> {
    let skip_consistency_check = env::var("SKIP_CONSISTENCY_CHECK").ok().as_deref() == Some("1");
    Ok(wallet.go_online(OnlineOptions {
        indexer_url: electrum_url(),
        skip_consistency_check,
        vanilla_sync_lookback: 20,
    })?)
}

fn sync_wallet(wallet: &mut Wallet, online: Online) -> Result<(), Box<dyn std::error::Error>> {
    for keychain in [SyncKeychain::Colored, SyncKeychain::Vanilla { lookback: 20 }] {
        wallet.sync(
            online.clone(),
            SyncOptions {
                keychain,
                strategy: SyncStrategy::FullSync,
            },
        )?;
    }
    Ok(())
}

fn http_get(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resp = minreq::get(url)
        .send()
        .map_err(|e| format!("http get {url}: {e}"))?;
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(format!("http get {url}: status {}", resp.status_code).into());
    }
    Ok(resp.as_str()?.to_owned())
}

fn http_post_json(url: &str, body: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resp = minreq::post(url)
        .with_header("Content-Type", "application/json")
        .with_body(body)
        .send()
        .map_err(|e| format!("http post {url}: {e}"))?;
    if resp.status_code < 200 || resp.status_code >= 300 {
        return Err(format!("http post {url}: status {}", resp.status_code).into());
    }
    Ok(resp.as_str()?.to_owned())
}

fn fetch_tx_hex(txid: &str) -> Result<String, Box<dyn std::error::Error>> {
    let base = esplora_api_base();
    match http_get(&format!("{base}/tx/{txid}/hex")) {
        Ok(hex) => return Ok(hex.trim().to_owned()),
        Err(e) => eprintln!("esplora tx hex failed ({e}); trying bitcoind"),
    }
    // Fallback 1: bitcoind JSON-RPC (btc-rpc-proxy or local node).
    let rpc_url = env::var("BITCOIN_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18443".to_owned());
    let body = format!(
        r#"{{"jsonrpc":"1.0","id":"tx","method":"getrawtransaction","params":["{txid}"]}}"#
    );
    if let Ok(raw) = http_post_json(&rpc_url, &body) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if v.get("error").map(|e| e.is_null()).unwrap_or(false) {
                if let Some(hex) = v.get("result").and_then(|r| r.as_str()) {
                    return Ok(hex.to_owned());
                }
            }
        }
    }
    // Fallback 2: docker bitcoin-cli (rgb-lib tests stack).
    let user = env::var("BTC_RPC_USER").unwrap_or_else(|_| "user".to_owned());
    let pass = env::var("BTC_RPC_PASS").unwrap_or_else(|_| "default_password".to_owned());
    let out = std::process::Command::new("docker")
        .args([
            "exec",
            "tests-bitcoind-1",
            "/opt/bitcoin/bin/bitcoin-cli",
            "-regtest",
            &format!("-rpcuser={user}"),
            &format!("-rpcpassword={pass}"),
            "getrawtransaction",
            txid,
        ])
        .output()
        .map_err(|e| format!("docker bitcoin-cli: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "bitcoin-cli getrawtransaction failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// RFQ lock PSBTs often omit witness/non-witness UTXO. Fill them from esplora so BDK can sign.
fn fill_psbt_utxos(psbt_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut psbt = Psbt::from_str(psbt_b64)?;

    for (idx, input) in psbt.inputs.iter_mut().enumerate() {
        if input.witness_utxo.is_some() && input.non_witness_utxo.is_some() {
            continue;
        }
        let txin = psbt
            .unsigned_tx
            .input
            .get(idx)
            .ok_or_else(|| format!("psbt missing unsigned input {idx}"))?;
        let txid = txin.previous_output.txid;
        let vout = txin.previous_output.vout;
        let hex = fetch_tx_hex(&txid.to_string())?;
        let raw = Vec::<u8>::from_hex(&hex).map_err(|e| format!("hex decode: {e}"))?;
        let prev_tx: Transaction = deserialize_tx(&raw)?;
        let txout: TxOut = prev_tx
            .output
            .get(vout as usize)
            .cloned()
            .ok_or_else(|| format!("prev tx {txid} missing vout {vout}"))?;
        // Only witness_utxo — RFQ `psbt_structure_equals` rejects added non_witness_utxo.
        if input.witness_utxo.is_none() {
            input.witness_utxo = Some(txout);
        }
    }

    Ok(psbt.to_string())
}

/// Print regtest P2TR address for a 32-byte hex private key (BIP86 / key-path).
/// Used to derive the demo resolver claim destination from BITCOIN_DEPOSIT_PRIVATE_KEY.
fn cmd_taproot_addr(priv_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    use rgb_lib::bitcoin::Address;
    use rgb_lib::bitcoin::network::Network;
    use rgb_lib::bitcoin::secp256k1::XOnlyPublicKey;

    let priv_bytes = Vec::<u8>::from_hex(priv_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("priv hex: {e}"))?;
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&priv_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    // Address::p2tr applies BIP86 tweak (merkle_root=None).
    let addr = Address::p2tr(&secp, xonly, None, Network::Regtest);
    println!("xonly_internal={}", hex::encode(xonly.serialize()));
    println!("address={addr}");
    Ok(())
}

fn cmd_info() -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    sync_wallet(&mut wallet, online.clone())?;

    let btc = wallet.get_btc_balance(Some(online.clone()), false)?;
    let unspents = wallet.list_unspents(Some(online.clone()), false, false)?;
    let primary = env::var("BITCOIN_ADDRESS").ok();
    let receive = wallet.get_address()?;

    println!("wallet_dir={}", wallet.get_wallet_dir().display());
    println!("receive_address={receive}");
    println!("btc_balance={btc:?}");

    for u in &unspents {
        println!(
            "utxo_outpoint={}:{} amount={} colorable={}",
            u.utxo.outpoint.txid, u.utxo.outpoint.vout, u.utxo.btc_amount, u.utxo.colorable
        );
        for a in &u.rgb_allocations {
            if let Some(asset_id) = &a.asset_id {
                println!(
                    "rgb_asset={asset_id} assignment={:?} settled={}",
                    a.assignment, a.settled
                );
            }
        }
    }

    if let Some(addr) = primary {
        println!("primary_address={addr}");
    }

    Ok(())
}

fn cmd_sign(psbt: &str) -> Result<(), Box<dyn std::error::Error>> {
    let filled = fill_psbt_utxos(psbt)?;
    let wallet = open_wallet()?;
    let mut opts = rgb_lib::bdk_wallet::SignOptions::default();
    opts.trust_witness_utxo = true;
    let signed = wallet.sign_psbt(filled, Some(opts))?;
    println!("signed_psbt={signed}");
    Ok(())
}

fn cmd_broadcast(signed_psbt: &str) -> Result<(), Box<dyn std::error::Error>> {
    let filled = fill_psbt_utxos(signed_psbt)?;
    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    let txid = wallet.send_btc_end(online, filled)?;
    println!("txid={txid}");
    Ok(())
}

fn cmd_send_end(signed_psbt: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    let result = wallet.send_end(online, signed_psbt.to_owned())?;
    println!("send_end_txid={}", result.txid);
    Ok(())
}

/// Real RGB lock: `send_begin` + sign against RFQ witness invoice (colored PSBT).
/// Prints `signed_psbt=` for RFQ approval. Set `BROADCAST=1` to also `send_end`.
fn cmd_lock_send(invoice_str: &str, amount_sat: u64) -> Result<(), Box<dyn std::error::Error>> {
    let invoice = Invoice::new(invoice_str.to_owned())?;
    let data = invoice.invoice_data();
    let asset_id = data
        .asset_id
        .clone()
        .ok_or("invoice missing asset_id")?;
    let fee_rate: u64 = env::var("FEE_RATE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let min_conf: u8 = env::var("MIN_CONFIRMATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let broadcast = env::var("BROADCAST").ok().as_deref() == Some("1");

    let recipient = Recipient {
        recipient_id: data.recipient_id,
        assignment: data.assignment,
        witness_data: Some(WitnessData {
            amount_sat,
            blinding: None,
        }),
        transport_endpoints: data.transport_endpoints,
    };
    let mut recipient_map = HashMap::new();
    recipient_map.insert(asset_id.clone(), vec![recipient]);

    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    sync_wallet(&mut wallet, online.clone())?;

    let begin = wallet.send_begin(
        online.clone(),
        recipient_map,
        false,
        fee_rate,
        min_conf,
        None,
        false,
        None,
    )?;
    let mut opts = rgb_lib::bdk_wallet::SignOptions::default();
    opts.trust_witness_utxo = true;
    let signed = wallet.sign_psbt(begin.psbt, Some(opts))?;
    println!("signed_psbt={signed}");
    println!("asset_id={asset_id}");
    println!("lock_anchor_sat={amount_sat}");

    if broadcast {
        let result = wallet.send_end(online, signed)?;
        println!("lock_send_txid={}", result.txid);
    } else {
        println!("broadcast=0 (set BROADCAST=1 to send_end)");
    }
    Ok(())
}

/// Register HTLC script as pending witness receive so lock consignment can attach.
/// Pass asset_id `-` to skip pre-import (fresh claimer wallet); consignment on refresh
/// brings the contract in.
fn cmd_register_htlc(
    script_hex: &str,
    asset_id: &str,
    asset_amount: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let script = ScriptBuf::from_hex(script_hex).map_err(|e| format!("script hex: {e}"))?;
    let endpoints: Vec<String> = env::var("RGB_TRANSPORT")
        .unwrap_or_else(|_| "rpc://127.0.0.1:3000/json-rpc".to_owned())
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();
    let min_conf: u8 = env::var("MIN_CONFIRMATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let asset_id_opt = if asset_id == "-" || asset_id.is_empty() {
        None
    } else {
        Some(asset_id.to_owned())
    };

    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    sync_wallet(&mut wallet, online.clone())?;
    let recv = wallet.script_witness_receive(
        script,
        asset_id_opt,
        Assignment::Fungible(asset_amount),
        None,
        endpoints,
        min_conf,
    )?;
    println!("register_htlc_invoice={}", recv.invoice);
    println!("recipient_id={}", recv.recipient_id);
    // Pull any pending consignments after lock is confirmed.
    let refresh = wallet.refresh(online.clone(), None, vec![], false)?;
    println!("refreshed=1 updated={}", refresh.len());
    // Second pass after sync — consignment may need confirmed outpoint attached.
    sync_wallet(&mut wallet, online.clone())?;
    let refresh2 = wallet.refresh(online, None, vec![], false)?;
    println!("refreshed=2 updated={}", refresh2.len());
    Ok(())
}

fn cmd_issue_nia(ticker: &str, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
    let precision: u8 = env::var("ASSET_PRECISION")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let name = env::var("ASSET_NAME").unwrap_or_else(|_| format!("{ticker} e2e"));
    let fee_rate: u64 = env::var("FEE_RATE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    sync_wallet(&mut wallet, online.clone())?;
    // Ensure some free colorable slots before issue.
    let _ = wallet.create_utxos(online.clone(), true, Some(5), None, fee_rate, false);
    sync_wallet(&mut wallet, online)?;

    let asset = wallet.issue_asset_nia(ticker.to_owned(), name, precision, vec![amount])?;
    println!("asset_id={}", asset.asset_id);
    println!("ticker={}", asset.ticker);
    println!("precision={}", asset.precision);
    println!("issued_supply={}", asset.issued_supply);
    Ok(())
}

fn cmd_create_utxos(num: u8) -> Result<(), Box<dyn std::error::Error>> {
    let fee_rate: u64 = env::var("FEE_RATE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    // Default rgb-lib size is 1000 sats — too small for RFQ lock_anchor_sat=10000.
    let size: Option<u32> = env::var("UTXO_SIZE_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(Some(50_000));
    // UTXO_UP_TO=1 (default): stop when enough empty slots exist.
    // UTXO_UP_TO=0: always create `num` new colorable UTXOs.
    let up_to = env::var("UTXO_UP_TO").ok().as_deref() != Some("0");
    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    sync_wallet(&mut wallet, online.clone())?;
    let created = wallet.create_utxos(online, up_to, Some(num), size, fee_rate, false)?;
    println!("created_utxos={created} target={num} size={size:?} up_to={up_to}");
    Ok(())
}

fn cmd_refresh() -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    sync_wallet(&mut wallet, online.clone())?;
    let refresh = wallet.refresh(online, None, vec![], false)?;
    println!("refreshed=1 updated={}", refresh.len());
    Ok(())
}

fn cmd_list_transfers(asset_id: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let wallet = open_wallet()?;
    let transfers = wallet.list_transfers(asset_id.map(|s| s.to_owned()))?;
    for t in transfers {
        println!(
            "transfer idx={} batch={} kind={:?} status={:?} txid={:?} amount={:?}",
            t.idx,
            t.batch_transfer_idx,
            t.kind,
            t.status,
            t.txid,
            t.requested_assignment
        );
    }
    Ok(())
}

fn cmd_fail_transfers(batch_idx: Option<i32>) -> Result<(), Box<dyn std::error::Error>> {
    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    let ok = wallet.fail_transfers(online, batch_idx, false, false)?;
    println!("fail_transfers={ok} batch_idx={batch_idx:?}");
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ClaimOffer {
    psbt: String,
    secret: String,
    #[serde(default)]
    witness_invoice: Option<String>,
    #[serde(default)]
    resolver_tap_script: Option<String>,
    #[serde(default)]
    lock_txid: Option<String>,
    #[serde(default)]
    lock_vout: Option<u32>,
    #[serde(default)]
    asset_id: Option<String>,
    #[serde(default)]
    asset_amount: Option<u64>,
}

fn rgb_transport_endpoints() -> Vec<String> {
    env::var("RGB_TRANSPORT")
        .unwrap_or_else(|_| "rpc://127.0.0.1:3000/json-rpc".to_owned())
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

fn proxy_http_url() -> String {
    let ep = rgb_transport_endpoints()
        .into_iter()
        .next()
        .unwrap_or_else(|| "rpc://127.0.0.1:3000/json-rpc".to_owned());
    if let Some(rest) = ep.strip_prefix("rpc://") {
        format!("http://{rest}")
    } else {
        ep
    }
}

struct ColorFinalize {
    recipient_id: String,
    /// Full invoice (includes per-receive `rid_nonce` on transport endpoints).
    invoice: String,
    consignment_path: std::path::PathBuf,
    seal_vout: u32,
}

/// Mirror of rgb-lib `derive_proxy_recipient_id` (crate-private).
fn proxy_recipient_id(recipient_id: &str, nonce: &[u8]) -> String {
    if nonce.is_empty() {
        return recipient_id.to_owned();
    }
    let mut buf = Vec::with_capacity(recipient_id.len() + nonce.len());
    buf.extend_from_slice(recipient_id.as_bytes());
    buf.extend_from_slice(nonce);
    hex::encode(rgb_lib::bitcoin::hashes::sha256::Hash::hash(&buf))
}

fn rid_nonce_from_invoice(invoice: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let inv = Invoice::new(invoice.to_owned())?;
    for ep in inv.invoice_data().transport_endpoints {
        // Invoice strings sometimes keep URL-encoded `rid_nonce%3D...`.
        let ep = ep.replace("%3D", "=").replace("%3d", "=");
        if let Some(qpos) = ep.find('?') {
            for pair in ep[qpos + 1..].split('&') {
                if let Some(hex_nonce) = pair.strip_prefix("rid_nonce=") {
                    return Ok(Vec::<u8>::from_hex(hex_nonce)?);
                }
            }
        }
    }
    Ok(vec![])
}

/// Open a pending witness receive on the destination script, color the PSBT onto
/// that output, and keep the consignment so we can `post_consignment` + `refresh`
/// after broadcast (writes SQL Receive coloring — what `list_unspents` reads).
fn prepare_color_psbt(
    wallet: &mut Wallet,
    psbt: &mut Psbt,
    asset_id: &str,
    asset_amount: u64,
    dest_vout: u32,
) -> Result<ColorFinalize, Box<dyn std::error::Error>> {
    let dest_script = psbt
        .unsigned_tx
        .output
        .get(dest_vout as usize)
        .ok_or("dest_vout out of range")?
        .script_pubkey
        .clone();

    let min_conf: u8 = env::var("MIN_CONFIRMATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let recv = wallet.script_witness_receive(
        dest_script.clone(),
        Some(asset_id.to_owned()),
        Assignment::Fungible(asset_amount),
        None,
        rgb_transport_endpoints(),
        min_conf,
    )?;
    println!(
        "dest_receive_recipient_id={} invoice={}",
        recv.recipient_id, recv.invoice
    );

    let saved: Vec<_> = psbt
        .inputs
        .iter()
        .map(|i| (i.tap_scripts.clone(), i.witness_utxo.clone()))
        .collect();

    let contract_id = ContractId::from_str(asset_id).map_err(|e| format!("asset_id: {e}"))?;
    let coloring_info = ColoringInfo {
        asset_info_map: HashMap::from([(
            contract_id,
            AssetColoringInfo {
                output_map: HashMap::from([(dest_vout, asset_amount)]),
                static_blinding: None,
            },
        )]),
        static_blinding: None,
        nonce: None,
    };
    let transfers = wallet.color_psbt_and_consume(psbt, coloring_info)?;
    println!("colored_transfers={}", transfers.len());

    for (i, (tap_scripts, witness_utxo)) in saved.into_iter().enumerate() {
        if psbt.inputs[i].tap_scripts.is_empty() {
            psbt.inputs[i].tap_scripts = tap_scripts;
        }
        if psbt.inputs[i].witness_utxo.is_none() {
            psbt.inputs[i].witness_utxo = witness_utxo;
        }
    }

    let seal_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.script_pubkey == dest_script)
        .map(|(i, _)| i as u32)
        .ok_or("destination script missing after color_psbt")?;

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let dir = std::env::temp_dir().join(format!("rgb-consign-{txid}"));
    fs::create_dir_all(&dir)?;
    let consignment_path = dir.join("consignment.rgbc");
    let transfer = transfers.first().ok_or("color_psbt produced no transfers")?;
    transfer
        .save_file(&consignment_path)
        .map_err(|e| format!("save consignment: {e}"))?;
    println!("consignment_path={} seal_vout={seal_vout}", consignment_path.display());

    Ok(ColorFinalize {
        recipient_id: recv.recipient_id,
        invoice: recv.invoice,
        consignment_path,
        seal_vout,
    })
}

fn finalize_after_broadcast(
    wallet: &mut Wallet,
    online: Online,
    finalize: &ColorFinalize,
    txid: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let proxy = proxy_http_url();
    let nonce = rid_nonce_from_invoice(&finalize.invoice)?;
    let proxy_rid = proxy_recipient_id(&finalize.recipient_id, &nonce);
    wallet.post_consignment(
        &proxy,
        proxy_rid.clone(),
        &finalize.consignment_path,
        txid.to_owned(),
        Some(finalize.seal_vout),
    )?;
    println!(
        "posted_consignment=1 proxy={proxy} rid={} proxy_rid={} nonce_len={}",
        finalize.recipient_id,
        proxy_rid,
        nonce.len()
    );

    // Optional mine so refresh can settle with min_confirmations>=1.
    if env::var("MINE_AFTER").ok().as_deref() != Some("0") {
        let addr = std::process::Command::new("docker")
            .args([
                "exec",
                "tests-bitcoind-1",
                "/opt/bitcoin/bin/bitcoin-cli",
                "-regtest",
                "-rpcuser=user",
                "-rpcpassword=default_password",
                "-rpcwallet=miner",
                "getnewaddress",
            ])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        if !addr.is_empty() {
            let _ = std::process::Command::new("docker")
                .args([
                    "exec",
                    "tests-bitcoind-1",
                    "/opt/bitcoin/bin/bitcoin-cli",
                    "-regtest",
                    "-rpcuser=user",
                    "-rpcpassword=default_password",
                    "-rpcwallet=miner",
                    "generatetoaddress",
                    "1",
                    &addr,
                ])
                .status();
            println!("mined_after_broadcast=1");
        }
    }

    sync_wallet(wallet, online.clone())?;
    let updated = wallet.refresh(online.clone(), None, vec![], false)?;
    println!("finalize_refresh_updated={}", updated.len());
    // Second pass: WaitingConfirmations → Settled after mine/sync.
    sync_wallet(wallet, online.clone())?;
    let updated2 = wallet.refresh(online, None, vec![], false)?;
    println!("finalize_refresh2_updated={}", updated2.len());
    Ok(())
}

/// Sign HTLC claim PSBT with resolver key: witness `[sig, preimage, script, control_block]`.
/// With `COLOR_RGB=1`, color the PSBT first (RGB-wrapped claim), then post+refresh.
fn cmd_claim(offer_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let offer: ClaimOffer = serde_json::from_str(&fs::read_to_string(offer_path)?)?;
    let priv_hex = env::var("RESOLVER_PRIVKEY").map_err(|_| {
        "set RESOLVER_PRIVKEY to 32-byte hex (from BITCOIN_*_PRIVATE_KEY before |regtest)"
    })?;
    let priv_bytes = Vec::<u8>::from_hex(priv_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("RESOLVER_PRIVKEY hex: {e}"))?;
    let preimage = Vec::<u8>::from_hex(offer.secret.trim().trim_start_matches("0x"))
        .map_err(|e| format!("secret hex: {e}"))?;

    let mut psbt = Psbt::from_str(&fill_psbt_utxos(&offer.psbt)?)?;
    if psbt.inputs.len() != 1 {
        return Err(format!("expected 1 input, got {}", psbt.inputs.len()).into());
    }

    let color_rgb = env::var("COLOR_RGB").ok().as_deref() == Some("1");

    // Tiny anchors: keep enough fee for script-path witness (+ opret when COLOR_RGB=1).
    if let Some(wu) = psbt.inputs[0].witness_utxo.clone() {
        if psbt.unsigned_tx.output.len() == 1 && wu.value.to_sat() < 20_000 {
            let fee_sats: u64 = env::var("CLAIM_FEE_SATS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(if color_rgb { 500 } else { 16 });
            let out = wu.value.to_sat().saturating_sub(fee_sats);
            if out < 330 {
                return Err(format!(
                    "lock anchor {} too small for claim after fee {}",
                    wu.value.to_sat(),
                    fee_sats
                )
                .into());
            }
            psbt.unsigned_tx.output[0].value = rgb_lib::bitcoin::Amount::from_sat(out);
            println!("adjusted_claim_output_sats={out} fee_sats={fee_sats}");
        }
    }

    let mut color_finalize: Option<ColorFinalize> = None;
    if color_rgb {
        // Same resolver P2TR → same bare recipient_id unless reuse+rid_nonce.
        // Without this, post_consignment hits RecipientIDAlreadyUsed on 2nd claim.
        let asset_id = offer
            .asset_id
            .clone()
            .or_else(|| {
                offer
                    .witness_invoice
                    .as_ref()
                    .and_then(|inv| inv.split('/').next().map(|s| s.to_owned()))
            })
            .ok_or("COLOR_RGB=1 requires asset_id on offer (or witness_invoice)")?;
        let asset_amount = offer
            .asset_amount
            .or_else(|| env::var("ASSET_AMOUNT").ok().and_then(|s| s.parse().ok()))
            .ok_or("COLOR_RGB=1 requires asset_amount on offer (or ASSET_AMOUNT)")?;

        let dest_vout = psbt
            .unsigned_tx
            .output
            .iter()
            .position(|o| !o.script_pubkey.is_op_return())
            .ok_or("claim psbt has no destination output")? as u32;

        let mut wallet = open_wallet_opts(Some(true))?;
        let online = go_online(&mut wallet)?;
        sync_wallet(&mut wallet, online)?;
        color_finalize = Some(prepare_color_psbt(
            &mut wallet,
            &mut psbt,
            &asset_id,
            asset_amount,
            dest_vout,
        )?);
        println!("color_rgb=1 asset_id={asset_id} amount={asset_amount}");
    }

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&priv_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);

    let input = &mut psbt.inputs[0];
    let (control_block, (script, _leaf_ver)) = input
        .tap_scripts
        .iter()
        .next()
        .map(|(cb, v)| (cb.clone(), v.clone()))
        .ok_or("psbt input missing tap_scripts (control block)")?;

    if let Some(expected) = &offer.resolver_tap_script {
        let expected_script = ScriptBuf::from_hex(expected)
            .map_err(|e| format!("resolver_tap_script hex: {e}"))?;
        if expected_script != script {
            return Err("resolver_tap_script does not match psbt tap_scripts leaf".into());
        }
    }

    let witness_utxo = input
        .witness_utxo
        .clone()
        .ok_or("missing witness_utxo after fill")?;
    let prevouts = vec![witness_utxo];

    let mut unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&mut unsigned_tx);
    let leaf_hash = rgb_lib::bitcoin::taproot::TapLeafHash::from_script(
        script.as_script(),
        LeafVersion::TapScript,
    );
    let sighash = cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&prevouts),
        leaf_hash,
        TapSighashType::Default,
    )?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &keypair);

    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness.push(&preimage);
    witness.push(script.as_bytes());
    witness.push(&control_block.serialize());
    input.final_script_witness = Some(witness);
    input.tap_script_sigs.clear();
    input.tap_scripts.clear();
    input.tap_key_sig = None;

    let signed_psbt = psbt.to_string();
    let tx = psbt.extract_tx_unchecked_fee_rate();
    let tx_hex = hex::encode(serialize_tx(&tx));
    println!("claim_tx_hex={tx_hex}");
    println!("claim_txid={}", tx.compute_txid());

    if let (Some(txid), Some(vout)) = (&offer.lock_txid, offer.lock_vout) {
        println!("spends={txid}:{vout}");
    }

    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    let broadcast_txid = wallet.send_btc_end(online.clone(), signed_psbt)?;
    println!("broadcast_txid={broadcast_txid}");

    if let Some(finalize) = color_finalize.as_ref() {
        finalize_after_broadcast(&mut wallet, online, finalize, &broadcast_txid)?;
    }
    Ok(())
}

/// Sign HTLC timeout-refund PSBT: witness `[sig, script, control_block]` (no preimage).
/// With `COLOR_RGB=1`, color first. Extra fee-payer inputs are signed with the wallet mnemonic.
fn cmd_refund(offer_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Debug, Deserialize)]
    struct RefundOffer {
        psbt: String,
        #[serde(default)]
        witness_invoice: Option<String>,
        #[serde(default)]
        refund_tap_script: Option<String>,
        #[serde(default)]
        lock_txid: Option<String>,
        #[serde(default)]
        lock_vout: Option<u32>,
        #[serde(default)]
        asset_id: Option<String>,
        #[serde(default)]
        asset_amount: Option<u64>,
    }

    let offer: RefundOffer = serde_json::from_str(&fs::read_to_string(offer_path)?)?;
    let priv_hex = env::var("REFUNDER_PRIVKEY")
        .or_else(|_| env::var("RESOLVER_PRIVKEY"))
        .map_err(|_| "set REFUNDER_PRIVKEY (or RESOLVER_PRIVKEY) to 32-byte hex")?;
    let priv_bytes = Vec::<u8>::from_hex(priv_hex.trim().trim_start_matches("0x"))
        .map_err(|e| format!("REFUNDER_PRIVKEY hex: {e}"))?;

    let mut psbt = Psbt::from_str(&fill_psbt_utxos(&offer.psbt)?)?;

    // Optional override if core built the offer without CLTV locktime.
    if let Ok(ts) = env::var("REFUND_LOCKTIME") {
        let ts: u32 = ts.parse().map_err(|e| format!("REFUND_LOCKTIME: {e}"))?;
        psbt.unsigned_tx.lock_time = rgb_lib::bitcoin::absolute::LockTime::from_time(ts)
            .map_err(|e| format!("locktime: {e}"))?;
        for tin in &mut psbt.unsigned_tx.input {
            tin.sequence = rgb_lib::bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF;
        }
        println!("set_refund_locktime={ts}");
    }

    let color_rgb = env::var("COLOR_RGB").ok().as_deref() == Some("1");
    let mut color_finalize: Option<ColorFinalize> = None;
    if color_rgb {
        let asset_id = offer
            .asset_id
            .clone()
            .or_else(|| env::var("ASSET_ID").ok())
            .or_else(|| {
                offer
                    .witness_invoice
                    .as_ref()
                    .and_then(|inv| inv.split('/').next().map(|s| s.to_owned()))
            })
            .ok_or("COLOR_RGB=1 requires asset_id on offer (or ASSET_ID)")?;
        let asset_amount = offer
            .asset_amount
            .or_else(|| env::var("ASSET_AMOUNT").ok().and_then(|s| s.parse().ok()))
            .ok_or("COLOR_RGB=1 requires asset_amount on offer (or ASSET_AMOUNT)")?;

        let dest_vout = psbt
            .unsigned_tx
            .output
            .iter()
            .position(|o| !o.script_pubkey.is_op_return())
            .ok_or("refund psbt has no destination output")? as u32;

        let mut wallet = open_wallet_opts(Some(true))?;
        let online = go_online(&mut wallet)?;
        sync_wallet(&mut wallet, online)?;
        color_finalize = Some(prepare_color_psbt(
            &mut wallet,
            &mut psbt,
            &asset_id,
            asset_amount,
            dest_vout,
        )?);
        println!("color_rgb=1 asset_id={asset_id} amount={asset_amount} dest_vout={dest_vout}");
    }

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&priv_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);

    // Sign HTLC input(s) that carry tap_scripts.
    let htlc_indices: Vec<usize> = psbt
        .inputs
        .iter()
        .enumerate()
        .filter(|(_, i)| !i.tap_scripts.is_empty())
        .map(|(i, _)| i)
        .collect();
    if htlc_indices.is_empty() {
        return Err("refund psbt missing tap_scripts on any input".into());
    }

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| "missing witness_utxo".to_string())
        })
        .collect::<Result<_, _>>()?;

    for idx in htlc_indices {
        let input = &mut psbt.inputs[idx];
        let (control_block, (script, _leaf_ver)) = input
            .tap_scripts
            .iter()
            .next()
            .map(|(cb, v)| (cb.clone(), v.clone()))
            .ok_or("tap_scripts empty")?;

        if let Some(expected) = &offer.refund_tap_script {
            let expected_script = ScriptBuf::from_hex(expected)
                .map_err(|e| format!("refund_tap_script hex: {e}"))?;
            if expected_script != script {
                return Err("refund_tap_script does not match psbt tap_scripts leaf".into());
            }
        }

        let mut unsigned_tx = psbt.unsigned_tx.clone();
        let mut cache = SighashCache::new(&mut unsigned_tx);
        let leaf_hash = rgb_lib::bitcoin::taproot::TapLeafHash::from_script(
            script.as_script(),
            LeafVersion::TapScript,
        );
        let sighash = cache.taproot_script_spend_signature_hash(
            idx,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )?;
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr(&msg, &keypair);

        let mut witness = Witness::new();
        witness.push(sig.as_ref());
        witness.push(script.as_bytes());
        witness.push(&control_block.serialize());
        input.final_script_witness = Some(witness);
        input.tap_script_sigs.clear();
        input.tap_scripts.clear();
        input.tap_key_sig = None;
        println!("signed_htlc_input={idx}");
    }

    // Sign fee-payer / change inputs with wallet keys if any remain unsigned.
    let needs_wallet_sign = psbt
        .inputs
        .iter()
        .any(|i| i.final_script_witness.is_none() && i.final_script_sig.is_none());
    let mut signed_psbt = psbt.to_string();
    if needs_wallet_sign {
        let wallet = open_wallet()?;
        let mut opts = rgb_lib::bdk_wallet::SignOptions::default();
        opts.trust_witness_utxo = true;
        signed_psbt = wallet.sign_psbt(signed_psbt, Some(opts))?;
        println!("signed_fee_inputs=1");
    }

    let psbt = Psbt::from_str(&signed_psbt)?;
    let tx = psbt.extract_tx_unchecked_fee_rate();
    let tx_hex = hex::encode(serialize_tx(&tx));
    println!("refund_tx_hex={tx_hex}");
    println!("refund_txid={}", tx.compute_txid());
    if let (Some(txid), Some(vout)) = (&offer.lock_txid, offer.lock_vout) {
        println!("spends={txid}:{vout}");
    }

    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    let broadcast_txid = wallet.send_btc_end(online.clone(), signed_psbt)?;
    println!("broadcast_txid={broadcast_txid}");
    if let Some(finalize) = color_finalize.as_ref() {
        finalize_after_broadcast(&mut wallet, online, finalize, &broadcast_txid)?;
    }
    Ok(())
}

/// Color a wallet-owned PSBT onto its first non-opret output, sign with mnemonic, broadcast, finalize.
/// Usage: color-spend <psbt_base64> <asset_id> <asset_amount>
fn cmd_color_spend(
    psbt_b64: &str,
    asset_id: &str,
    asset_amount: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut psbt = Psbt::from_str(&fill_psbt_utxos(psbt_b64)?)?;
    let dest_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| !o.script_pubkey.is_op_return())
        .ok_or("psbt has no destination output")? as u32;

    let mut wallet = open_wallet()?;
    let online = go_online(&mut wallet)?;
    sync_wallet(&mut wallet, online.clone())?;
    let finalize = prepare_color_psbt(&mut wallet, &mut psbt, asset_id, asset_amount, dest_vout)?;

    let mut opts = rgb_lib::bdk_wallet::SignOptions::default();
    opts.trust_witness_utxo = true;
    let signed = wallet.sign_psbt(psbt.to_string(), Some(opts))?;
    let psbt = Psbt::from_str(&signed)?;
    let tx = psbt.extract_tx_unchecked_fee_rate();
    println!("color_spend_txid={}", tx.compute_txid());

    let broadcast_txid = wallet.send_btc_end(online.clone(), signed)?;
    println!("broadcast_txid={broadcast_txid}");
    finalize_after_broadcast(&mut wallet, online, &finalize, &broadcast_txid)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("info") => cmd_info(),
        Some("sign") => {
            let psbt = args.get(1).ok_or("usage: sign <psbt_base64>")?;
            cmd_sign(psbt)
        }
        Some("broadcast") => {
            let psbt = args.get(1).ok_or("usage: broadcast <signed_psbt>")?;
            cmd_broadcast(psbt)
        }
        Some("send-end") => {
            let psbt = args.get(1).ok_or("usage: send-end <signed_psbt>")?;
            cmd_send_end(psbt)
        }
        Some("extract") => {
            let psbt = args.get(1).ok_or("usage: extract <signed_psbt>")?;
            let psbt = Psbt::from_str(&fill_psbt_utxos(psbt)?)?;
            let tx = psbt.extract_tx_unchecked_fee_rate();
            println!("tx_hex={}", hex::encode(serialize_tx(&tx)));
            println!("txid={}", tx.compute_txid());
            Ok(())
        }
        Some("lock-send") => {
            let invoice = args.get(1).ok_or("usage: lock-send <witness_invoice> [amount_sat]")?;
            let amount_sat: u64 = match args.get(2) {
                Some(s) => s.parse().map_err(|e| format!("amount_sat: {e}"))?,
                None => match env::var("LOCK_ANCHOR_SAT") {
                    Ok(s) => s.parse().map_err(|e| format!("LOCK_ANCHOR_SAT: {e}"))?,
                    Err(_) => 10_000,
                },
            };
            cmd_lock_send(invoice, amount_sat)
        }
        Some("register-htlc") => {
            let script = args
                .get(1)
                .ok_or("usage: register-htlc <script_pubkey_hex> <asset_id|-> <asset_amount>")?;
            let asset_id = args.get(2).ok_or("missing asset_id (use - if unknown)")?;
            let amount: u64 = args
                .get(3)
                .ok_or("missing asset_amount")?
                .parse()
                .map_err(|e| format!("asset_amount: {e}"))?;
            cmd_register_htlc(script, asset_id, amount)
        }
        Some("refresh") => cmd_refresh(),
        Some("list-transfers") => {
            let asset = args.get(1).map(|s| s.as_str());
            cmd_list_transfers(asset)
        }
        Some("fail-transfers") => {
            let batch = match args.get(1) {
                Some(s) if s != "all" => Some(s.parse().map_err(|e| format!("batch_idx: {e}"))?),
                _ => None,
            };
            cmd_fail_transfers(batch)
        }
        Some("create-utxos") => {
            let num: u8 = match args.get(1) {
                Some(s) => s.parse().map_err(|e| format!("num: {e}"))?,
                None => 10,
            };
            cmd_create_utxos(num)
        }
        Some("issue-nia") => {
            let ticker = args
                .get(1)
                .map(|s| s.as_str())
                .unwrap_or("DEMO2");
            let amount: u64 = match args.get(2) {
                Some(s) => s.parse().map_err(|e| format!("amount: {e}"))?,
                None => 1_000_000_000_000,
            };
            cmd_issue_nia(ticker, amount)
        }
        Some("taproot-addr") => {
            let priv_hex = args
                .get(1)
                .cloned()
                .or_else(|| env::var("RESOLVER_PRIVKEY").ok())
                .ok_or("usage: taproot-addr <32-byte-hex-priv> (or set RESOLVER_PRIVKEY)")?;
            cmd_taproot_addr(&priv_hex)
        }
        Some("claim") => {
            let path = args.get(1).ok_or("usage: claim <offer.json>")?;
            cmd_claim(path)
        }
        Some("refund") => {
            let path = args.get(1).ok_or("usage: refund <offer.json>")?;
            cmd_refund(path)
        }
        Some("color-spend") => {
            let psbt = args.get(1).ok_or("usage: color-spend <psbt_base64> <asset_id> <amount>")?;
            let asset_id = args.get(2).ok_or("missing asset_id")?;
            let amount: u64 = args
                .get(3)
                .ok_or("missing asset_amount")?
                .parse()
                .map_err(|e| format!("asset_amount: {e}"))?;
            cmd_color_spend(psbt, asset_id, amount)
        }
        _ => {
            eprintln!(
                "usage: phase_b_wallet <info|sign|broadcast|extract|lock-send|register-htlc|refresh|list-transfers|fail-transfers|create-utxos|issue-nia|taproot-addr|claim|refund|color-spend> [args]"
            );
            Err("unknown command".into())
        }
    }
}
