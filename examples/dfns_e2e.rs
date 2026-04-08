//! DFNS MPC end-to-end test — real RGB transfers on signet
//!
//! Tests the DFNS MPC wallet with real RGB operations.
//! MPC wallets coexist with singlesig/multisig wallets in the same binary.
//!
//! Run with:
//! ```
//! cargo run --example dfns_e2e --features dfns,electrum -- <command>
//! ```
//!
//! Commands: setup, check, utxos, issue, receive, send, verify,
//!           send-btc, drain, clean
//!
//! Required env vars (from .env or .env.utexo):
//!   DFNS_API_URL, DFNS_AUTH_TOKEN, DFNS_CRED_ID, DFNS_PRIVATE_KEY,
//!   BITCOIN_WALLET_ID
//!
//! Optional:
//!   DFNS_MASTER_KEY_ID, ELECTRUM_URL, RGB_PROXY_URL, E2E_DATA_DIR

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use rgb_lib::wallet::{DatabaseType, MpcWallet, Online, Recipient, WalletData};
use rgb_lib::{AssetSchema, Assignment, BitcoinNetwork, DfnsConfig, DfnsProvider};

// ---------------------------------------------------------------------------
// State persistence
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
struct E2eState {
    data_dir: String,
    funding_address: Option<String>,
    asset_id: Option<String>,
    last_invoice: Option<String>,
    last_recipient_id: Option<String>,
    master_key_id: Option<String>,
    last_step: String,
}

fn state_path() -> String {
    let base = env::var("E2E_DATA_DIR").unwrap_or_else(|_| "/tmp/rgb-dfns-e2e".to_string());
    format!("{base}/state.json")
}

fn load_state() -> E2eState {
    let path = state_path();
    if Path::new(&path).exists() {
        let data = fs::read_to_string(&path).expect("failed to read state");
        serde_json::from_str(&data).expect("failed to parse state")
    } else {
        E2eState::default()
    }
}

fn save_state(state: &E2eState) {
    let path = state_path();
    let dir = Path::new(&path).parent().unwrap();
    fs::create_dir_all(dir).expect("failed to create state dir");
    let data = serde_json::to_string_pretty(state).expect("failed to serialize state");
    fs::write(&path, data).expect("failed to write state");
}

// ---------------------------------------------------------------------------
// Env loading
// ---------------------------------------------------------------------------

fn load_dotenv() {
    for path in [".env", ".env.utexo", "dfns/.env", "dfns/.env.utexo"] {
        if Path::new(path).exists() {
            let contents = fs::read_to_string(path).expect("failed to read .env");
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim().trim_matches('"').trim_matches('\'');
                    if env::var(key).is_err() {
                        unsafe { env::set_var(key, value) };
                    }
                }
            }
            println!("[env] Loaded from {path}");
            return;
        }
    }
    println!("[env] No .env file found, using environment variables");
}

fn env_required(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("{key} not set"))
}

fn bitcoin_network() -> BitcoinNetwork {
    match env::var("BITCOIN_NETWORK")
        .unwrap_or_else(|_| "signet".to_string())
        .as_str()
    {
        "mainnet" => BitcoinNetwork::Mainnet,
        "testnet" => BitcoinNetwork::Testnet,
        "signet" => BitcoinNetwork::Signet,
        "regtest" => BitcoinNetwork::Regtest,
        other => panic!("Invalid BITCOIN_NETWORK: {other}"),
    }
}

fn electrum_url() -> String {
    env::var("ELECTRUM_URL").unwrap_or_else(|_| match bitcoin_network() {
        BitcoinNetwork::Signet => "tcp://electrum.iriswallet.com:50031".to_string(),
        BitcoinNetwork::Testnet => "ssl://electrum.iriswallet.com:50013".to_string(),
        BitcoinNetwork::Mainnet => "ssl://electrum.iriswallet.com:50003".to_string(),
        _ => "tcp://localhost:50001".to_string(),
    })
}

fn proxy_url() -> String {
    env::var("RGB_PROXY_URL")
        .unwrap_or_else(|_| "rpc://proxy.iriswallet.com/0.2/json-rpc".to_string())
}

// ---------------------------------------------------------------------------
// Wallet builder
// ---------------------------------------------------------------------------

fn dfns_config(master_key_id: String) -> DfnsConfig {
    let private_key_raw = env_required("DFNS_PRIVATE_KEY");
    let private_key = private_key_raw.replace("\\n", "\n");

    DfnsConfig {
        api_url: env_required("DFNS_API_URL"),
        auth_token: env_required("DFNS_AUTH_TOKEN"),
        cred_id: env_required("DFNS_CRED_ID"),
        private_key,
        master_key_id,
        base_path: "m/86".to_string(),
    }
}

/// Resolve or create the DFNS master key, then build a provider with it.
/// Checks: .env → state.json → creates new (and saves to state).
fn make_dfns_provider() -> DfnsProvider {
    // 1. Check .env
    let mut master_key_id = env::var("DFNS_MASTER_KEY_ID")
        .map(|s| s.trim().trim_matches('\'').trim_matches('"').to_string())
        .unwrap_or_default();

    // 2. Check state file
    if master_key_id.is_empty() {
        let state = load_state();
        if let Some(ref saved) = state.master_key_id
            && !saved.is_empty()
        {
            master_key_id = saved.clone();
        }
    }

    // 3. Create new if still empty
    let master_key_id = if master_key_id.is_empty() {
        let bootstrap = DfnsProvider::new(dfns_config(String::new()))
            .expect("failed to create DFNS bootstrap provider");
        println!("[..] No DFNS_MASTER_KEY_ID found, creating master key...");
        let key = bootstrap
            .create_master_key("rgb-lib-e2e")
            .expect("failed to create master key");
        println!("[OK] Created master key: {}", key.id);
        println!("     Tip: add to .env: DFNS_MASTER_KEY_ID={}", key.id);

        // Save to state so subsequent runs reuse it
        let mut state = load_state();
        state.master_key_id = Some(key.id.clone());
        save_state(&state);

        key.id
    } else {
        println!("[OK] Using master key: {master_key_id}");
        master_key_id
    };

    DfnsProvider::new(dfns_config(master_key_id)).expect("failed to create DFNS provider")
}

fn open_wallet(data_dir: &str) -> MpcWallet {
    let provider = make_dfns_provider();
    let wallet_data = WalletData {
        data_dir: data_dir.to_string(),
        bitcoin_network: bitcoin_network(),
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: 5,
        supported_schemas: vec![AssetSchema::Nia],
        reuse_addresses: false,
    };
    MpcWallet::new(
        wallet_data,
        env_required("BITCOIN_WALLET_ID"),
        Box::new(provider),
    )
    .expect("failed to create DFNS wallet")
}

fn go_online(wallet: &mut MpcWallet) -> Online {
    let url = electrum_url();
    println!("[..] Connecting to {url}");
    let online = wallet.go_online(true, url).expect("failed to go online");
    println!("[OK] Online (id: {})", online.id);
    online
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn separator(title: &str) {
    println!("\n============================================================");
    println!("  {title}");
    println!("============================================================\n");
}

fn print_btc_balance(wallet: &mut MpcWallet, online: &Online, label: &str) {
    let bal = wallet
        .get_btc_balance(Some(*online), true)
        .expect("balance failed");
    println!(
        "  {label} BTC: vanilla={} sat, colored={} sat",
        bal.vanilla.settled, bal.colored.settled
    );
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_setup(state: &mut E2eState) {
    separator("SETUP - Create DFNS wallet");

    // Reuse existing state if available
    if let Some(addr) = state.funding_address.as_ref()
        && !state.data_dir.is_empty()
    {
        println!("[OK] Existing wallet found, reusing");
        println!("     Data dir: {}", state.data_dir);
        println!("     Funding address: {addr}");
        println!("\n>>> Already set up. Run: check");
        return;
    }

    let base = env::var("E2E_DATA_DIR").unwrap_or_else(|_| "/tmp/rgb-dfns-e2e".to_string());
    state.data_dir = format!("{base}/dfns");
    fs::create_dir_all(&state.data_dir).unwrap();

    let mut wallet = open_wallet(&state.data_dir);
    let addr = wallet.get_address().expect("get_address failed");
    state.funding_address = Some(addr.clone());
    println!("[OK] DFNS wallet created");
    println!("     Data dir: {}", state.data_dir);
    println!("     Funding address: {addr}");

    state.last_step = "setup".to_string();
    save_state(state);

    println!("\n>>> Fund this address with signet BTC, then run: check");
}

fn cmd_check(state: &mut E2eState) {
    separator("CHECK - Verify BTC balance");

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);
    wallet.sync(online).expect("sync failed");
    print_btc_balance(&mut wallet, &online, "DFNS");

    let bal = wallet.get_btc_balance(Some(online), true).expect("balance");
    let total = bal.vanilla.settled + bal.colored.settled;

    if total == 0 {
        println!("\n[!!] Wallet has no BTC.");
        if let Some(addr) = &state.funding_address {
            println!("     Address: {addr}");
        }
        println!("     Fund it and re-run: check");
    } else {
        println!("\n[OK] Wallet funded ({total} sat). Next: utxos");
    }

    state.last_step = "check".to_string();
    save_state(state);
}

fn cmd_utxos(state: &mut E2eState) {
    separator("UTXOS - Create colored UTXOs");

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);
    wallet.sync(online).expect("sync failed");

    let num_utxos: u8 = env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(2); // default 2 to conserve DFNS wallet quota

    println!("[..] Creating {num_utxos} colored UTXOs...");
    match wallet.create_utxos(online, true, Some(num_utxos), None, 1, false) {
        Ok(n) => println!("[OK] Created {n} UTXOs"),
        Err(e) => println!("[!!] create_utxos failed: {e}"),
    }

    state.last_step = "utxos".to_string();
    save_state(state);
    println!("\n>>> Wait for confirmation, then run: issue");
}

fn cmd_issue(state: &mut E2eState) {
    separator("ISSUE - Issue NIA asset (1000 tokens)");

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);
    wallet.sync(online).expect("sync failed");

    println!("[..] Issuing NIA asset (E2E/E2E Token)...");
    match wallet.issue_asset_nia(
        "E2E".to_string(),
        "E2E Test Token".to_string(),
        0,
        vec![1000],
    ) {
        Ok(asset) => {
            println!("[OK] Asset issued!");
            println!("     Asset ID: {}", asset.asset_id);
            println!("     Balance:  {} settled", asset.balance.settled);
            state.asset_id = Some(asset.asset_id);
        }
        Err(e) => {
            println!("[!!] Issue failed: {e}");
            println!("     Make sure UTXOs are confirmed. Re-run: utxos then issue");
        }
    }

    state.last_step = "issue".to_string();
    save_state(state);
    println!("\n>>> Next: receive (to generate an invoice for a peer)");
}

fn cmd_receive(state: &mut E2eState) {
    separator("RECEIVE - Create blind receive (for incoming transfer)");
    let asset_id = state.asset_id.clone();

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);
    wallet.sync(online).expect("sync failed");

    let amount: u64 = env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    println!("[..] Creating blind receive for {amount} tokens...");
    let receive_data = wallet
        .blind_receive(
            asset_id,
            Assignment::Fungible(amount),
            None,
            vec![proxy_url()],
            0,
        )
        .expect("blind_receive failed");

    state.last_recipient_id = Some(receive_data.recipient_id.clone());
    state.last_invoice = Some(receive_data.invoice.clone());

    println!("[OK] Blind receive created!");
    println!("     Recipient ID: {}", receive_data.recipient_id);
    println!("     Invoice:      {}", receive_data.invoice);
    if let Some(exp) = receive_data.expiration_timestamp {
        println!("     Expires:      {exp}");
    }

    state.last_step = "receive".to_string();
    save_state(state);

    println!("\n>>> Give this invoice to the sender, then after they send, run: refresh");
}

fn cmd_send(state: &mut E2eState) {
    separator("SEND - Send tokens to an invoice");

    let asset_id = state
        .asset_id
        .clone()
        .expect("No asset_id. Run: issue first");

    // Get recipient_id from args or prompt
    let recipient_id = env::args()
        .nth(2)
        .unwrap_or_else(|| panic!("Usage: dfns_e2e send <recipient_id> [amount]"));
    let amount: u64 = env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);
    wallet.sync(online).expect("sync failed");

    let mut recipient_map: HashMap<String, Vec<Recipient>> = HashMap::new();
    recipient_map.insert(
        asset_id,
        vec![Recipient {
            recipient_id: recipient_id.clone(),
            witness_data: None,
            assignment: Assignment::Fungible(amount),
            transport_endpoints: vec![proxy_url()],
        }],
    );

    println!("[..] Sending {amount} tokens to {recipient_id}...");
    match wallet.send(online, recipient_map, true, 1, 0, None, false) {
        Ok(result) => {
            println!("[OK] Send succeeded!");
            println!("     Txid:  {}", result.txid);
            println!("     Batch: {}", result.batch_transfer_idx);
        }
        Err(e) => println!("[!!] Send failed: {e}"),
    }

    state.last_step = "send".to_string();
    save_state(state);
    println!("\n>>> Wait for confirmation, then run: verify");
}

fn cmd_refresh(state: &mut E2eState) {
    separator("REFRESH - Refresh transfers and check balances");

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);
    wallet.sync(online).expect("sync failed");

    println!("[..] Refreshing transfers...");
    match wallet.refresh(online, None, vec![], false) {
        Ok(result) => {
            println!("[OK] Refresh complete ({} transfers updated)", result.len());
        }
        Err(e) => println!("[!!] Refresh failed: {e}"),
    }

    print_btc_balance(&mut wallet, &online, "DFNS");

    if let Some(asset_id) = &state.asset_id {
        match wallet.get_asset_balance(asset_id.clone()) {
            Ok(bal) => {
                println!(
                    "  RGB: settled={}, future={}, spendable={}",
                    bal.settled, bal.future, bal.spendable
                );
            }
            Err(e) => println!("  RGB balance: {e}"),
        }
    }

    // List all assets
    match wallet.list_assets(vec![AssetSchema::Nia]) {
        Ok(assets) => {
            if let Some(nia_list) = &assets.nia
                && !nia_list.is_empty()
            {
                println!("\n  Assets:");
                for a in nia_list {
                    let bal = wallet
                        .get_asset_balance(a.asset_id.clone())
                        .map(|b| format!("settled={}", b.settled))
                        .unwrap_or_else(|e| format!("err: {e}"));
                    println!("    {} ({}) - {} [{}]", a.name, a.ticker, a.asset_id, bal);
                }
            }
        }
        Err(e) => println!("  List assets: {e}"),
    }

    state.last_step = "refresh".to_string();
    save_state(state);
}

fn cmd_send_btc(state: &mut E2eState) {
    separator("SEND-BTC - Send vanilla BTC");

    let address = env::args()
        .nth(2)
        .unwrap_or_else(|| panic!("Usage: dfns_e2e send-btc <address> [amount_sats]"));
    let amount: u64 = env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);
    wallet.sync(online).expect("sync failed");

    println!("[..] Sending {amount} sat to {address}...");
    match wallet.send_btc(online, address, amount, 1, false) {
        Ok(txid) => println!("[OK] Sent! Txid: {txid}"),
        Err(e) => println!("[!!] send_btc failed: {e}"),
    }

    state.last_step = "send-btc".to_string();
    save_state(state);
}

fn cmd_drain(state: &mut E2eState) {
    separator("DRAIN - Sweep wallet to address");

    let address = env::args()
        .nth(2)
        .unwrap_or_else(|| panic!("Usage: dfns_e2e drain <address>"));

    let mut wallet = open_wallet(&state.data_dir);
    let online = go_online(&mut wallet);

    println!("[..] Draining to {address}...");
    match wallet.drain_to(online, address, true, 1) {
        Ok(txid) => println!("[OK] Drained! Txid: {txid}"),
        Err(e) => println!("[!!] drain_to failed: {e}"),
    }

    state.last_step = "drain".to_string();
    save_state(state);
}

fn cmd_clean() {
    separator("CLEAN - Remove all test data");
    let base = env::var("E2E_DATA_DIR").unwrap_or_else(|_| "/tmp/rgb-dfns-e2e".to_string());
    if Path::new(&base).exists() {
        fs::remove_dir_all(&base).expect("failed to remove data dir");
        println!("[OK] Removed {base}");
    } else {
        println!("[OK] Nothing to clean");
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    load_dotenv();

    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "setup" => {
            let mut state = load_state();
            cmd_setup(&mut state);
        }
        "check" => cmd_check(&mut load_state()),
        "utxos" => cmd_utxos(&mut load_state()),
        "issue" => cmd_issue(&mut load_state()),
        "receive" => cmd_receive(&mut load_state()),
        "send" => cmd_send(&mut load_state()),
        "refresh" => cmd_refresh(&mut load_state()),
        "send-btc" => cmd_send_btc(&mut load_state()),
        "drain" => cmd_drain(&mut load_state()),
        "clean" => cmd_clean(),
        _ => {
            println!("DFNS MPC End-to-End Test");
            println!();
            println!("Usage: dfns_e2e <command> [args]");
            println!();
            println!("Single-wallet flow (run in order):");
            println!("  setup                    Create wallet, print funding address");
            println!("  check                    Show BTC balance");
            println!("  utxos                    Create colored UTXOs");
            println!("  issue                    Issue NIA asset (1000 tokens)");
            println!();
            println!("Transfer commands:");
            println!("  receive [amount]         Create blind receive (default: 100)");
            println!("  send <recipient_id> [n]  Send n tokens (default: 100)");
            println!("  refresh                  Refresh transfers + show balances");
            println!();
            println!("BTC commands:");
            println!("  send-btc <addr> [sats]   Send vanilla BTC (default: 1000)");
            println!("  drain <addr>             Sweep all BTC to address");
            println!();
            println!("Utility:");
            println!("  clean                    Remove all test data");
            println!();
            println!("State: {}", state_path());
            println!();
            println!("Two-wallet transfer flow:");
            println!("  1. On wallet A: issue");
            println!("  2. On wallet B: receive 100");
            println!("  3. On wallet A: send <recipient_id_from_B> 100");
            println!("  4. Wait for confirmation");
            println!("  5. On wallet B: refresh");
            println!();
            println!("NOTE: MPC and non-MPC wallets are compile-time exclusive.");
            println!("For BDK peer wallet, compile without 'mpc' feature:");
            println!("  cargo run --example bdk_peer --features electrum -- <command>");
        }
    }
}
