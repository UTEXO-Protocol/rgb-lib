//! BDK peer wallet for e2e testing against DFNS MPC wallet.
//!
//! This is the non-MPC counterpart to dfns_e2e.rs.
//! Compile WITHOUT the mpc feature:
//! ```
//! cargo run --example bdk_peer --features electrum -- <command>
//! ```
//!
//! Commands: setup, check, utxos, receive, send, refresh, clean

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use rgb_lib::wallet::{
    DatabaseType, Online, Recipient, RgbWalletOpsOffline, RgbWalletOpsOnline, SinglesigKeys,
    Wallet, WalletData,
};
use rgb_lib::{AssetSchema, Assignment, BitcoinNetwork, generate_keys};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
struct PeerState {
    data_dir: String,
    mnemonic: Option<String>,
    xpub_vanilla: Option<String>,
    xpub_colored: Option<String>,
    fingerprint: Option<String>,
    funding_address: Option<String>,
    asset_id: Option<String>,
    last_recipient_id: Option<String>,
    last_invoice: Option<String>,
    last_step: String,
}

fn state_path() -> String {
    let base = env::var("E2E_DATA_DIR").unwrap_or_else(|_| "/tmp/rgb-dfns-e2e".to_string());
    format!("{base}/bdk_state.json")
}

fn load_state() -> PeerState {
    let path = state_path();
    if Path::new(&path).exists() {
        let data = fs::read_to_string(&path).expect("failed to read state");
        serde_json::from_str(&data).expect("failed to parse state")
    } else {
        PeerState::default()
    }
}

fn save_state(state: &PeerState) {
    let path = state_path();
    let dir = Path::new(&path).parent().unwrap();
    fs::create_dir_all(dir).expect("failed to create state dir");
    let data = serde_json::to_string_pretty(state).expect("failed to serialize state");
    fs::write(&path, data).expect("failed to write state");
}

// ---------------------------------------------------------------------------
// Env
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
// Wallet
// ---------------------------------------------------------------------------

fn open_wallet(state: &PeerState) -> Wallet {
    let wallet_data = WalletData {
        data_dir: state.data_dir.clone(),
        bitcoin_network: bitcoin_network(),
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: 5,
        supported_schemas: vec![AssetSchema::Nia],
        reuse_addresses: false,
    };
    let keys = SinglesigKeys {
        account_xpub_vanilla: state
            .xpub_vanilla
            .clone()
            .expect("no xpub_vanilla in state"),
        account_xpub_colored: state
            .xpub_colored
            .clone()
            .expect("no xpub_colored in state"),
        mnemonic: state.mnemonic.clone(),
        master_fingerprint: state.fingerprint.clone().expect("no fingerprint in state"),
        vanilla_keychain: None,
        witness_version: rgb_lib::keys::WitnessVersion::Taproot,
    };
    Wallet::new(wallet_data, keys).expect("failed to create BDK wallet")
}

fn go_online(wallet: &mut Wallet) -> Online {
    let url = electrum_url();
    println!("[..] Connecting to {url}");
    let online = wallet.go_online(true, url).expect("failed to go online");
    println!("[OK] Online (id: {})", online.id);
    online
}

fn separator(title: &str) {
    println!("\n============================================================");
    println!("  {title}");
    println!("============================================================\n");
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_setup(state: &mut PeerState) {
    separator("SETUP - Create BDK wallet");

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
    state.data_dir = format!("{base}/bdk");
    fs::create_dir_all(&state.data_dir).unwrap();

    let network = bitcoin_network();
    let keys = generate_keys(network, rgb_lib::keys::WitnessVersion::Taproot);
    state.mnemonic = Some(keys.mnemonic.clone());
    state.xpub_vanilla = Some(keys.account_xpub_vanilla.clone());
    state.xpub_colored = Some(keys.account_xpub_colored.clone());
    state.fingerprint = Some(keys.master_fingerprint.clone());

    let mut wallet = open_wallet(state);
    let addr = wallet.get_address().expect("get_address failed");
    state.funding_address = Some(addr.clone());

    println!("[OK] BDK wallet created");
    println!("     Data dir: {}", state.data_dir);
    println!("     Funding address: {addr}");

    state.last_step = "setup".to_string();
    save_state(state);
    println!("\n>>> Fund this address with signet BTC, then run: check");
}

fn cmd_check(state: &mut PeerState) {
    separator("CHECK - Verify BTC balance");

    let mut wallet = open_wallet(state);
    let online = go_online(&mut wallet);

    // skip_sync=false so BDK syncs with the indexer first
    let bal = wallet
        .get_btc_balance(Some(online), false)
        .expect("balance failed");
    let total = bal.vanilla.settled + bal.colored.settled;
    println!(
        "  BTC: vanilla={} sat, colored={} sat",
        bal.vanilla.settled, bal.colored.settled
    );

    if total == 0 {
        println!("\n[!!] No BTC balance.");
        if let Some(addr) = &state.funding_address {
            println!("     Address: {addr}");
        }
    } else {
        println!("\n[OK] Funded ({total} sat). Next: utxos");
    }

    state.last_step = "check".to_string();
    save_state(state);
}

fn cmd_utxos(state: &mut PeerState) {
    separator("UTXOS - Create colored UTXOs");

    let mut wallet = open_wallet(state);
    let online = go_online(&mut wallet);

    println!("[..] Creating colored UTXOs...");
    match wallet.create_utxos(online, true, Some(5), None, 1, false) {
        Ok(n) => println!("[OK] Created {n} UTXOs"),
        Err(e) => println!("[!!] create_utxos failed: {e}"),
    }

    state.last_step = "utxos".to_string();
    save_state(state);
    println!("\n>>> Wait for confirmation, then run: receive or send");
}

fn cmd_receive(state: &mut PeerState) {
    separator("RECEIVE - Create blind receive");
    let asset_id = state.asset_id.clone();

    let mut wallet = open_wallet(state);
    let _online = go_online(&mut wallet); // sync so UTXOs are up to date

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

    state.last_step = "receive".to_string();
    save_state(state);
    println!("\n>>> Give the recipient_id to the sender, then after they send, run: refresh");
}

fn cmd_send(state: &mut PeerState) {
    separator("SEND - Send tokens");

    let asset_id = state
        .asset_id
        .clone()
        .expect("No asset_id in state. Set it first or receive tokens.");

    let recipient_id = env::args()
        .nth(2)
        .unwrap_or_else(|| panic!("Usage: bdk_peer send <recipient_id> [amount]"));
    let amount: u64 = env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let mut wallet = open_wallet(state);
    let online = go_online(&mut wallet);

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
            println!("[OK] Sent! Txid: {}", result.txid);
        }
        Err(e) => println!("[!!] Send failed: {e}"),
    }

    state.last_step = "send".to_string();
    save_state(state);
}

fn cmd_refresh(state: &mut PeerState) {
    separator("REFRESH - Refresh transfers + show balances");

    let mut wallet = open_wallet(state);
    let online = go_online(&mut wallet);

    println!("[..] Refreshing...");
    match wallet.refresh(online, None, vec![], false) {
        Ok(result) => println!("[OK] {} transfers updated", result.len()),
        Err(e) => println!("[!!] Refresh: {e}"),
    }

    let bal = wallet
        .get_btc_balance(Some(online), true)
        .expect("balance failed");
    println!(
        "  BTC: vanilla={}, colored={}",
        bal.vanilla.settled, bal.colored.settled
    );

    // List assets and balances
    match wallet.list_assets(vec![AssetSchema::Nia]) {
        Ok(assets) => {
            if let Some(nia_list) = &assets.nia {
                for a in nia_list {
                    let bal = wallet
                        .get_asset_balance(a.asset_id.clone())
                        .map(|b| format!("settled={}, future={}", b.settled, b.future))
                        .unwrap_or_else(|e| format!("err: {e}"));
                    println!("  {} ({}) - {} [{}]", a.name, a.ticker, a.asset_id, bal);

                    // Auto-set asset_id if we have one
                    if state.asset_id.is_none() {
                        state.asset_id = Some(a.asset_id.clone());
                    }
                }
            }
        }
        Err(e) => println!("  List assets: {e}"),
    }

    state.last_step = "refresh".to_string();
    save_state(state);
}

fn cmd_clean() {
    separator("CLEAN - Remove BDK test data");
    let base = env::var("E2E_DATA_DIR").unwrap_or_else(|_| "/tmp/rgb-dfns-e2e".to_string());
    let bdk_dir = format!("{base}/bdk");
    let state_file = state_path();
    for path in [&bdk_dir, &state_file] {
        if Path::new(path).exists() {
            if Path::new(path).is_dir() {
                fs::remove_dir_all(path).ok();
            } else {
                fs::remove_file(path).ok();
            }
            println!("[OK] Removed {path}");
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    load_dotenv();

    let cmd = env::args().nth(1).unwrap_or_else(|| "help".to_string());

    match cmd.as_str() {
        "setup" => cmd_setup(&mut load_state()),
        "check" => cmd_check(&mut load_state()),
        "utxos" => cmd_utxos(&mut load_state()),
        "receive" => cmd_receive(&mut load_state()),
        "send" => cmd_send(&mut load_state()),
        "refresh" => cmd_refresh(&mut load_state()),
        "clean" => cmd_clean(),
        _ => {
            println!("BDK Peer Wallet (non-MPC counterpart for e2e testing)");
            println!();
            println!("Usage: bdk_peer <command> [args]");
            println!();
            println!("Commands:");
            println!("  setup              Create wallet, print funding address");
            println!("  check              Show BTC balance");
            println!("  utxos              Create colored UTXOs");
            println!("  receive [amount]   Create blind receive (default: 100)");
            println!("  send <rid> [n]     Send n tokens to recipient (default: 50)");
            println!("  refresh            Refresh + show all balances");
            println!("  clean              Remove BDK test data");
            println!();
            println!("State: {}", state_path());
            println!();
            println!("IMPORTANT: Compile WITHOUT mpc feature:");
            println!("  cargo run --example bdk_peer --features electrum -- <command>");
        }
    }
}
