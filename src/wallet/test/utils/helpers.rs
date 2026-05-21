use super::*;

/// Panic if the given expression doesn't match the provided pattern, logging the unexpected result
#[macro_export]
macro_rules! assert_matches {
    ($expression:expr, $pattern:pat $(if $guard:expr)? $(,)?) => {
        match $expression {
            $pattern $(if $guard)? => {},
            _ => {
                panic!("received unexpected result: {}", format!("{:?}", $expression));
            }
        }
    };
}

pub(crate) fn join_with_sep(parts: &[&str]) -> String {
    parts.join(MAIN_SEPARATOR_STR)
}

pub(crate) fn get_current_time() -> u128 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

pub(crate) fn get_restore_dir_string() -> String {
    join_with_sep(&RESTORE_DIR_PARTS)
}

pub(crate) fn get_test_data_dir_string() -> String {
    join_with_sep(&TEST_DATA_DIR_PARTS)
}

pub(crate) fn get_restore_dir_path<P: AsRef<Path>>(last: Option<P>) -> PathBuf {
    let mut path = PathBuf::from(get_restore_dir_string());
    if let Some(l) = last {
        path = path.join(l);
    }
    path
}

pub(crate) fn get_test_data_dir_path() -> PathBuf {
    PathBuf::from(get_test_data_dir_string())
}

pub(crate) fn create_test_data_dir() -> PathBuf {
    let test_data_dir = get_test_data_dir_path();
    if !test_data_dir.exists() {
        fs::create_dir_all(&test_data_dir).unwrap();
    }
    test_data_dir
}

pub(crate) fn get_test_wallet_data(data_dir: &str) -> WalletData {
    WalletData {
        data_dir: data_dir.to_string(),
        bitcoin_network: BitcoinNetwork::Regtest,
        database_type: DatabaseType::Sqlite,
        max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
        supported_schemas: AssetSchema::VALUES.to_vec(),
        reuse_addresses: false,
    }
}

pub(crate) fn get_test_wallet_with_keys(keys: &Keys) -> Wallet {
    let wallet_keys = SinglesigKeys::from_keys(keys, None);
    get_test_wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest)
}

// return a wallet for testing
pub(crate) fn get_test_wallet_with_net(
    private_keys: bool,
    max_allocations_per_utxo: Option<u32>,
    bitcoin_network: BitcoinNetwork,
) -> Wallet {
    let keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let wallet_keys = if private_keys {
        SinglesigKeys::from_keys(&keys, None)
    } else {
        SinglesigKeys::from_keys_no_mnemonic(&keys, None)
    };
    get_test_wallet_raw(&wallet_keys, max_allocations_per_utxo, bitcoin_network)
}

// return a wallet for testing
pub(crate) fn get_test_wallet_raw(
    wallet_keys: &SinglesigKeys,
    max_allocations_per_utxo: Option<u32>,
    bitcoin_network: BitcoinNetwork,
) -> Wallet {
    create_test_data_dir();

    let wallet = Wallet::new(
        WalletData {
            data_dir: get_test_data_dir_string(),
            bitcoin_network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: max_allocations_per_utxo.unwrap_or(MAX_ALLOCATIONS_PER_UTXO),
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        wallet_keys.clone(),
    )
    .unwrap();
    println!("wallet directory: {:?}", wallet.get_wallet_dir());
    wallet
}

// return a regtest wallet for testing
pub(crate) fn get_test_wallet(private_keys: bool, max_allocations_per_utxo: Option<u32>) -> Wallet {
    get_test_wallet_with_net(
        private_keys,
        max_allocations_per_utxo,
        BitcoinNetwork::Regtest,
    )
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_funded_party_p2wpkh() -> SinglesigParty {
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::SegWitV0);
    let mut wallet = Wallet::new(
        WalletData {
            data_dir: get_test_data_dir_string(),
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        SinglesigKeys::from_keys(&keys, None),
    )
    .unwrap();
    let online = wallet.go_online(test_go_online_options(None)).unwrap();
    let mut party = party!(wallet, online);
    fund_wallet(party.get_address());
    party.create_utxos_default();
    party
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_empty_wallet(
    private_keys: bool,
    indexer_url: Option<String>,
) -> (Wallet, Online) {
    let mut wallet = get_test_wallet(private_keys, None);
    let online = wallet
        .go_online(test_go_online_options(indexer_url.as_deref()))
        .unwrap();
    (wallet, online)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_funded_noutxo_wallet(
    private_keys: bool,
    indexer_url: Option<String>,
) -> (Wallet, Online) {
    let (mut wallet, online) = get_empty_wallet(private_keys, indexer_url);
    fund_wallet(wallet.get_address().unwrap());
    (wallet, online)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_funded_party(private_keys: bool, indexer_url: Option<String>) -> SinglesigParty {
    let (wallet, online) = get_funded_noutxo_wallet(private_keys, indexer_url);
    let mut party = party!(wallet, online);
    party.create_utxos_default();
    party
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_empty_party(private_keys: bool, indexer_url: Option<String>) -> SinglesigParty {
    let (wallet, online) = get_empty_wallet(private_keys, indexer_url);
    party!(wallet, online)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_funded_noutxo_party(
    private_keys: bool,
    indexer_url: Option<String>,
) -> SinglesigParty {
    let (wallet, online) = get_funded_noutxo_wallet(private_keys, indexer_url);
    party!(wallet, online)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn send_to_address(address: String) {
    send_sats_to_address(address, None);
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn send_sats_to_address(address: String, sats: Option<u64>) {
    let amt = BdkAmount::from_sat(sats.unwrap_or(100_000_000));
    let btc_str = amt.to_string_in(Denomination::Bitcoin);
    let t_0 = OffsetDateTime::now_utc();
    let bitcoin_cli = bitcoin_cli();
    loop {
        if (OffsetDateTime::now_utc() - t_0).as_seconds_f32() > 120.0 {
            panic!("could not send to address ({QUEUE_DEPTH_EXCEEDED})");
        }
        let output = Command::new("docker")
            .stdin(Stdio::null())
            .arg("compose")
            .args(&bitcoin_cli)
            .arg("-rpcwallet=miner")
            .arg("sendtoaddress")
            .arg(&address)
            .arg(&btc_str)
            .output()
            .expect("failed to fund wallet");
        if !output.status.success()
            && String::from_utf8(output.stderr)
                .unwrap()
                .contains(QUEUE_DEPTH_EXCEEDED)
        {
            eprintln!("work queue depth exceeded");
            std::thread::sleep(std::time::Duration::from_millis(500));
            continue;
        }
        assert!(output.status.success());
        break;
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn fund_wallet(address: String) {
    send_to_address(address);
    mine(false);
}

pub(crate) fn compare_test_directories(src: &Path, dst: &Path, skip: &[&str]) {
    let ignores = RegexSet::new(skip).unwrap();
    let cmp = dircmp::Comparison::new(ignores);
    let diff = cmp.compare(src, dst).unwrap();
    assert!(diff.is_empty());
}

pub(crate) fn get_test_batch_transfers(wallet: &Wallet, txid: &str) -> Vec<DbBatchTransfer> {
    let txn = wallet.database().begin_transaction().unwrap();
    let batch_transfers = txn.iter_batch_transfers().unwrap();
    txn.commit().unwrap();
    batch_transfers
        .into_iter()
        .filter(|b| b.txid == Some(txid.to_string()))
        .collect()
}

pub(crate) fn get_test_asset_transfers(
    wallet: &Wallet,
    batch_transfer_idx: i32,
) -> Vec<DbAssetTransfer> {
    let txn = wallet.database().begin_transaction().unwrap();
    let asset_transfers = txn.iter_asset_transfers().unwrap();
    txn.commit().unwrap();
    asset_transfers
        .into_iter()
        .filter(|at| at.batch_transfer_idx == batch_transfer_idx)
        .collect()
}

pub(crate) fn get_test_transfers(
    wallet: &Wallet,
    asset_transfer_idx: i32,
) -> impl Iterator<Item = DbTransfer> {
    let txn = wallet.database().begin_transaction().unwrap();
    let transfers = txn.iter_transfers().unwrap();
    txn.commit().unwrap();
    transfers
        .into_iter()
        .filter(move |t| t.asset_transfer_idx == asset_transfer_idx)
}

pub(crate) fn get_test_asset_transfer(wallet: &Wallet, batch_transfer_idx: i32) -> DbAssetTransfer {
    let asset_transfers = get_test_asset_transfers(wallet, batch_transfer_idx);
    let mut user_driven_transfers = asset_transfers.into_iter().filter(|t| t.user_driven);
    let user_driven_transfer = user_driven_transfers.next().unwrap();
    assert!(user_driven_transfers.next().is_none());
    user_driven_transfer
}

pub(crate) fn get_test_colorings(wallet: &Wallet, asset_transfer_idx: i32) -> Vec<DbColoring> {
    let txn = wallet.database().begin_transaction().unwrap();
    let colorings = txn.iter_colorings().unwrap();
    txn.commit().unwrap();
    colorings
        .into_iter()
        .filter(|c| c.asset_transfer_idx == asset_transfer_idx)
        .collect()
}

pub(crate) fn get_test_transfer_recipient(wallet: &Wallet, recipient_id: &str) -> DbTransfer {
    let txn = wallet.database().begin_transaction().unwrap();
    let all_transfers = txn.iter_transfers().unwrap();
    txn.commit().unwrap();
    let mut transfers = all_transfers
        .into_iter()
        .filter(|t| t.recipient_id == Some(recipient_id.to_string()) && t.incoming);
    let transfer = transfers.next().unwrap();
    assert!(transfers.next().is_none());
    transfer
}

pub(crate) fn get_test_transfer_sender(
    wallet: &Wallet,
    txid: &str,
) -> (DbTransfer, DbAssetTransfer, DbBatchTransfer) {
    let batch_transfers = get_test_batch_transfers(wallet, txid);
    assert_eq!(batch_transfers.len(), 1);
    let batch_transfer = batch_transfers.into_iter().next().unwrap();
    let asset_transfer = get_test_asset_transfer(wallet, batch_transfer.idx);
    let mut transfers = get_test_transfers(wallet, asset_transfer.idx);
    let transfer = transfers.next().unwrap();
    assert!(transfers.next().is_none());
    (transfer, asset_transfer, batch_transfer)
}

pub(crate) fn get_test_transfers_sender(
    wallet: &Wallet,
    txid: &str,
) -> (
    HashMap<String, Vec<DbTransfer>>,
    Vec<DbAssetTransfer>,
    DbBatchTransfer,
) {
    let batch_transfers = get_test_batch_transfers(wallet, txid);
    assert_eq!(batch_transfers.len(), 1);
    let batch_transfer = batch_transfers.into_iter().next().unwrap();
    let asset_transfers = get_test_asset_transfers(wallet, batch_transfer.idx);
    let mut transfers: HashMap<String, Vec<DbTransfer>> = HashMap::new();
    for asset_transfer in &asset_transfers {
        let asset_id = asset_transfer.asset_id.clone().unwrap();
        let transfers_for_asset = get_test_transfers(wallet, asset_transfer.idx);
        transfers.insert(asset_id, transfers_for_asset.collect());
    }
    (transfers, asset_transfers, batch_transfer)
}

pub(crate) fn get_test_transfer_data(
    wallet: &Wallet,
    transfer: &DbTransfer,
) -> (TransferData, DbAssetTransfer) {
    let db_data = test_get_db_data(wallet, false);
    let (asset_transfer, batch_transfer) =
        transfer.related_transfers(&db_data.asset_transfers, &db_data.batch_transfers);
    let transfer_data = wallet
        .get_transfer_data(
            transfer,
            &asset_transfer,
            &batch_transfer,
            &db_data.txos,
            &db_data.colorings,
        )
        .unwrap();
    (transfer_data, asset_transfer)
}

pub(crate) fn get_test_transfer_related(
    wallet: &Wallet,
    transfer: &DbTransfer,
) -> (DbAssetTransfer, DbBatchTransfer) {
    let db_data = test_get_db_data(wallet, false);
    transfer.related_transfers(&db_data.asset_transfers, &db_data.batch_transfers)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn list_test_unspents(wallet: &mut Wallet, msg: &str) -> Vec<Unspent> {
    let unspents = test_list_unspents(wallet, None, false);
    print_unspents(&unspents, msg);
    unspents
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_colorable_unspents(
    wallet: &mut Wallet,
    online: Option<Online>,
    settled_only: bool,
) -> Vec<Unspent> {
    test_list_unspents(wallet, online, settled_only)
        .into_iter()
        .filter(|u| u.utxo.colorable)
        .collect()
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn assert_colorable_unspent_count(
    wallet: &mut Wallet,
    online: Option<Online>,
    settled_only: bool,
    expected_len: usize,
) {
    let colorable_len = get_colorable_unspents(wallet, online, settled_only).len();
    assert_eq!(colorable_len, expected_len);
}

pub(crate) fn print_unspents(unspents: &[Unspent], msg: &str) {
    println!("\n{msg} ({} unspents)", unspents.len());
    for u in unspents {
        println!(
            "> {} {} {}",
            u.utxo.outpoint,
            u.utxo.btc_amount,
            if u.utxo.colorable {
                "colorable"
            } else {
                "vanilla"
            }
        );
        for a in &u.rgb_allocations {
            println!(
                "\t- {} {:?} {}",
                a.asset_id.as_ref().unwrap(),
                a.assignment,
                if a.settled { "settled" } else { "pending" }
            )
        }
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn wait_for_asset_balance(wallet: &Wallet, asset_id: &str, expected_balance: &Balance) {
    println!("waiting for asset balance");
    let mut current_balance = test_get_asset_balance(wallet, asset_id);
    let check = || {
        current_balance = test_get_asset_balance(wallet, asset_id);
        if &current_balance == expected_balance {
            return true;
        }
        false
    };
    if !wait_for_function(check, 10, 500) {
        println!("current balance: {current_balance:?}");
        println!("expected balance: {expected_balance:?}");
        panic!("asset balance is not becoming the expected one");
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn restart_test_wallet(
    wallet_data: WalletData,
    keys: SinglesigKeys,
) -> (Wallet, Online) {
    let mut wallet = Wallet::new(wallet_data, keys).expect("wallet recreate failed");
    let online = wallet
        .go_online(test_go_online_options(None))
        .expect("go_online after recreate failed");
    (wallet, online)
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn wait_for_btc_balance(
    wallet: &mut Wallet,
    online: Online,
    expected_balance: &BtcBalance,
) {
    println!("waiting for BTC balance");
    let mut current_balance = test_get_btc_balance(wallet, online);
    let check = || {
        current_balance = test_get_btc_balance(wallet, online);
        if &current_balance == expected_balance {
            return true;
        }
        false
    };
    if !wait_for_function(check, 10, 500) {
        println!("current balance: {current_balance:?}");
        println!("expected balance: {expected_balance:?}");
        panic!("BTC balance is not becoming the expected one");
    }
}

pub(crate) fn wait_for_function<F>(mut func: F, timeout_secs: u8, interval_ms: u16) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs as u64);
    while start.elapsed() < timeout {
        if func() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(interval_ms as u64));
    }
    false
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn write_opouts_to_reject_list(filename: &str, opouts: &[String]) {
    let lists_dir = PathBuf::from(join_with_sep(&LISTS_DIR_PARTS));
    if !lists_dir.exists() {
        fs::create_dir_all(&lists_dir).unwrap();
    }
    let file_path = lists_dir.join(filename);
    let mut file = std::fs::File::create(&file_path).unwrap();
    for opout in opouts {
        writeln!(file, "{}", opout).unwrap()
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn get_proxy_client(proxy_url: Option<&str>) -> ProxyClient {
    ProxyClient::new(proxy_url.unwrap_or(PROXY_URL)).unwrap()
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) fn test_go_online_options(indexer_url: Option<&str>) -> OnlineOptions {
    OnlineOptions {
        indexer_url: indexer_url.unwrap_or(ELECTRUM_URL).to_string(),
        skip_consistency_check: true,
        vanilla_sync_lookback: INDEXER_SYNC_LOOKBACK as u32,
    }
}
