use super::*;

#[test]
#[parallel]
fn reuse_returns_same_address() {
    create_test_data_dir();

    let bitcoin_network = BitcoinNetwork::Regtest;
    let keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let mut wallet = Wallet::new(
        WalletData {
            data_dir: get_test_data_dir_string(),
            bitcoin_network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: true,
        },
        SinglesigKeys::from_keys(&keys, None),
    )
    .unwrap();

    // Internal (vanilla) keychain: same address on repeated calls
    let addr1 = wallet.get_address().unwrap();
    let addr2 = wallet.get_address().unwrap();
    assert_eq!(addr1, addr2);

    // External (colored) keychain: rotate works independently
    let colored1 = wallet.rotate_address(KeychainKind::External).unwrap();
    let colored2 = wallet.rotate_address(KeychainKind::External).unwrap();
    assert_ne!(colored1, colored2);
    assert_ne!(colored1, addr1);
}

#[test]
#[parallel]
fn rotate_changes_address() {
    create_test_data_dir();

    let bitcoin_network = BitcoinNetwork::Regtest;
    let keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let mut wallet = Wallet::new(
        WalletData {
            data_dir: get_test_data_dir_string(),
            bitcoin_network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: true,
        },
        SinglesigKeys::from_keys(&keys, None),
    )
    .unwrap();

    let old_addr = wallet.get_address().unwrap();
    let rotated_addr = wallet.rotate_address(KeychainKind::Internal).unwrap();
    let new_addr = wallet.get_address().unwrap();

    assert_ne!(new_addr, old_addr);
    assert_eq!(rotated_addr, new_addr);
}

#[test]
#[parallel]
fn rotate_disabled_errors() {
    let mut wallet = get_test_wallet(false, None);
    let result = wallet.rotate_address(KeychainKind::Internal);
    assert!(matches!(result, Err(Error::AddressReuseDisabled)));
}

/// Verify that send_btc and create_utxos change outputs go to the pinned reuse address.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_btc_change_reuses_address() {
    initialize();

    let bitcoin_network = BitcoinNetwork::Regtest;
    let keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let mut wallet = Wallet::new(
        WalletData {
            data_dir: get_test_data_dir_string(),
            bitcoin_network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: true,
        },
        SinglesigKeys::from_keys(&keys, None),
    )
    .unwrap();

    let online = wallet.go_online(true, ELECTRUM_URL.to_string()).unwrap();

    // pinned vanilla address
    let pinned_addr = wallet.get_address().unwrap();

    // fund and create utxos
    fund_wallet(pinned_addr.clone());
    test_create_utxos_default(&mut wallet, online);
    mine(false, false);

    // send BTC to a separate wallet (generates change)
    let mut rcv_wallet = get_test_wallet(false, None);
    let rcv_addr = rcv_wallet.get_address().unwrap();
    wallet
        .send_btc(online, rcv_addr, 1000, FEE_RATE, false)
        .unwrap();
    mine(false, false);

    // all vanilla unspents should be at the pinned address
    let pinned_script = wallet
        .bdk_wallet()
        .peek_address(KeychainKind::Internal, 0)
        .address
        .script_pubkey();
    let vanilla_unspents = test_list_unspents_vanilla(&mut wallet, online, None);
    assert!(!vanilla_unspents.is_empty());
    for unspent in &vanilla_unspents {
        assert_eq!(
            unspent.txout.script_pubkey, pinned_script,
            "vanilla unspent at wrong address"
        );
    }
}
