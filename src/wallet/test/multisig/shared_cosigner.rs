//! Two multisig wallets sharing one cosigner key from a pool of three.
//!
//! Key pool: K1, K2, K3
//! - Wallet A (2-of-2): cosigners = [K1, K2]  — K1 shared
//! - Wallet B (2-of-2): cosigners = [K1, K3]  — K1 shared, K3 unique
//!
//! K1 therefore appears twice across the two wallets; K2 and K3 once each.

use super::*;
use utils::*;

/// Offline: shared K1 yields two distinct multisig wallets with isolated dirs/state.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn shared_cosigner_two_wallets_offline() {
    create_test_data_dir();

    let bitcoin_network = BitcoinNetwork::Regtest;
    let threshold = 2u8;
    let random_str: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let k1 = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let k2 = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let k3 = generate_keys(bitcoin_network, WitnessVersion::Taproot);

    let c1 = Cosigner::from_keys(&k1, None);
    let c2 = Cosigner::from_keys(&k2, None);
    let c3 = Cosigner::from_keys(&k3, None);

    let keys_a = MultisigKeys::new(vec![c1.clone(), c2.clone()], threshold, threshold);
    let keys_b = MultisigKeys::new(vec![c1.clone(), c3.clone()], threshold, threshold);

    let desc_a = keys_a.build_descriptors(bitcoin_network).unwrap();
    let desc_b = keys_b.build_descriptors(bitcoin_network).unwrap();
    assert_ne!(desc_a.colored, desc_b.colored);
    assert_ne!(desc_a.vanilla, desc_b.vanilla);

    // shared cosigner identity
    assert_eq!(
        c1.master_fingerprint,
        keys_a.cosigners[0].master_fingerprint
    );
    assert_eq!(
        c1.master_fingerprint,
        keys_b.cosigners[0].master_fingerprint
    );
    assert_eq!(
        keys_a.cosigners[0].account_xpub_colored,
        keys_b.cosigners[0].account_xpub_colored
    );
    // unique legs
    assert_ne!(
        keys_a.cosigners[1].master_fingerprint,
        keys_b.cosigners[1].master_fingerprint
    );

    let ms_a = get_test_ms_wallet(&keys_a, format!("{random_str}_a"));
    let ms_b = get_test_ms_wallet(&keys_b, format!("{random_str}_b"));

    let dir_a = ms_a.get_wallet_dir();
    let dir_b = ms_b.get_wallet_dir();
    assert_ne!(
        dir_a, dir_b,
        "shared K1 must not collapse wallet state dirs"
    );
    assert!(dir_a.exists());
    assert!(dir_b.exists());
    assert_ne!(
        dir_a.file_name(),
        dir_b.file_name(),
        "fingerprint dirs must differ (descriptor hash)"
    );

    // K1 can be the singlesig signer for BOTH multisig groups
    let ss_k1 = get_test_wallet_with_keys(&k1);
    assert_eq!(ss_k1.get_wallet_data().bitcoin_network, bitcoin_network);
    let _ = ss_k1; // signing itself needs a live PSBT from hub ops

    // reopen A and B — state dirs still independent
    drop(ms_a);
    drop(ms_b);
    let ms_a2 = MultisigWallet::new(
        WalletData {
            data_dir: get_test_data_dir_path()
                .join(format!("{random_str}_a"))
                .to_string_lossy()
                .to_string(),
            bitcoin_network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        keys_a.clone(),
    )
    .unwrap();
    let ms_b2 = MultisigWallet::new(
        WalletData {
            data_dir: get_test_data_dir_path()
                .join(format!("{random_str}_b"))
                .to_string_lossy()
                .to_string(),
            bitcoin_network,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        keys_b.clone(),
    )
    .unwrap();
    assert_eq!(ms_a2.get_wallet_dir(), dir_a);
    assert_eq!(ms_b2.get_wallet_dir(), dir_b);
    assert_eq!(ms_a2.get_keys(), keys_a);
    assert_eq!(ms_b2.get_keys(), keys_b);

    println!(
        "OK offline: A={} B={} shared_fp={}",
        dir_a.display(),
        dir_b.display(),
        c1.master_fingerprint
    );
}

/// Full hub e2e: fund / create_utxos / issue on A then B, verify balances stay isolated.
///
/// Ignored locally while rgb-multisig-hub rejects biscuit tokens
/// (`Missing or invalid credentials`) — same failure hits stock `multisig::fail`.
/// Run when hub auth works:
///   cargo test --features electrum shared_cosigner_two_wallets_hub -- --ignored --nocapture
#[cfg(feature = "electrum")]
#[test]
#[serial]
#[ignore = "hub biscuit auth broken in current docker image/env"]
fn shared_cosigner_two_wallets_hub() {
    initialize();

    let bitcoin_network = BitcoinNetwork::Regtest;
    let threshold = 2u8;
    let random_str: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let k1 = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let k2 = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let k3 = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let c1 = Cosigner::from_keys(&k1, None);
    let c2 = Cosigner::from_keys(&k2, None);
    let c3 = Cosigner::from_keys(&k3, None);
    let keys_a = MultisigKeys::new(vec![c1.clone(), c2.clone()], threshold, threshold);
    let keys_b = MultisigKeys::new(vec![c1.clone(), c3.clone()], threshold, threshold);

    let ss_k1 = get_test_wallet_with_keys(&k1);
    let ss_k2 = get_test_wallet_with_keys(&k2);
    let ss_k3 = get_test_wallet_with_keys(&k3);

    // --- Wallet A ---
    op_counter_reset();
    let root_a = KeyPair::new();
    let xpubs_a = vec![
        c1.account_xpub_colored.clone(),
        c2.account_xpub_colored.clone(),
    ];
    let token_a1 = create_token(&root_a, Role::Cosigner(xpubs_a[0].clone()), None);
    let token_a2 = create_token(&root_a, Role::Cosigner(xpubs_a[1].clone()), None);
    write_hub_config(
        &xpubs_a,
        threshold,
        threshold,
        root_a.public().to_bytes_hex(),
        None,
    );
    restart_multisig_hub();
    std::thread::sleep(std::time::Duration::from_secs(3));

    let mut ms_a1 = get_test_ms_wallet(&keys_a, format!("{random_str}_a1"));
    let online_a1 = ms_go_online(&mut ms_a1, &token_a1);
    let mut ms_a2 = get_test_ms_wallet(&keys_a, format!("{random_str}_a2"));
    let online_a2 = ms_go_online(&mut ms_a2, &token_a2);
    let wallet_dir_a = ms_a1.get_wallet_dir();
    let mut party_a1 = ms_party!(&ss_k1, &mut ms_a1, online_a1, &xpubs_a[0]);
    let mut party_a2 = ms_party!(&ss_k2, &mut ms_a2, online_a2, &xpubs_a[1]);

    send_sats_to_address(party_a1.get_address(), Some(20_000));
    mine(false);
    let op_a = party_a1.create_utxos_init(false, Some(3), Some(1000), FEE_RATE);
    operation_complete::<CreateUtxosHandler>(
        op_a.operation_idx,
        &mut [&mut party_a1, &mut party_a2],
        &mut [],
        &mut [],
        true,
    );
    let IssuedAsset::Nia(asset_a) = issue_asset(
        &mut party_a1,
        &mut [&mut party_a2],
        AssetSchema::Nia,
        Some(&[1_000_000]),
        None,
    ) else {
        unreachable!()
    };
    check_asset_balance(
        &[&party_a1, &party_a2],
        &asset_a.asset_id,
        (1_000_000, 1_000_000, 1_000_000),
    );
    let asset_a_id = asset_a.asset_id.clone();
    drop(party_a1);
    drop(party_a2);
    drop(ms_a1);
    drop(ms_a2);

    // --- Wallet B ---
    op_counter_reset();
    let root_b = KeyPair::new();
    let xpubs_b = vec![
        c1.account_xpub_colored.clone(),
        c3.account_xpub_colored.clone(),
    ];
    let token_b1 = create_token(&root_b, Role::Cosigner(xpubs_b[0].clone()), None);
    let token_b2 = create_token(&root_b, Role::Cosigner(xpubs_b[1].clone()), None);
    write_hub_config(
        &xpubs_b,
        threshold,
        threshold,
        root_b.public().to_bytes_hex(),
        None,
    );
    restart_multisig_hub();
    std::thread::sleep(std::time::Duration::from_secs(3));

    let mut ms_b1 = get_test_ms_wallet(&keys_b, format!("{random_str}_b1"));
    let online_b1 = ms_go_online(&mut ms_b1, &token_b1);
    let mut ms_b2 = get_test_ms_wallet(&keys_b, format!("{random_str}_b2"));
    let online_b2 = ms_go_online(&mut ms_b2, &token_b2);
    let wallet_dir_b = ms_b1.get_wallet_dir();
    assert_ne!(wallet_dir_a, wallet_dir_b);

    let mut party_b1 = ms_party!(&ss_k1, &mut ms_b1, online_b1, &xpubs_b[0]);
    let mut party_b2 = ms_party!(&ss_k3, &mut ms_b2, online_b2, &xpubs_b[1]);
    send_sats_to_address(party_b1.get_address(), Some(20_000));
    mine(false);
    let op_b = party_b1.create_utxos_init(false, Some(3), Some(1000), FEE_RATE);
    operation_complete::<CreateUtxosHandler>(
        op_b.operation_idx,
        &mut [&mut party_b1, &mut party_b2],
        &mut [],
        &mut [],
        true,
    );
    let IssuedAsset::Nia(asset_b) = issue_asset(
        &mut party_b1,
        &mut [&mut party_b2],
        AssetSchema::Nia,
        Some(&[2_000_000]),
        None,
    ) else {
        unreachable!()
    };
    check_asset_balance(
        &[&party_b1, &party_b2],
        &asset_b.asset_id,
        (2_000_000, 2_000_000, 2_000_000),
    );
    let asset_b_id = asset_b.asset_id.clone();
    assert_ne!(asset_a_id, asset_b_id);
    drop(party_b1);
    drop(party_b2);
    drop(ms_b1);
    drop(ms_b2);

    // reopen A — RGB state must still be there, B's asset absent
    let ms_a_re = MultisigWallet::new(
        WalletData {
            data_dir: get_test_data_dir_path()
                .join(format!("{random_str}_a1"))
                .to_string_lossy()
                .to_string(),
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        keys_a,
    )
    .unwrap();
    assert_eq!(ms_a_re.get_wallet_dir(), wallet_dir_a);
    let bal_a = ms_a_re.get_asset_balance(asset_a_id.clone()).unwrap();
    assert_eq!(bal_a.settled, 1_000_000);
    assert!(ms_a_re.get_asset_balance(asset_b_id.clone()).is_err());

    let ms_b_re = MultisigWallet::new(
        WalletData {
            data_dir: get_test_data_dir_path()
                .join(format!("{random_str}_b1"))
                .to_string_lossy()
                .to_string(),
            bitcoin_network: BitcoinNetwork::Regtest,
            database_type: DatabaseType::Sqlite,
            max_allocations_per_utxo: MAX_ALLOCATIONS_PER_UTXO,
            supported_schemas: AssetSchema::VALUES.to_vec(),
            reuse_addresses: false,
        },
        keys_b,
    )
    .unwrap();
    assert_eq!(ms_b_re.get_wallet_dir(), wallet_dir_b);
    let bal_b = ms_b_re.get_asset_balance(asset_b_id).unwrap();
    assert_eq!(bal_b.settled, 2_000_000);
    assert!(ms_b_re.get_asset_balance(asset_a_id).is_err());
}

/// Same cosigner listed twice in one MultisigKeys — not deduped in the descriptor.
#[test]
#[parallel]
fn duplicate_cosigner_in_same_wallet_keys() {
    let bitcoin_network = BitcoinNetwork::Regtest;
    let k1 = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let k2 = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let c1 = Cosigner::from_keys(&k1, None);
    let c2 = Cosigner::from_keys(&k2, None);

    let keys = MultisigKeys::new(vec![c1.clone(), c1.clone(), c2], 2, 2);
    let descs = keys.build_descriptors(bitcoin_network).unwrap();
    let c1_frag = format!("[{}/", c1.master_fingerprint);
    assert_eq!(
        descs.colored.matches(&c1_frag).count(),
        2,
        "duplicate cosigner is not deduped: {}",
        descs.colored
    );
}
