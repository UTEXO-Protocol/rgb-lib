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

    let online = wallet.go_online(test_go_online_options(None)).unwrap();

    // pinned vanilla address
    let pinned_addr = wallet.get_address().unwrap();

    // fund and create utxos
    fund_wallet(pinned_addr.clone());
    wallet
        .create_utxos(online, false, None, None, FEE_RATE, false)
        .unwrap();
    mine(false);

    // send BTC to a separate wallet (generates change)
    let mut rcv_wallet = get_test_wallet(false, None);
    let rcv_addr = rcv_wallet.get_address().unwrap();
    wallet
        .send_btc(online, rcv_addr, 1000, FEE_RATE, false, None)
        .unwrap();
    mine(false);

    // all vanilla unspents should be at the pinned address
    let pinned_script = wallet
        .bdk_wallet()
        .peek_address(KeychainKind::Internal, 0)
        .address
        .script_pubkey();
    let vanilla_unspents = wallet
        .list_unspents_vanilla(online, MIN_CONFIRMATIONS, false)
        .unwrap();
    assert!(!vanilla_unspents.is_empty());
    for unspent in &vanilla_unspents {
        assert_eq!(
            unspent.txout.script_pubkey, pinned_script,
            "vanilla unspent at wrong address"
        );
    }
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn witness_receive_twice_reuses_pending_witness_script_row() {
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
    let online = wallet.go_online(test_go_online_options(None)).unwrap();

    let pinned_addr = wallet.get_address().unwrap();
    fund_wallet(pinned_addr);
    wallet
        .create_utxos(online, false, None, None, FEE_RATE, false)
        .unwrap();
    mine(false);

    // Two consecutive witness_receive calls on the same pinned External script
    // must not panic on `pending_witness_script.script` UNIQUE constraint.
    wallet
        .witness_receive(
            None,
            Assignment::Any,
            Some((now().unix_timestamp() + DURATION_RCV_TRANSFER as i64) as u64),
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .unwrap();
    wallet
        .witness_receive(
            None,
            Assignment::Any,
            Some((now().unix_timestamp() + DURATION_RCV_TRANSFER as i64) as u64),
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .unwrap();
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn witness_receive_keeps_recipient_id_but_rotates_invoice_nonce() {
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
    let online = wallet.go_online(test_go_online_options(None)).unwrap();

    let pinned_addr = wallet.get_address().unwrap();
    fund_wallet(pinned_addr);
    wallet
        .create_utxos(online, false, None, None, FEE_RATE, false)
        .unwrap();
    mine(false);

    let inv1 = wallet
        .witness_receive(
            None,
            Assignment::Any,
            Some((now().unix_timestamp() + DURATION_RCV_TRANSFER as i64) as u64),
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .unwrap();
    let inv2 = wallet
        .witness_receive(
            None,
            Assignment::Any,
            Some((now().unix_timestamp() + DURATION_RCV_TRANSFER as i64) as u64),
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .unwrap();

    // Script-derived recipient_id (Beneficiary) is stable across calls.
    assert_eq!(inv1.recipient_id, inv2.recipient_id);

    // The two invoice strings differ — each carries its own rid_nonce.
    assert_ne!(inv1.invoice, inv2.invoice);

    // Parse each invoice and verify the transport endpoint round-trips with
    // a `rid_nonce=<hex>` query parameter that decodes to a 16-byte vec.
    for (label, inv) in [("inv1", &inv1), ("inv2", &inv2)] {
        let parsed = Invoice::new(inv.invoice.clone()).unwrap();
        let endpoints = parsed.invoice_data().transport_endpoints;
        assert!(!endpoints.is_empty(), "{label}: no transport endpoints");
        let ep = &endpoints[0];
        assert!(
            ep.contains("rid_nonce="),
            "{label}: parsed endpoint missing rid_nonce=: {ep}"
        );
        let (_, nonce) = crate::utils::extract_recipient_nonce(ep);
        let nonce = nonce.expect("rid_nonce should parse");
        assert_eq!(nonce.len(), 16, "{label}: nonce wrong length: {nonce:?}");
    }
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn two_consecutive_witness_transfers_both_settle() {
    initialize();

    // Sender: default funded party (no reuse). Issues an asset.
    let mut party = get_funded_party!();
    let asset = party.issue_asset_nia(Some(&[AMOUNT, AMOUNT * 2]));

    // Receiver: reuse_addresses=true so both invoices hit the same pinned
    // External script. Verifies the proxy routing key differs per invoice
    // so the second send is not rejected as a duplicate.
    let bitcoin_network = BitcoinNetwork::Regtest;
    let keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let mut rcv_wallet = Wallet::new(
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
    let rcv_online = rcv_wallet.go_online(test_go_online_options(None)).unwrap();
    fund_wallet(rcv_wallet.get_address().unwrap());
    rcv_wallet
        .create_utxos(rcv_online, false, None, None, FEE_RATE, false)
        .unwrap();
    mine(false);
    let mut rcv_party = party!(rcv_wallet, rcv_online);

    let amount: u64 = 1;
    let mut prior_recipient_id: Option<String> = None;
    let mut rcv_batch_idxs: Vec<i32> = vec![];
    let mut sender_txids: Vec<String> = vec![];
    for cycle in 0..2 {
        // Receiver issues a witness invoice. Reuse_addresses ⇒ same pinned
        // script ⇒ same recipient_id; only the rid_nonce changes per call.
        let receive_data = rcv_party.witness_receive();
        if let Some(prev) = prior_recipient_id.as_ref() {
            assert_eq!(
                prev, &receive_data.recipient_id,
                "cycle {cycle}: recipient_id (beneficiary) should be pinned across calls"
            );
        }
        prior_recipient_id = Some(receive_data.recipient_id.clone());
        rcv_batch_idxs.push(receive_data.batch_transfer_idx);

        // Build the sender's Recipient from the parsed invoice, so the
        // transport URLs carry rid_nonce (matching production sender flow).
        let invoice = Invoice::new(receive_data.invoice.clone()).unwrap();
        let invoice_endpoints = invoice.invoice_data().transport_endpoints;
        let recipient_map = HashMap::from([(
            asset.asset_id.clone(),
            vec![Recipient {
                assignment: Assignment::Fungible(amount),
                recipient_id: receive_data.recipient_id.clone(),
                witness_data: Some(WitnessData {
                    amount_sat: 1000,
                    blinding: None,
                }),
                transport_endpoints: invoice_endpoints,
            }],
        )]);
        let txid = party.send_retry(&recipient_map);
        assert!(!txid.is_empty(), "cycle {cycle}: send returned empty txid");
        sender_txids.push(txid);

        // Drive both sides to Settled.
        std::thread::sleep(Duration::from_millis(1000));
        rcv_party.wait_for_refresh(None);
        party.wait_for_refresh(Some(&asset.asset_id));
        mine(false);
        std::thread::sleep(Duration::from_millis(1000));
        rcv_party.wait_for_refresh(None);
        party.wait_for_refresh(Some(&asset.asset_id));
    }

    // Both witness transfers on the receiver must be Settled. Look up by
    // batch_transfer_idx (unique per invoice) since recipient_id is shared
    // across the two transfers under reuse_addresses.
    let rcv_transfers = rcv_party.list_transfers(Some(&asset.asset_id));
    for batch_idx in &rcv_batch_idxs {
        let t = rcv_transfers
            .iter()
            .find(|t| t.batch_transfer_idx == *batch_idx)
            .unwrap_or_else(|| panic!("no receiver transfer for batch_idx {batch_idx}"));
        assert_eq!(
            t.status,
            TransferStatus::Settled,
            "receiver transfer for batch_idx {batch_idx} not settled"
        );
    }

    // Both sends on the sender side must also be Settled.
    for txid in &sender_txids {
        let (sender_transfer, _, _) = party.get_test_transfer_sender(txid);
        let (sender_data, _) = party.get_test_transfer_data(&sender_transfer);
        assert_eq!(
            sender_data.status,
            TransferStatus::Settled,
            "sender transfer for txid {txid} not settled"
        );
    }
}
