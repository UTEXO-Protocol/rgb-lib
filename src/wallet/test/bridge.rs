use super::*;

/// A BFA mint is only valid against a real EVM lock, so this exercises the whole loop: deploy an
/// ERC-20 and a bridge on anvil, issue an asset bound to that bridge, prepare the mint, lock the
/// tokens under the resulting OpId, and only then broadcast.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let eth_supply = 1_000_000;
    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, eth_supply);
    assert_eq!(
        erc20_balance_of(&eth_contract.address, &eth_contract.deployer),
        eth_supply
    );
    let bridge_contract = deploy_bridge(&eth_contract.address);

    let mut party = get_funded_party!();

    let asset = party.issue_asset_bfa(1, bridge_contract.address.clone(), None);
    assert_eq!(asset.initial_supply, 0);
    // nothing has been bridged in yet
    assert_eq!(
        party
            .get_asset_metadata(&asset.asset_id)
            .known_circulating_supply,
        0
    );

    // mint to ourselves through a blinded invoice
    party.create_utxos_default();
    let receive_data = party.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };

    let begin = party.bridge_begin(&asset.asset_id, recipient);
    // The OpId binds the two domains: it is what the EVM lock must commit to.
    assert_eq!(begin.details.opid.len(), 64);
    // nothing reaches the proxy before the mint is broadcast: a failure between
    // here and bridge_end must leave the invoice reusable
    assert!(
        !party.refresh_all(),
        "the consignment was posted before the mint was broadcast"
    );

    // lock the ERC-20 under that OpId, then complete the mint
    erc20_approve(&eth_contract.address, &bridge_contract.address, AMOUNT);
    bridge_funds_in(&bridge_contract.address, AMOUNT, &begin.details.opid);

    let signed_psbt = party.wallet.sign_psbt(begin.psbt, None).unwrap();
    let result = party.bridge_end(signed_psbt);
    assert!(!result.txid.is_empty());
    // the minting wallet learns the bridged supply from its own transition
    assert_eq!(
        party
            .get_asset_metadata(&asset.asset_id)
            .known_circulating_supply,
        AMOUNT
    );

    // the mint pays our own blinded invoice, so like any receive it reaches the balance only
    // once refresh has fetched and validated the consignment; the receive carries no asset
    // until then, so an asset-filtered refresh would skip it
    party.wait_for_refresh(None);

    // before mining the supply is only pending
    assert_eq!(
        party.get_asset_balance(&asset.asset_id),
        Balance {
            settled: 0,
            future: AMOUNT,
            spendable: 0,
        }
    );

    mine(false);
    assert!(party.refresh_asset(&asset.asset_id));

    assert_eq!(
        party.get_asset_balance(&asset.asset_id),
        Balance {
            settled: AMOUNT,
            future: AMOUNT,
            spendable: AMOUNT,
        }
    );

    // and the receiving side reads the same supply out of the consignment
    assert_eq!(
        party
            .get_asset_metadata(&asset.asset_id)
            .known_circulating_supply,
        AMOUNT
    );

    // the mint spent one bridge right and rolled a fresh one forward, so the wallet can mint again
    let rights = party
        .list_unspents(false)
        .into_iter()
        .flat_map(|u| u.rgb_allocations)
        .filter(|a| matches!(a.assignment, Assignment::BridgeRight))
        .count();
    assert_eq!(rights, 1);
}

/// A mint lane received from the issuer mints like one from genesis: the issuer sends a bridge
/// right, the receiving wallet mints against a real EVM lock, and the right rolls forward on it.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn mints_with_a_received_right() {
    initialize();

    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge_contract = deploy_bridge(&eth_contract.address);

    let mut issuer = get_funded_party!();
    let mut minter = get_funded_party!();

    let asset = issuer.issue_asset_bfa(1, bridge_contract.address.clone(), None);

    // the issuer hands its only lane to the minter
    let receive_data = minter.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::BridgeRight,
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let txid = issuer.send_retry(&recipient_map);
    assert!(!txid.is_empty());
    minter.wait_for_refresh(None);
    issuer.wait_for_refresh(None);
    mine(false);
    minter.wait_for_refresh(None);
    issuer.wait_for_refresh(None);

    // mint to the minter's own blinded invoice with the received right
    let receive_data = minter.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };
    let begin = minter.bridge_begin(&asset.asset_id, recipient);
    erc20_approve(&eth_contract.address, &bridge_contract.address, AMOUNT);
    bridge_funds_in(&bridge_contract.address, AMOUNT, &begin.details.opid);
    let signed_psbt = minter.wallet.sign_psbt(begin.psbt, None).unwrap();
    let result = minter.bridge_end(signed_psbt);
    assert!(!result.txid.is_empty());

    minter.wait_for_refresh(None);
    mine(false);
    assert!(minter.refresh_asset(&asset.asset_id));
    assert_eq!(
        minter.get_asset_balance(&asset.asset_id),
        Balance {
            settled: AMOUNT,
            future: AMOUNT,
            spendable: AMOUNT,
        }
    );

    // the lane rolled forward on the minter; the issuer has none left
    let rights = |party: &mut SinglesigParty| {
        party
            .list_unspents(false)
            .into_iter()
            .flat_map(|u| u.rgb_allocations)
            .filter(|a| matches!(a.assignment, Assignment::BridgeRight))
            .count()
    };
    assert_eq!(rights(&mut minter), 1);
    assert_eq!(rights(&mut issuer), 0);
}

/// Without a matching lock the mint must not validate: this is the property the whole schema
/// exists for, and it is checked by RGB consensus rather than by us.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn without_evm_lock_fails() {
    initialize();

    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge_contract = deploy_bridge(&eth_contract.address);

    let mut party = get_funded_party!();
    let asset = party.issue_asset_bfa(1, bridge_contract.address.clone(), None);

    party.create_utxos_default();
    let receive_data = party.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };

    // deliberately skip the fundsIn call
    let begin = party.bridge_begin(&asset.asset_id, recipient);
    let signed_psbt = party.wallet.sign_psbt(begin.psbt, None).unwrap();
    party.bridge_end(signed_psbt);

    mine(false);

    // the recipient refuses the consignment, so nothing settles
    assert!(party.refresh_all());
    assert!(
        party.check_test_transfer_status_incoming(
            &receive_data.recipient_id,
            TransferStatus::Failed
        )
    );
    assert_eq!(
        party.get_asset_balance(&asset.asset_id).settled,
        0,
        "a mint with no matching FundsIn event must not settle"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn wrong_schema_fails() {
    initialize();

    let mut party = get_funded_party!();
    let asset = party.issue_asset_nia(None);

    let receive_data = party.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };

    let result = party.bridge_begin_result(&asset.asset_id, recipient);
    assert!(matches!(
        result,
        Err(Error::UnsupportedBridge {
            asset_schema: AssetSchema::Nia
        })
    ));
}

/// A BFA genesis mints no supply, so its bridge rights sit alone on their UTXOs.
/// Every decision point that enumerates the other assignment variants has to know
/// about them, or the mint fails against a wallet that holds exactly what it needs.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn selects_a_lone_bridge_right() {
    initialize();

    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge_contract = deploy_bridge(&eth_contract.address);

    let mut party = get_funded_party!();
    let asset = party.issue_asset_bfa(1, bridge_contract.address.clone(), None);
    assert_eq!(asset.initial_supply, 0);

    party.create_utxos_default();
    let receive_data = party.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };

    // No EVM lock and no mining: this asserts only that the transition can be
    // built from a wallet whose sole bridge assignment is the right itself.
    let result = party.bridge_begin_result(&asset.asset_id, recipient);
    assert!(
        !matches!(result, Err(Error::InsufficientAssignments { .. })),
        "the wallet holds the one right the mint needs, but selection did not find it"
    );
    assert_eq!(result.unwrap().details.opid.len(), 64);
}

/// The multisig path reads the OpId back out of the fascia file, the singlesig path gets it
/// from the transition it just built. The Go bridge trusts them to be the same value.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fascia_opid_matches_begin_result() {
    initialize();

    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge_contract = deploy_bridge(&eth_contract.address);

    let mut party = get_funded_party!();
    let asset = party.issue_asset_bfa(1, bridge_contract.address.clone(), None);

    party.create_utxos_default();
    let receive_data = party.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };

    let begin = party.bridge_begin(&asset.asset_id, recipient);
    let from_fascia = crate::wallet::multisig::bridge_opid_from_fascia_path(Path::new(
        &begin.details.fascia_path,
    ))
    .unwrap();
    assert_eq!(from_fascia, begin.details.opid);
}

/// The mint end to end, over a blinded and a witness invoice: begin posts the consignment, the
/// user's refresh validates it against the lock the user is about to make, the user locks what
/// their wallet read from it, and only then is the mint broadcast. The user's ordinary refresh
/// settles it.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn mint_checked_by_the_user_before_the_evm_lock() {
    initialize();

    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge_contract = deploy_bridge(&eth_contract.address);

    // one bridge right per mint
    let mut bridge = get_funded_party!();
    let asset = bridge.issue_asset_bfa(2, bridge_contract.address.clone(), None);
    bridge.create_utxos_default();

    let mut user = get_funded_party!();
    user.create_utxos_default();
    let invoices = [
        (user.blind_receive(), None),
        (
            user.witness_receive(),
            Some(WitnessData {
                amount_sat: 1000,
                blinding: None,
            }),
        ),
    ];

    for (i, (receive_data, witness_data)) in invoices.into_iter().enumerate() {
        // nothing has been fetched for this invoice yet
        assert_eq!(
            user.wallet
                .get_received_mint(receive_data.recipient_id.clone())
                .unwrap(),
            None
        );

        let begin = bridge.bridge_begin(
            &asset.asset_id,
            Recipient {
                assignment: Assignment::Fungible(AMOUNT),
                recipient_id: receive_data.recipient_id.clone(),
                witness_data,
                transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
            },
        );

        // the refresh checks the mint without progressing the transfer
        assert!(!user.refresh_all());
        assert!(user.check_test_transfer_status_recipient(
            &receive_data.recipient_id,
            TransferStatus::WaitingCounterparty,
        ));
        // what the user locks on the EVM side comes from the checked consignment itself
        let mint = user
            .wallet
            .get_received_mint(receive_data.recipient_id.clone())
            .unwrap()
            .unwrap();
        assert_eq!(
            mint,
            ReceivedMint {
                opid: begin.details.opid.clone(),
                amount: AMOUNT,
                contract_address: bridge_contract.address.clone(),
            }
        );
        // a later refresh changes nothing
        assert!(!user.refresh_all());

        erc20_approve(&eth_contract.address, &mint.contract_address, mint.amount);
        bridge_funds_in(&mint.contract_address, mint.amount, &mint.opid);
        let signed_psbt = bridge.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
        // the consignment is already out: this must not post it again
        bridge.bridge_end(signed_psbt);

        user.wait_for_refresh(None);
        mine(false);
        assert!(user.refresh_asset(&asset.asset_id));
        bridge.wait_for_refresh(Some(&asset.asset_id));
        let minted = AMOUNT * (i as u64 + 1);
        assert_eq!(
            user.get_asset_balance(&asset.asset_id),
            Balance {
                settled: minted,
                future: minted,
                spendable: minted,
            }
        );
    }
}

/// Mints that do not match the invoice: one for a different asset, one for a different amount.
/// The user's refresh refuses them and the transfers fail, so the user has nothing to lock.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn mint_not_matching_the_invoice_is_refused() {
    initialize();

    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge_contract = deploy_bridge(&eth_contract.address);

    let mut bridge = get_funded_party!();
    let asset = bridge.issue_asset_bfa(2, bridge_contract.address.clone(), None);
    bridge.create_utxos_default();

    let mut user = get_funded_party!();
    user.create_utxos_default();
    let other_asset = user.issue_asset_nia(None);
    let invoices = [
        user.blind_receive_asset_expiry(Some(other_asset.asset_id), None),
        user.wallet
            .blind_receive(
                None,
                Assignment::Fungible(AMOUNT + 1),
                default_rcv_expiration(),
                TRANSPORT_ENDPOINTS.clone(),
                MIN_CONFIRMATIONS,
            )
            .unwrap(),
    ];

    for receive_data in invoices {
        bridge.bridge_begin(
            &asset.asset_id,
            Recipient {
                assignment: Assignment::Fungible(AMOUNT),
                recipient_id: receive_data.recipient_id.clone(),
                witness_data: None,
                transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
            },
        );
        assert!(user.refresh_all());
        assert!(user.check_test_transfer_status_recipient(
            &receive_data.recipient_id,
            TransferStatus::Failed
        ));
    }
}

/// A bridge that posts, under the user's invoice, a mint paying somebody else: the user's refresh
/// refuses it and the EVM lock never happens.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn mint_to_another_recipient_is_refused() {
    initialize();

    let eth_contract = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge_contract = deploy_bridge(&eth_contract.address);

    let mut bridge = get_funded_party!();
    let asset = bridge.issue_asset_bfa(1, bridge_contract.address.clone(), None);

    let mut user = get_funded_party!();
    user.create_utxos_default();
    let user_receive = user.blind_receive();
    let mut attacker = get_funded_party!();
    attacker.create_utxos_default();
    let attacker_receive = attacker.blind_receive();

    // the mint pays the attacker's invoice...
    let begin = bridge.bridge_begin(
        &asset.asset_id,
        Recipient {
            assignment: Assignment::Fungible(AMOUNT),
            recipient_id: attacker_receive.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        },
    );
    // ...but its consignment is presented to the user as its own
    let txid = Psbt::from_str(&begin.psbt)
        .unwrap()
        .unsigned_tx
        .compute_txid()
        .to_string();
    let user_proxy_rid = Invoice::new(user_receive.invoice.clone())
        .unwrap()
        .invoice_data()
        .proxy_recipient_id;
    bridge
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            user_proxy_rid,
            bridge
                .wallet
                .get_send_consignment_path(&asset.asset_id, &txid),
            txid,
            None,
        )
        .unwrap();

    assert!(user.refresh_all());
    assert!(
        user.check_test_transfer_status_recipient(
            &user_receive.recipient_id,
            TransferStatus::Failed
        )
    );
}
