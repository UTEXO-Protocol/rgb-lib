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

    // lock the ERC-20 under that OpId, then complete the mint
    erc20_approve(&eth_contract.address, &bridge_contract.address, AMOUNT);
    bridge_funds_in(&bridge_contract.address, AMOUNT, &begin.details.opid);

    let signed_psbt = party.wallet.sign_psbt(begin.psbt, None).unwrap();
    let result = party.bridge_end(signed_psbt);
    assert!(!result.txid.is_empty());

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

    // the mint spent one bridge right and rolled a fresh one forward, so the wallet can mint again
    let rights = party
        .list_unspents(false)
        .into_iter()
        .flat_map(|u| u.rgb_allocations)
        .filter(|a| matches!(a.assignment, Assignment::BridgeRight))
        .count();
    assert_eq!(rights, 1);
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
    party.refresh_asset(&asset.asset_id);
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
