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
    // holders count a lock only once the EVM chain has finalized it
    evm_finalize();

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

/// Mint `AMOUNT` on `minter`'s lane to a blinded invoice of `holder`, first locking each of
/// `locks`, in order, under the mint's OpId and finalizing them. Returns the holder's recipient
/// ID.
#[cfg(feature = "electrum")]
fn mint_after_locks(
    minter: &mut SinglesigParty,
    holder: &mut SinglesigParty,
    asset_id: &str,
    token: &EthContract,
    bridge: &EthContract,
    locks: &[u64],
) -> String {
    let receive_data = holder.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };
    let begin = minter.bridge_begin(asset_id, recipient);
    for &amount in locks {
        erc20_approve(&token.address, &bridge.address, amount);
        bridge_funds_in(&bridge.address, amount, &begin.details.opid);
    }
    evm_finalize();
    let signed_psbt = minter.wallet.sign_psbt(begin.psbt, None).unwrap();
    assert!(!minter.bridge_end(signed_psbt).txid.is_empty());
    receive_data.recipient_id
}

/// `fundsIn` lets anyone lock any amount under any OpId, and the federation checks only the
/// deposit it is shown, so a depositor can lock a wrong amount under its own mint OpId ahead of
/// the real deposit and still get the mint signed. Holders read every FundsIn log in chain order:
/// the mint must validate for them all the same, and so must the next mint on the lane, which
/// descends from the first through the rolled-forward bridge right.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn an_earlier_wrong_amount_lock_does_not_invalidate_the_lane() {
    initialize();

    let token = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge = deploy_bridge(&token.address);

    let mut minter = get_funded_party!();
    let mut first_holder = get_funded_party!();
    let mut second_holder = get_funded_party!();

    let asset = minter.issue_asset_bfa(1, bridge.address.clone(), None);

    // 1 locked under the mint's OpId first, then the amount the mint commits to
    let first = mint_after_locks(
        &mut minter,
        &mut first_holder,
        &asset.asset_id,
        &token,
        &bridge,
        &[1, AMOUNT],
    );
    first_holder.wait_for_refresh(None);
    mine(false);
    first_holder.refresh_all();
    // settles the mint on the minting side, making the rolled-forward right spendable
    minter.refresh_all();

    // an honestly backed mint on the same lane
    let second = mint_after_locks(
        &mut minter,
        &mut second_holder,
        &asset.asset_id,
        &token,
        &bridge,
        &[AMOUNT],
    );
    second_holder.wait_for_refresh(None);
    mine(false);
    second_holder.refresh_all();

    let settled = |holder: &mut SinglesigParty, recipient_id: &str| {
        holder.check_test_transfer_status_incoming(recipient_id, TransferStatus::Settled)
            && holder.get_asset_balance(&asset.asset_id).settled == AMOUNT
    };
    let first_settled = settled(&mut first_holder, &first);
    let second_settled = settled(&mut second_holder, &second);
    assert!(
        first_settled && second_settled,
        "holders refused backed mints: first settled = {first_settled}, \
         next on the lane settled = {second_settled}"
    );
}

/// Accepting any matching lock must not accept a mint that only wrong-amount locks back.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn only_wrong_amount_locks_fail() {
    initialize();

    let token = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge = deploy_bridge(&token.address);

    let mut minter = get_funded_party!();
    let mut holder = get_funded_party!();

    let asset = minter.issue_asset_bfa(1, bridge.address.clone(), None);

    let recipient_id = mint_after_locks(
        &mut minter,
        &mut holder,
        &asset.asset_id,
        &token,
        &bridge,
        &[1, AMOUNT - 1, AMOUNT + 1],
    );
    holder.wait_for_refresh(None);
    mine(false);
    holder.refresh_all();

    assert!(holder.check_test_transfer_status_incoming(&recipient_id, TransferStatus::Failed));
}

/// A holder counts only finalized locks, yet a mint whose lock is merely not final yet must wait
/// for it rather than be refused for good. Serial: a parallel test finalizing its own locks would
/// finalize this one too.
#[cfg(feature = "electrum")]
#[test]
#[serial]
fn a_lock_not_final_yet_leaves_the_mint_waiting() {
    initialize();

    let token = deploy_test_erc20("Bridged Token", "BRG", 18, 1_000_000);
    let bridge = deploy_bridge(&token.address);

    let mut minter = get_funded_party!();
    let mut holder = get_funded_party!();

    let asset = minter.issue_asset_bfa(1, bridge.address.clone(), None);

    let receive_data = holder.blind_receive();
    let recipient = Recipient {
        assignment: Assignment::Fungible(AMOUNT),
        recipient_id: receive_data.recipient_id.clone(),
        witness_data: None,
        transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
    };
    let begin = minter.bridge_begin(&asset.asset_id, recipient);
    erc20_approve(&token.address, &bridge.address, AMOUNT);
    bridge_funds_in(&bridge.address, AMOUNT, &begin.details.opid);
    let signed_psbt = minter.wallet.sign_psbt(begin.psbt, None).unwrap();
    assert!(!minter.bridge_end(signed_psbt).txid.is_empty());

    // the lock is on chain but not finalized: the transfer stays waiting, with a retryable error
    let refresh = holder.refresh_result(None, &[]).unwrap();
    let failures: Vec<&Error> = refresh
        .values()
        .filter_map(|t| t.failure.as_ref())
        .collect();
    assert!(
        matches!(
            failures.as_slice(),
            [Error::Network { details }] if details.contains("not final yet")
        ),
        "{failures:?}"
    );
    assert!(holder.check_test_transfer_status_incoming(
        &receive_data.recipient_id,
        TransferStatus::WaitingCounterparty
    ));

    evm_finalize();
    holder.wait_for_refresh(None);
    mine(false);
    holder.refresh_all();
    assert!(
        holder.check_test_transfer_status_incoming(
            &receive_data.recipient_id,
            TransferStatus::Settled
        )
    );
    assert_eq!(holder.get_asset_balance(&asset.asset_id).settled, AMOUNT);
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
