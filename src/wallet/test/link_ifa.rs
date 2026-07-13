use super::*;

#[cfg(feature = "electrum")]
fn issue_link_ifa_assets(party: &mut SinglesigParty) -> (AssetIFA, AssetIFA) {
    let parent = party
        .wallet
        .issue_asset_ifa(
            TICKER.to_string(),
            NAME.to_string(),
            PRECISION,
            vec![AMOUNT],
            vec![AMOUNT],
            None,
            Some(IfaIssuanceType::LinkRightOnly),
        )
        .expect("parent issuance should succeed");
    party.create_utxos_default();
    let child = party
        .wallet
        .issue_asset_ifa(
            TICKER.to_string(),
            NAME.to_string(),
            PRECISION,
            vec![AMOUNT],
            vec![AMOUNT],
            None,
            Some(IfaIssuanceType::LinkedFromParent {
                contract_id: parent.asset_id.clone(),
                request_link_right: false,
            }),
        )
        .expect("child issuance should succeed");
    (parent, child)
}

#[cfg(feature = "electrum")]
fn assert_link_ifa_invalid_assignment(
    party: &mut SinglesigParty,
    parent_asset_id: &str,
    child_asset_id: &str,
    link_right_outpoint: Outpoint,
) {
    let online = party.online;
    let result = party.wallet.link_ifa(
        online,
        parent_asset_id.to_owned(),
        child_asset_id.to_owned(),
        link_right_outpoint,
        FEE_RATE,
        MIN_CONFIRMATIONS,
    );
    assert!(matches!(result, Err(Error::InvalidAssignment)));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let mut party = get_funded_party!();
    let (parent, child) = issue_link_ifa_assets(&mut party);

    let result = party
        .wallet
        .link_ifa(
            party.online,
            parent.asset_id.clone(),
            child.asset_id.clone(),
            parent
                .link_right_outpoint
                .clone()
                .expect("issuance must return the parent link-right outpoint"),
            FEE_RATE,
            MIN_CONFIRMATIONS,
        )
        .expect("link should succeed");

    assert!(!result.txid.is_empty());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn rejects_fake_and_wrong_link_right_outpoints() {
    initialize();

    let mut party = get_funded_party!();
    let (parent, child) = issue_link_ifa_assets(&mut party);
    let parent_asset_id = parent.asset_id.clone();
    let child_asset_id = child.asset_id.clone();

    let wrong_outpoint = party
        .list_unspents(false)
        .into_iter()
        .find(|u| {
            u.rgb_allocations.iter().any(|a| {
                a.asset_id.as_deref() == Some(parent_asset_id.as_str())
                    && a.assignment == Assignment::Fungible(AMOUNT)
            })
        })
        .expect("parent fungible outpoint should exist")
        .utxo
        .outpoint;

    let fake_outpoint = Outpoint {
        txid: FAKE_TXID.to_string(),
        vout: 0,
    };

    assert_link_ifa_invalid_assignment(
        &mut party,
        &parent_asset_id,
        &child_asset_id,
        fake_outpoint,
    );
    assert_link_ifa_invalid_assignment(
        &mut party,
        &parent_asset_id,
        &child_asset_id,
        wrong_outpoint,
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn rejects_child_not_declaring_parent() {
    initialize();

    let mut party = get_funded_party!();
    let (parent, _child) = issue_link_ifa_assets(&mut party);

    party.create_utxos_default();
    let unlinked_child = party.issue_asset_ifa(Some(&[AMOUNT]), Some(&[AMOUNT]), None);

    let result = party.wallet.link_ifa(
        party.online,
        parent.asset_id.clone(),
        unlinked_child.asset_id.clone(),
        parent
            .link_right_outpoint
            .clone()
            .expect("issuance must return the parent link-right outpoint"),
        FEE_RATE,
        MIN_CONFIRMATIONS,
    );
    assert!(matches!(result, Err(Error::InvalidContractLink { .. })));

    let unspents = party.list_unspents(false);
    assert!(unspents.iter().any(|u| {
        u.utxo.outpoint == *parent.link_right_outpoint.as_ref().unwrap()
            && u.rgb_allocations.iter().any(|a| {
                a.asset_id.as_deref() == Some(parent.asset_id.as_str())
                    && a.assignment == Assignment::LinkRight
            })
    }));
}
