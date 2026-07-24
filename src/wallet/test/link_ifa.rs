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
fn assert_link_ifa_invalid_link_right_outpoint(
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
    assert!(matches!(result, Err(Error::InvalidRightOutpoint { .. })));
}

#[cfg(feature = "electrum")]
fn assert_link_right_isolated(party: &mut SinglesigParty, asset_id: &str, outpoint: &Outpoint) {
    let link_right_utxo = party
        .list_unspents(false)
        .into_iter()
        .find(|unspent| unspent.utxo.outpoint == *outpoint)
        .expect("link-right UTXO should remain unspent");
    assert_eq!(link_right_utxo.rgb_allocations.len(), 1);
    assert_eq!(
        link_right_utxo.rgb_allocations[0].asset_id.as_deref(),
        Some(asset_id)
    );
    assert_eq!(
        link_right_utxo.rgb_allocations[0].assignment,
        Assignment::LinkRight
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let mut party = get_funded_party!();
    let (parent, child) = issue_link_ifa_assets(&mut party);
    let link_right_outpoint = parent
        .issuance_link_right_outpoint
        .clone()
        .expect("issuance must return the parent link-right outpoint");
    assert_link_right_isolated(&mut party, &parent.asset_id, &link_right_outpoint);

    assert_eq!(parent.linked_from_asset_id, None);
    assert_eq!(parent.linked_to_asset_id, None);
    assert_eq!(child.linked_from_asset_id, Some(parent.asset_id.clone()));
    assert_eq!(child.linked_to_asset_id, None);

    let parent_metadata = party.get_asset_metadata(&parent.asset_id);
    let child_metadata = party.get_asset_metadata(&child.asset_id);
    assert_eq!(parent_metadata.linked_from_asset_id, None);
    assert_eq!(parent_metadata.linked_to_asset_id, None);
    assert_eq!(
        parent_metadata.unspent_link_right_outpoint,
        Some(link_right_outpoint.clone())
    );
    assert_eq!(child_metadata.unspent_link_right_outpoint, None);
    assert_eq!(
        child_metadata.linked_from_asset_id,
        Some(parent.asset_id.clone())
    );
    assert_eq!(child_metadata.linked_to_asset_id, None);

    // Minting and burning must leave the dedicated link-right UTXO untouched
    party.create_utxos_default();
    party.inflate(&parent.asset_id, &[1]);
    mine(false);
    assert!(party.refresh_asset(&parent.asset_id));
    assert_link_right_isolated(&mut party, &parent.asset_id, &link_right_outpoint);

    party.burn(&parent.asset_id, 1);
    mine(false);
    assert!(party.refresh_asset(&parent.asset_id));
    assert_link_right_isolated(&mut party, &parent.asset_id, &link_right_outpoint);

    // Linking contracts should consume the link-right UTXO
    let result = party
        .wallet
        .link_ifa(
            party.online,
            parent.asset_id.clone(),
            child.asset_id.clone(),
            link_right_outpoint.clone(),
            FEE_RATE,
            MIN_CONFIRMATIONS,
        )
        .expect("link should succeed");
    assert!(!result.txid.is_empty());

    {
        let runtime = party.wallet.rgb_runtime().expect("rgb runtime should load");
        let parent_contract_id =
            ContractId::from_str(&parent.asset_id).expect("valid parent contract ID");
        let child_contract_id =
            ContractId::from_str(&child.asset_id).expect("valid child contract ID");
        runtime
            .validate_contracts_link::<InflatableFungibleAsset, InflatableFungibleAsset>(
                parent_contract_id,
                child_contract_id,
            )
            .expect("parent and child contracts should validate as linked");
    }

    let parent_metadata = party.get_asset_metadata(&parent.asset_id);
    let child_metadata = party.get_asset_metadata(&child.asset_id);
    assert_eq!(parent_metadata.linked_from_asset_id, None);
    assert_eq!(
        parent_metadata.linked_to_asset_id,
        Some(child.asset_id.clone())
    );
    assert_eq!(
        child_metadata.linked_from_asset_id,
        Some(parent.asset_id.clone())
    );
    assert_eq!(child_metadata.linked_to_asset_id, None);
    assert_eq!(parent_metadata.unspent_link_right_outpoint, None);

    let ifa_assets = party
        .wallet
        .list_assets(vec![AssetSchema::Ifa])
        .expect("IFA assets should be listed")
        .ifa
        .expect("IFA assets should be present");
    let listed_parent = ifa_assets
        .iter()
        .find(|asset| asset.asset_id == parent.asset_id)
        .expect("parent asset should be listed");
    let listed_child = ifa_assets
        .iter()
        .find(|asset| asset.asset_id == child.asset_id)
        .expect("child asset should be listed");
    assert_eq!(
        listed_parent.linked_to_asset_id,
        Some(child.asset_id.clone())
    );
    assert_eq!(
        listed_child.linked_from_asset_id,
        Some(parent.asset_id.clone())
    );
    assert_eq!(
        listed_parent.issuance_link_right_outpoint,
        Some(link_right_outpoint.clone())
    );

    // Second link should fail
    let duplicate = party.wallet.link_ifa(
        party.online,
        parent.asset_id.clone(),
        child.asset_id.clone(),
        link_right_outpoint,
        FEE_RATE,
        MIN_CONFIRMATIONS,
    );
    assert!(matches!(duplicate, Err(Error::InvalidRightOutpoint { .. })));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn cross_wallet_link_requires_receiving_child_contract() {
    initialize();

    let mut parent_issuer = get_funded_party!();
    let mut child_issuer = get_funded_party!();

    let parent = parent_issuer
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
    let child = child_issuer
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

    let link_right_outpoint = parent
        .issuance_link_right_outpoint
        .clone()
        .expect("parent issuance must create a link-right outpoint");

    let before_receive = parent_issuer.wallet.link_ifa(
        parent_issuer.online,
        parent.asset_id.clone(),
        child.asset_id.clone(),
        link_right_outpoint.clone(),
        FEE_RATE,
        MIN_CONFIRMATIONS,
    );
    assert!(matches!(before_receive, Err(Error::AssetNotFound { .. })));

    let receive_data = parent_issuer.blind_receive();
    let recipient_map = HashMap::from([(
        child.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(AMOUNT),
            recipient_id: receive_data.recipient_id,
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    child_issuer.send_retry(&recipient_map);
    parent_issuer.wait_for_refresh(None);

    assert!(parent_issuer.db_check_asset_exists(&child.asset_id).is_ok());

    let result = parent_issuer.wallet.link_ifa(
        parent_issuer.online,
        parent.asset_id,
        child.asset_id,
        link_right_outpoint,
        FEE_RATE,
        MIN_CONFIRMATIONS,
    );
    assert!(
        result.is_ok(),
        "link should succeed after child receipt: {result:?}"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn issuer_receive_paths_do_not_reuse_link_right_utxo() {
    initialize();

    let mut issuer_wallet = get_funded_party!();
    let (parent_asset, _child_asset) = issue_link_ifa_assets(&mut issuer_wallet);
    let issuer_link_right_outpoint = parent_asset
        .issuance_link_right_outpoint
        .clone()
        .expect("issuer issuance must return the parent link-right outpoint");

    let issuer_blind_receive = issuer_wallet.blind_receive();
    let issuer_blind_receive_transfer =
        issuer_wallet.get_test_transfer_recipient(&issuer_blind_receive.recipient_id);
    let (issuer_blind_receive_data, _) =
        issuer_wallet.get_test_transfer_data(&issuer_blind_receive_transfer);
    assert_ne!(
        issuer_blind_receive_data
            .receive_utxo
            .expect("issuer blind receive should reserve a UTXO"),
        issuer_link_right_outpoint,
    );

    let issuer_witness_receive = issuer_wallet.witness_receive();
    let issuer_witness_receive_transfer =
        issuer_wallet.get_test_transfer_recipient(&issuer_witness_receive.recipient_id);
    let (issuer_witness_receive_data, _) =
        issuer_wallet.get_test_transfer_data(&issuer_witness_receive_transfer);
    assert_ne!(
        issuer_witness_receive_data.receive_utxo,
        Some(issuer_link_right_outpoint.clone()),
    );

    assert_link_right_isolated(
        &mut issuer_wallet,
        &parent_asset.asset_id,
        &issuer_link_right_outpoint,
    );
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

    assert_link_ifa_invalid_link_right_outpoint(
        &mut party,
        &parent_asset_id,
        &child_asset_id,
        fake_outpoint,
    );
    assert_link_ifa_invalid_link_right_outpoint(
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
            .issuance_link_right_outpoint
            .clone()
            .expect("issuance must return the parent link-right outpoint"),
        FEE_RATE,
        MIN_CONFIRMATIONS,
    );
    assert!(matches!(result, Err(Error::InvalidContractLink { .. })));

    let unspents = party.list_unspents(false);
    assert!(unspents.iter().any(|u| {
        u.utxo.outpoint == *parent.issuance_link_right_outpoint.as_ref().unwrap()
            && u.rgb_allocations.iter().any(|a| {
                a.asset_id.as_deref() == Some(parent.asset_id.as_str())
                    && a.assignment == Assignment::LinkRight
            })
    }));
}
