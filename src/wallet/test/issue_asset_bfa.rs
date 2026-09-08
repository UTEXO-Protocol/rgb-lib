use super::*;

/// A syntactically valid EVM address for tests that never reach the chain.
const FAKE_ETH_ADDRESS: &str = "0x0000000000000000000000000000000000000001";

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let mut party = get_funded_party!();

    let bridge_rights = 3;
    let asset = party.issue_asset_bfa(bridge_rights, FAKE_ETH_ADDRESS.to_string(), None);

    // BFA genesis allocates no supply: it only hands out mint lanes
    assert_eq!(asset.initial_supply, 0);
    assert_eq!(asset.ticker, TICKER);
    assert_eq!(asset.name, NAME);
    assert_eq!(asset.precision, PRECISION);
    assert_eq!(
        asset.balance,
        Balance {
            settled: 0,
            future: 0,
            spendable: 0,
        }
    );

    let transfers = party.list_transfers(Some(&asset.asset_id));
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers.first().unwrap().kind, TransferKind::Issuance);

    // one bridge right per requested lane, each on its own UTXO
    let rights: Vec<_> = party
        .list_unspents(false)
        .into_iter()
        .flat_map(|u| u.rgb_allocations)
        .filter(|a| matches!(a.assignment, Assignment::BridgeRight))
        .collect();
    assert_eq!(rights.len(), bridge_rights as usize);

    // the asset is listed under its own schema, not among the IFAs
    let assets = party.list_assets(&[AssetSchema::Bfa]);
    assert_eq!(assets.bfa.unwrap().len(), 1);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn no_bridge_rights_fails() {
    initialize();

    let mut party = get_funded_party!();

    // Without a mint lane the asset could never mint anything, so refuse at issuance
    // rather than leaving a contract nobody can use.
    let result = party.issue_asset_bfa_result(0, FAKE_ETH_ADDRESS.to_string(), None);
    assert!(matches!(result, Err(Error::NoBridgeRights)));
}
