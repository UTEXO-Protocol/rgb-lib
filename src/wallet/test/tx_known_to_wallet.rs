use super::*;

use std::str::FromStr;

use bdk_wallet::bitcoin::Txid;

// `tx_known_to_wallet` underpins the idempotent multisig SendEnd: an operation
// whose transaction is already on-chain must be completed without this party
// re-finalizing the PSBT. The helper reports whether the wallet's BDK graph
// already knows a transaction (after the latest sync).
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn detects_broadcast_tx() {
    initialize();

    let mut party = get_empty_party!();
    let mut rcv = get_empty_party!();
    fund_wallet(party.get_address());
    party.create_utxos_default();
    mine(false);

    // before any send, a random txid is unknown
    let unknown =
        Txid::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    assert!(!party.wallet.tx_known_to_wallet(&unknown));

    // broadcast a tx, mine it and sync the wallet
    let txid_str = party.send_btc(&rcv.get_address(), 1000);
    mine(false);
    party.get_btc_balance_with_sync();

    let txid = Txid::from_str(&txid_str).unwrap();
    assert!(
        party.wallet.tx_known_to_wallet(&txid),
        "a broadcast and mined tx must be known to the wallet"
    );
    assert!(
        !party.wallet.tx_known_to_wallet(&unknown),
        "an unrelated txid must not be known to the wallet"
    );
}
