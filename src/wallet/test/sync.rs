use super::*;

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fail() {
    initialize();

    let sync_options = SyncOptions {
        keychain: SyncKeychain::Colored,
        strategy: SyncStrategy::FastSync,
    };

    // wallets
    let mut party = get_funded_party!();

    // sync input params
    // - check online is correct
    let wrong_online = Online { id: 1 };
    let good_online = party.online;
    party.online = wrong_online;
    let result = party.sync_result(sync_options);
    party.online = good_online;
    assert!(matches!(result, Err(Error::CannotChangeOnline)));
}

/// Sync reconciles rgb-lib's Txo table downward: a row that rgb-lib holds as
/// `exists=true && spent=false && pending_witness=false` but whose outpoint is
/// not in BDK's `list_unspent` after sync gets marked spent.
///
/// Simulates the divergence reported in production where an out-of-band
/// event (snapshot restore, manual edit, second process) left rgb-lib's DB
/// claiming a UTXO that BDK no longer indexes.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn sync_marks_orphan_txo_spent() {
    initialize();

    let mut wallet = get_test_wallet(false, None);
    let online = wallet.go_online(test_go_online_options(None)).unwrap();

    // Insert an orphan Txo row: rgb-lib's DB claims this outpoint is on-chain
    // and unspent, but BDK has no record of it. This is shape-equivalent to a
    // post-restore stale row.
    let orphan_outpoint = Outpoint {
        txid: FAKE_TXID.to_string(),
        vout: 0,
    };
    let orphan = DbTxoActMod {
        idx: ActiveValue::NotSet,
        txid: ActiveValue::Set(orphan_outpoint.txid.clone()),
        vout: ActiveValue::Set(orphan_outpoint.vout),
        btc_amount: ActiveValue::Set(s!("2000")),
        spent: ActiveValue::Set(false),
        exists: ActiveValue::Set(true),
        pending_witness: ActiveValue::Set(false),
    };
    let txn = wallet.database().begin_transaction().unwrap();
    txn.set_txo(orphan).unwrap();
    txn.commit().unwrap();

    // Sanity: row is present, unspent
    let txn = wallet.database().begin_transaction().unwrap();
    let before = txn.get_txo(&orphan_outpoint).unwrap().expect("orphan row");
    txn.commit().unwrap();
    assert!(!before.spent);
    assert!(before.exists);

    // Sync the colored keychain. The reconcile pass should detect the
    // disagreement and mark the orphan row spent.
    wallet
        .sync(
            online,
            SyncOptions {
                keychain: SyncKeychain::Colored,
                strategy: SyncStrategy::FastSync,
            },
        )
        .unwrap();

    let txn = wallet.database().begin_transaction().unwrap();
    let after = txn.get_txo(&orphan_outpoint).unwrap().expect("orphan row");
    txn.commit().unwrap();
    assert!(
        after.spent,
        "sync should mark Txo spent when BDK no longer holds it as unspent"
    );
}

/// `pending_witness` rows must be skipped by the reconcile pass: they correspond
/// to incoming witness invoices waiting for the sender's tx to land. BDK does
/// not yet hold them as unspent (the tx isn't on-chain yet from the receiver's
/// perspective), and marking them spent would corrupt the receive flow.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn sync_skips_pending_witness_txos() {
    initialize();

    let mut wallet = get_test_wallet(false, None);
    let online = wallet.go_online(test_go_online_options(None)).unwrap();

    let pending_outpoint = Outpoint {
        txid: FAKE_TXID.to_string(),
        vout: 1,
    };
    let pending = DbTxoActMod {
        idx: ActiveValue::NotSet,
        txid: ActiveValue::Set(pending_outpoint.txid.clone()),
        vout: ActiveValue::Set(pending_outpoint.vout),
        btc_amount: ActiveValue::Set(s!("2000")),
        spent: ActiveValue::Set(false),
        exists: ActiveValue::Set(true),
        pending_witness: ActiveValue::Set(true),
    };
    let txn = wallet.database().begin_transaction().unwrap();
    txn.set_txo(pending).unwrap();
    txn.commit().unwrap();

    wallet
        .sync(
            online,
            SyncOptions {
                keychain: SyncKeychain::Colored,
                strategy: SyncStrategy::FastSync,
            },
        )
        .unwrap();

    let txn = wallet.database().begin_transaction().unwrap();
    let after = txn
        .get_txo(&pending_outpoint)
        .unwrap()
        .expect("pending row");
    txn.commit().unwrap();
    assert!(
        !after.spent,
        "pending_witness rows must not be marked spent by the reconcile pass"
    );
    assert!(
        after.pending_witness,
        "pending_witness flag should be preserved"
    );
}

/// `exists=false` rows represent UTXOs the wallet has issued (e.g. change of an
/// unconfirmed broadcast) but BDK has not yet observed on-chain. The reconcile
/// pass must skip these — they are not "missing", they are "not yet visible".
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn sync_skips_unobserved_txos() {
    initialize();

    let mut wallet = get_test_wallet(false, None);
    let online = wallet.go_online(test_go_online_options(None)).unwrap();

    let unobserved_outpoint = Outpoint {
        txid: FAKE_TXID.to_string(),
        vout: 2,
    };
    // exists=false placeholder
    let unobserved = DbTxoActMod {
        idx: ActiveValue::NotSet,
        txid: ActiveValue::Set(unobserved_outpoint.txid.clone()),
        vout: ActiveValue::Set(unobserved_outpoint.vout),
        btc_amount: ActiveValue::Set(s!("2000")),
        spent: ActiveValue::Set(false),
        exists: ActiveValue::Set(false),
        pending_witness: ActiveValue::Set(false),
    };
    let txn = wallet.database().begin_transaction().unwrap();
    txn.set_txo(unobserved).unwrap();
    txn.commit().unwrap();

    wallet
        .sync(
            online,
            SyncOptions {
                keychain: SyncKeychain::Colored,
                strategy: SyncStrategy::FastSync,
            },
        )
        .unwrap();

    let txn = wallet.database().begin_transaction().unwrap();
    let after = txn
        .get_txo(&unobserved_outpoint)
        .unwrap()
        .expect("unobserved row");
    txn.commit().unwrap();
    assert!(
        !after.spent,
        "exists=false rows must not be marked spent by the reconcile pass"
    );
}

/// End-to-end reproduction of the production divergence scenario.
///
/// Performs a real RGB issuance + send (so the consumed UTXO is observed by
/// both BDK and rgb-lib), then manually flips the input row's `spent` flag
/// back to false — the shape of the `apply-new-ifa-asset.sh` snapshot-restore
/// described in the bug report. The next `sync` call must heal the row.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn sync_reconciles_after_simulated_snapshot_restore() {
    initialize();

    let amount: u64 = 66;

    // sender + receiver
    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    // issue, then send
    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    party.send(recipient_map, FEE_RATE, None);

    // mine + refresh until settled, so BDK and rgb-lib agree on the spent set
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));
    mine(false);
    rcv_party.wait_for_refresh(None);
    party.wait_for_refresh(Some(&asset.asset_id));

    // pick an input that was actually consumed by the send
    let spent_input = party
        .db_txos()
        .into_iter()
        .find(|t| t.spent && t.exists && !t.pending_witness)
        .expect("send should have produced at least one spent input");

    // simulate the snapshot-restore: reset spent=false in rgb-lib's DB while
    // BDK continues to know the UTXO is gone from list_unspent
    {
        let txn = party.wlt().database().begin_transaction().unwrap();
        let mut active: DbTxoActMod = spent_input.clone().into();
        active.spent = ActiveValue::Set(false);
        txn.update_txo(active).unwrap();
        txn.commit().unwrap();
    }
    let mid = party.db_txo(&spent_input.outpoint()).expect("row exists");
    assert!(
        !mid.spent,
        "precondition: rgb-lib's DB now lies about this UTXO being unspent"
    );

    // sync — reconcile pass should heal the row
    party.sync(SyncOptions {
        keychain: SyncKeychain::Colored,
        strategy: SyncStrategy::FastSync,
    });

    let healed = party
        .db_txo(&spent_input.outpoint())
        .expect("row still exists");
    assert!(
        healed.spent,
        "sync_wallet should re-mark the diverged Txo spent (production case)"
    );
}
