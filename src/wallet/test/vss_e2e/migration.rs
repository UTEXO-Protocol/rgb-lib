use super::*;

use crate::wallet::test::utils::vss::{
    VssBackupDeleteGuard, generate_signing_key_and_store_id, tokio_runtime, vss_server_url,
};

use crate::wallet::vss::{VssBackupClient, VssBackupConfig, restore_from_vss};

// Block 5 / Scenario 5.1:
// "Other machine" migration via VSS restore: restored wallet must be operational.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
#[ignore = "Heavy E2E (issue/send/restore/issue/send); run manually with `cargo test --features vss -- --ignored --nocapture`."]
fn scenario_5_1_other_machine_restore_is_operational() {
    initialize();

    let rt = tokio_runtime();

    // --- "Machine A" ---
    let (mut wallet_a, online_a) = get_funded_wallet!();

    // Create some state: issue an asset and send part of it.
    let issued_supply = 100u64;
    let asset1 = wallet_a
        .issue_asset_nia("QA".into(), "QA asset".into(), 0, vec![issued_supply])
        .expect("issue_asset_nia");
    let asset1_id = asset1.asset_id.clone();

    let (mut wallet_recv, online_recv) = get_empty_wallet!();
    let send_amount1 = 10u64;
    let receive = wallet_recv
        .witness_receive(
            None,
            Assignment::Fungible(send_amount1),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive");
    let recipient_map = HashMap::from([(
        asset1_id.clone(),
        vec![Recipient {
            recipient_id: receive.recipient_id,
            witness_data: Some(WitnessData {
                amount_sat: 2_000,
                blinding: None,
            }),
            assignment: Assignment::Fungible(send_amount1),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let _ = wallet_a
        .send(
            online_a.clone(),
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            false,
        )
        .expect("send");
    mine_blocks(false, 2, false);

    let expected_settled_a = issued_supply - send_amount1;
    let ok = wait_for_function(
        || {
            let _ = wallet_recv.refresh(online_recv.clone(), None, vec![], false);
            let _ = wallet_a.refresh(online_a.clone(), Some(asset1_id.clone()), vec![], false);
            let bal = wallet_a.get_asset_balance(asset1_id.clone()).unwrap();
            bal.settled == expected_settled_a
        },
        120,
        500,
    );
    assert!(ok, "timeout waiting for asset1 settle on machine A");

    // Configure VSS and upload backup.
    let vss_url = vss_server_url();
    let (signing_key, store_id) = generate_signing_key_and_store_id("qa_other_machine");
    let config = VssBackupConfig::new(vss_url, store_id, signing_key);
    let mut cleanup = VssBackupDeleteGuard::new(config.clone());
    let client = VssBackupClient::new(config.clone()).expect("VssBackupClient new");
    let version = rt
        .block_on(wallet_a.vss_backup(&client))
        .expect("vss_backup");
    assert!(version >= 0, "unexpected version {version}");

    // --- "Machine B" (clean dir) ---
    let restore_tmp = tempfile::tempdir().expect("tempdir");
    let restore_root = restore_tmp.path().to_str().unwrap();
    let _ = rt
        .block_on(restore_from_vss(config.clone(), restore_root))
        .expect("restore_from_vss");

    let mut restored_data = wallet_a.get_wallet_data();
    restored_data.data_dir = restore_root.to_string();
    let mut wallet_b = Wallet::new(restored_data).expect("Wallet::new restored");
    assert!(
        !wallet_b.backup_info().expect("backup_info"),
        "backup_info should be false immediately after restore"
    );

    let online_b = wallet_b
        .go_online(true, ELECTRUM_URL.to_string())
        .expect("go_online");
    let _ = wallet_b.refresh(online_b.clone(), Some(asset1_id.clone()), vec![], false);
    let bal1_b = wallet_b
        .get_asset_balance(asset1_id.clone())
        .expect("balance");
    assert_eq!(
        bal1_b.settled, expected_settled_a,
        "Restored wallet asset1 settled balance mismatch"
    );

    // Prove restored wallet is operational: issue a new asset and send it.
    // Be generous with allocations: post-restore state may already have some slots consumed.
    match wallet_b.create_utxos(
        online_b.clone(),
        true,
        Some(5),
        Some(20_000),
        FEE_RATE,
        false,
    ) {
        Ok(_) | Err(Error::AllocationsAlreadyAvailable) => {}
        Err(e) => panic!("create_utxos restored failed: {e:?}"),
    }

    let issued2 = 50u64;
    let asset2 = wallet_b
        .issue_asset_nia("QA2".into(), "QA asset 2".into(), 0, vec![issued2])
        .expect("issue_asset_nia asset2");
    let asset2_id = asset2.asset_id.clone();

    let (mut wallet_b_recv, online_b_recv) = get_empty_wallet!();
    let send_amount2 = 5u64;
    let receive2 = wallet_b_recv
        .witness_receive(
            None,
            Assignment::Fungible(send_amount2),
            None,
            TRANSPORT_ENDPOINTS.clone(),
            MIN_CONFIRMATIONS,
        )
        .expect("witness_receive recv2");
    let recipient_map2 = HashMap::from([(
        asset2_id.clone(),
        vec![Recipient {
            recipient_id: receive2.recipient_id,
            witness_data: Some(WitnessData {
                amount_sat: 2_000,
                blinding: None,
            }),
            assignment: Assignment::Fungible(send_amount2),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let _ = wallet_b
        .send(
            online_b.clone(),
            recipient_map2,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            false,
        )
        .expect("send asset2");
    mine_blocks(false, 2, false);

    let expected_asset2_settled = issued2 - send_amount2;
    let ok2 = wait_for_function(
        || {
            let _ = wallet_b_recv.refresh(online_b_recv.clone(), None, vec![], false);
            let _ = wallet_b.refresh(online_b.clone(), Some(asset2_id.clone()), vec![], false);
            let bal2 = wallet_b.get_asset_balance(asset2_id.clone()).unwrap();
            bal2.settled == expected_asset2_settled
        },
        120,
        500,
    );
    assert!(ok2, "timeout waiting for asset2 settle after restore");

    rt.block_on(client.delete_backup()).expect("delete_backup");
    cleanup.disarm();
}
