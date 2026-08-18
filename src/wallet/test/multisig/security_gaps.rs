use super::*;
use utils::*;

/// Multisig PSBT validation gaps (no broadcast of the inspected PSBT).
///
/// Documents that `inspect_psbt` and `respond_to_operation` accept PSBTs carrying
/// one valid cosigner signature plus unrelated `tap_script_sigs`, while BDK
/// `finalize_psbt` rejects them. Update assertions when cosigner signature policy
/// is enforced.
#[cfg(feature = "electrum")]
#[test]
#[serial]
fn foreign_cosigner_tap_script_sigs_not_validated() {
    initialize();
    op_counter_reset();

    let bitcoin_network = BitcoinNetwork::Regtest;
    let threshold_colored = 2;
    let threshold_vanilla = 2;
    let random_str: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();

    let wlt_1_keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let wlt_2_keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let wlt_3_keys = generate_keys(bitcoin_network, WitnessVersion::Taproot);
    let cosigners = vec![
        Cosigner::from_keys(&wlt_1_keys, None),
        Cosigner::from_keys(&wlt_2_keys, None),
        Cosigner::from_keys(&wlt_3_keys, None),
    ];
    let cosigner_xpubs: Vec<String> = cosigners
        .iter()
        .map(|c| c.account_xpub_colored.clone())
        .collect();

    let root_keypair = KeyPair::new();
    let root_public_key = root_keypair.public();
    let cosigner_tokens: Vec<String> = cosigner_xpubs
        .iter()
        .map(|xpub| create_token(&root_keypair, Role::Cosigner(xpub.clone()), None))
        .collect();

    write_hub_config(
        &cosigner_xpubs,
        threshold_colored,
        threshold_vanilla,
        root_public_key.to_bytes_hex(),
        None,
    );
    restart_multisig_hub();

    let multisig_wlt_keys =
        MultisigKeys::new(cosigners.clone(), threshold_colored, threshold_vanilla);
    let mut wlt_1_multisig = get_test_ms_wallet(&multisig_wlt_keys, format!("{random_str}_1"));
    let wlt_1_multisig_online = ms_go_online(&mut wlt_1_multisig, &cosigner_tokens[0]);
    let mut wlt_2_multisig = get_test_ms_wallet(&multisig_wlt_keys, format!("{random_str}_2"));
    let wlt_2_multisig_online = ms_go_online(&mut wlt_2_multisig, &cosigner_tokens[1]);
    let mut wlt_3_multisig = get_test_ms_wallet(&multisig_wlt_keys, format!("{random_str}_3"));
    let _wlt_3_multisig_online = ms_go_online(&mut wlt_3_multisig, &cosigner_tokens[2]);

    let wlt_1_singlesig = get_test_wallet_with_keys(&wlt_1_keys);
    let wlt_2_singlesig = get_test_wallet_with_keys(&wlt_2_keys);

    let mut wlt_1 = ms_party!(
        &wlt_1_singlesig,
        &mut wlt_1_multisig,
        wlt_1_multisig_online,
        &cosigner_xpubs[0]
    );
    let mut wlt_2 = ms_party!(
        &wlt_2_singlesig,
        &mut wlt_2_multisig,
        wlt_2_multisig_online,
        &cosigner_xpubs[1]
    );

    send_sats_to_address(wlt_1.get_address(), Some(10_000));
    mine(false);

    let op_init = wlt_1.create_utxos_init(false, None, None, FEE_RATE);
    let signed = psbt_signed_by_cosigner(&op_init.psbt, wlt_1.signer);
    let psbt = psbt_with_foreign_tap_script_sigs(&signed, 2);

    // inspect_psbt: should reject foreign cosigner signatures (currently accepts)
    let inspection = wlt_1.multisig.inspect_psbt(psbt.clone()).unwrap();
    assert_eq!(
        inspection.signature_count, 3,
        "inspect_psbt counts valid + foreign tap_script_sigs without validating cosigners"
    );

    // respond_to_operation pre-check: signature_count > 0 only (currently accepts)
    wlt_2.sync(SyncOptions {
        keychain: SyncKeychain::Colored,
        strategy: SyncStrategy::FastSync,
    });
    wlt_2
        .respond_to_operation_res(
            op_init.operation_idx,
            RespondToOperation::Ack(psbt.clone()),
        )
        .unwrap();

    // finalize_psbt: BDK rejects invalid script-path signatures
    let err = wlt_1
        .multisig
        .finalize_psbt(psbt, None)
        .unwrap_err();
    assert_matches!(err, Error::CannotFinalizePsbt);
}
