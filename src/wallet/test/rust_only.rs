use super::*;

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn success() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // prepare PSBT
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(psbt.proprietary.is_empty());
    let witness_utxo_before = psbt.inputs[0].witness_utxo.clone();
    let tap_internal_key_before = psbt.inputs[0].tap_internal_key;
    assert!(witness_utxo_before.is_some());

    // color PSBT
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    let vout = output.0 as u32;
    output_map.insert(vout, AMOUNT); // sending AMOUNT since color_psbt doesn't support change
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    stamp_output_map_sentinels(&mut psbt);
    let mut psbt_copy = psbt.clone();
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info.clone())
        .unwrap();

    // check PSBT
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(!psbt.proprietary.is_empty());
    assert_eq!(psbt.inputs[0].witness_utxo, witness_utxo_before);
    assert_eq!(psbt.inputs[0].tap_internal_key, tap_internal_key_before);
    // OP_RETURN inserted at front: original output maps must shift by +1 (skip(1) rebuild path).
    assert_output_maps_offset_by(&psbt_copy, &psbt, 1);
    let vout = vout + 1;

    // check fascia
    assert_eq!(fascia.bundles().len(), 1);
    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let im_keys = bundle.input_map.keys();
    assert_eq!(im_keys.len(), 1);
    let mut transitions = bundle.known_transitions.iter().map(|kt| &kt.transition);
    assert_eq!(transitions.len(), 1);
    let transition = transitions.next().unwrap();
    let assignments = &transition.assignments;
    assert_eq!(assignments.len(), 1);
    let (_, fungible) = assignments.iter().next().unwrap();
    let fungible = fungible.as_fungible();
    assert_eq!(fungible.len(), 1);
    let fungible = fungible.first().unwrap();
    let seal = fungible.revealed_seal().unwrap();
    let state = fungible.as_revealed_state();
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), vout);
    assert_eq!(seal.blinding, blinding);
    assert_eq!(state.as_u64(), AMOUNT);

    // check beneficiaries
    assert_eq!(beneficiaries.len(), 1);
    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), vout);
    assert_eq!(seal.blinding, blinding);

    // color PSBT and prepare consume (stash not updated until consume_transfer_fascia)
    let ColorPrepareResult {
        transfers,
        batch_transfer_idx,
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt_copy, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    // check that the two color_psbt* methods produce matching PSBTs (no additional changes)
    assert_eq!(psbt, psbt_copy);

    // save consignment to file
    let txid = psbt_copy.unsigned_tx.compute_txid().to_string();
    let transfers_dir = party_send.wallet.get_transfers_dir().join(&txid);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    assert_eq!(transfers.len(), 1);
    transfers
        .first()
        .unwrap()
        .save_file(&consignment_path)
        .unwrap();

    // accept transfer
    recv_party
        .wallet
        .accept_transfer_consignment(
            recv_party.online,
            consignment_path,
            txid.clone(),
            vout,
            blinding,
        )
        .unwrap();

    broadcast_wallet_psbt(&party_send.wallet, &psbt_copy);
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_unspents_vanilla_success() {
    initialize();

    // wallets
    let mut party = get_empty_party!();

    // no unspents
    let bak_info_before = party.db_backup_info_opt();
    assert!(bak_info_before.is_none());
    let unspent_list = party.list_unspents_vanilla(None);
    let bak_info_after = party.db_backup_info_opt();
    assert!(bak_info_after.is_none());
    assert_eq!(unspent_list.len(), 0);

    let _guard = stop_mining();

    send_to_address(party.get_address());

    // one unspent, no confirmations
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 0);
    let unspent_list = party.list_unspents_vanilla(Some(0));
    assert_eq!(unspent_list.len(), 1);

    drop(_guard);
    mine(false);

    // one unspent, 1 confirmation
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 1);
    let unspent_list = party.list_unspents_vanilla(Some(0));
    assert_eq!(unspent_list.len(), 1);

    party.create_utxos_default();

    // one unspent (change), colored unspents not listed
    mine(false);
    let unspent_list = party.list_unspents_vanilla(None);
    assert_eq!(unspent_list.len(), 1);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_unspents_vanilla_skip_sync() {
    initialize();

    let mut party = get_empty_party!();

    fund_wallet(party.get_address());

    // no unspents if skipping sync
    let unspents = party
        .wallet
        .list_unspents_vanilla(party.online, MIN_CONFIRMATIONS, true)
        .unwrap();
    assert_eq!(unspents.len(), 0);

    // 1 unspent after manually syncing
    party
        .wallet
        .sync(
            party.online,
            SyncOptions {
                keychain: SyncKeychain::Vanilla {
                    lookback: INDEXER_SYNC_LOOKBACK as u32,
                },
                strategy: SyncStrategy::FastSync,
            },
        )
        .unwrap();
    let unspents = party
        .wallet
        .list_unspents_vanilla(party.online, MIN_CONFIRMATIONS, true)
        .unwrap();
    assert_eq!(unspents.len(), 1);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn save_new_asset_success() {
    initialize();
    let asset_amount: u64 = 66;

    // wallets
    let mut party = get_funded_party!();
    let mut rcv_party = get_empty_party!();

    // NIA
    let nia_asset = party.issue_asset_nia(None);
    party.check_save_new_asset(
        &mut rcv_party,
        &nia_asset.asset_id,
        Assignment::Fungible(asset_amount),
    );
    assert!(rcv_party.db_check_asset_exists(&nia_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&nia_asset.asset_id);
    assert_eq!(asset_model.id, nia_asset.asset_id);
    assert_eq!(asset_model.initial_supply, AMOUNT.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert_eq!(asset_model.ticker.unwrap(), TICKER);
    assert_eq!(asset_model.schema, AssetSchema::Nia);

    // CFA
    let cfa_asset = party.issue_asset_cfa(None, None);
    party.check_save_new_asset(
        &mut rcv_party,
        &cfa_asset.asset_id,
        Assignment::Fungible(asset_amount),
    );
    assert!(rcv_party.db_check_asset_exists(&cfa_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&cfa_asset.asset_id);
    assert_eq!(asset_model.id, cfa_asset.asset_id);
    assert_eq!(asset_model.initial_supply, AMOUNT.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert!(asset_model.ticker.is_none());
    assert_eq!(asset_model.schema, AssetSchema::Cfa);

    // UDA
    let image_str = ["tests", "qrcode.png"].join(MAIN_SEPARATOR_STR);
    let uda_asset =
        party.issue_asset_uda(Some(DETAILS), Some(FILE_STR), vec![&image_str, FILE_STR]);
    party.create_utxos(false, None, None, FEE_RATE, None);
    party.check_save_new_asset(&mut rcv_party, &uda_asset.asset_id, Assignment::NonFungible);
    assert!(rcv_party.db_check_asset_exists(&uda_asset.asset_id).is_ok());
    let asset_model = rcv_party.db_asset(&uda_asset.asset_id);
    assert_eq!(asset_model.id, uda_asset.asset_id);
    assert_eq!(asset_model.initial_supply, 1.to_string());
    assert_eq!(asset_model.name, NAME);
    assert_eq!(asset_model.precision, PRECISION);
    assert_eq!(asset_model.ticker.unwrap(), TICKER);
    assert_eq!(asset_model.schema, AssetSchema::Uda);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn import_asset_contract_success() {
    initialize();

    let mut issuer = get_funded_party!();
    let recipient = get_empty_party!();
    let assets = [
        (issuer.issue_asset_nia(None).asset_id, AssetSchema::Nia),
        (
            issuer.issue_asset_cfa(None, None).asset_id,
            AssetSchema::Cfa,
        ),
        (
            issuer.issue_asset_ifa(None, None, None).asset_id,
            AssetSchema::Ifa,
        ),
        (
            issuer.issue_asset_uda(None, None, vec![]).asset_id,
            AssetSchema::Uda,
        ),
    ];

    for (asset_id, asset_schema) in assets {
        let contract = issuer
            .wallet
            .export_asset_contract(asset_id.clone())
            .unwrap();
        let imported = recipient
            .wallet
            .import_asset_contract(contract.clone())
            .unwrap();
        assert_eq!(imported.asset_id, asset_id);
        assert!(!imported.already_imported);
        assert_eq!(imported.metadata.asset_schema, asset_schema);
        assert_eq!(imported.metadata.name, NAME);
        assert_eq!(imported.metadata.precision, PRECISION);
        assert_eq!(
            recipient
                .wallet
                .get_asset_balance(asset_id.clone())
                .unwrap(),
            Balance::default()
        );

        let repeated = recipient.wallet.import_asset_contract(contract).unwrap();
        assert_eq!(repeated.asset_id, asset_id);
        assert!(repeated.already_imported);
        assert_eq!(repeated.metadata, imported.metadata);
    }
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn import_asset_contract_rejects_missing_attachments() {
    initialize();

    let mut issuer = get_funded_party!();
    let recipient = get_empty_party!();
    let asset = issuer.issue_asset_cfa(None, Some(FILE_STR.to_string()));
    let contract = issuer.wallet.export_asset_contract(asset.asset_id).unwrap();

    let result = recipient.wallet.import_asset_contract(contract);
    assert_matches!(result, Err(Error::InvalidAttachments { .. }));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn import_asset_contract_repairs_partial_persistence() {
    initialize();

    let mut issuer = get_funded_party!();
    let stock_only_recipient = get_empty_party!();
    let database_only_recipient = get_empty_party!();
    let asset = issuer.issue_asset_nia(None);
    let contract = issuer
        .wallet
        .export_asset_contract(asset.asset_id.clone())
        .unwrap();
    let validation_config = ValidationConfig {
        chain_net: stock_only_recipient.wallet.chain_net(),
        trusted_typesystem: AssetSchema::Nia.types(),
        ..Default::default()
    };
    let valid_contract = contract
        .clone()
        .validate(&DumbResolver, &validation_config)
        .unwrap();
    let contract_id = valid_contract.contract_id();

    {
        let mut runtime = stock_only_recipient.wallet.rgb_runtime().unwrap();
        runtime
            .import_contract(valid_contract.clone(), &DumbResolver)
            .unwrap();
    }
    assert_matches!(
        stock_only_recipient
            .wallet
            .get_asset_metadata(asset.asset_id.clone()),
        Err(Error::AssetNotFound { .. })
    );
    let repaired = stock_only_recipient
        .wallet
        .import_asset_contract(contract.clone())
        .unwrap();
    assert!(!repaired.already_imported);

    {
        // Read metadata from the issuer's stock so the recipient's stock remains untouched. This
        // deterministically models a database commit that completed before the stock write.
        let runtime = issuer.wallet.rgb_runtime().unwrap();
        let txn = database_only_recipient
            .wallet
            .database()
            .begin_transaction()
            .unwrap();
        database_only_recipient
            .wallet
            .save_new_asset_internal(
                &txn,
                &runtime,
                contract_id,
                AssetSchema::Nia,
                valid_contract,
                None,
            )
            .unwrap();
        txn.commit().unwrap();
    }
    assert!(
        database_only_recipient
            .wallet
            .rgb_runtime()
            .unwrap()
            .export_contract(contract_id)
            .is_err()
    );
    let repaired = database_only_recipient
        .wallet
        .import_asset_contract(contract)
        .unwrap();
    assert!(!repaired.already_imported);
    assert_eq!(repaired.metadata.asset_schema, AssetSchema::Nia);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn import_asset_contract_serializes_concurrent_calls() {
    initialize();

    let mut issuer = get_funded_party!();
    let recipient = get_empty_party!();
    let asset = issuer.issue_asset_nia(None);
    let contract = issuer
        .wallet
        .export_asset_contract(asset.asset_id.clone())
        .unwrap();
    let wallet_data = recipient.wallet.wallet_data().clone();
    let keys = recipient.wallet.get_keys();
    let first_wallet = recipient.wallet;
    let second_wallet = Wallet::new(wallet_data.clone(), keys.clone()).unwrap();
    let first_contract = contract.clone();
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(move || first_wallet.import_asset_contract(first_contract));
        let second = scope.spawn(move || second_wallet.import_asset_contract(contract));
        (
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        )
    });

    assert_eq!(first.asset_id, asset.asset_id);
    assert_eq!(second.asset_id, asset.asset_id);
    assert_ne!(first.already_imported, second.already_imported);
    let wallet = Wallet::new(wallet_data, keys).unwrap();
    assert_eq!(
        wallet.get_asset_balance(asset.asset_id).unwrap(),
        Balance::default()
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_uda() {
    initialize();

    let nonce = 42u64;

    // wallets
    let mut party_send = get_funded_noutxo_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    let mut recv_party = get_empty_party!();
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_uda(None, None, vec![]);

    // create a custom BDK wallet with p2wpkh descriptor to avoid p2tr outputs,
    // so that the OP_RETURN is appended at the end
    let mnemonic = Mnemonic::parse_in(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let xprv = Xpriv::new_master(BdkNetwork::Regtest, &mnemonic.to_seed("")).unwrap();
    let custom_bdk_wallet =
        BdkWallet::create(format!("wpkh({xprv}/0/*)"), format!("wpkh({xprv}/1/*)"))
            .network(BdkNetwork::Regtest)
            .create_wallet_no_persist()
            .unwrap();
    let p2wpkh_addr = custom_bdk_wallet
        .peek_address(KeychainKind::External, 0)
        .address;

    // prepare PSBT: drain all wallet UTXOs to the p2wpkh address (no p2tr outputs, no change)
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .drain_wallet()
        .drain_to(p2wpkh_addr.script_pubkey())
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(psbt.proprietary.is_empty());
    let witness_utxo_before = psbt.inputs[0].witness_utxo.clone();
    let tap_internal_key_before = psbt.inputs[0].tap_internal_key;
    assert!(witness_utxo_before.is_some());

    // color PSBT
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    output_map.insert(0u32, 1u64); // UDA: assign to vout 0, amount 1
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: None,
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: None,
        nonce: Some(nonce),
    };
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info)
        .unwrap();

    // check PSBT: OP_RETURN is appended at the end
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    assert!(!psbt.proprietary.is_empty());
    assert!(
        psbt.unsigned_tx
            .output
            .last()
            .unwrap()
            .script_pubkey
            .is_op_return()
    );
    assert_eq!(psbt.inputs[0].witness_utxo, witness_utxo_before);
    assert_eq!(psbt.inputs[0].tap_internal_key, tap_internal_key_before);

    // check fascia
    assert_eq!(fascia.bundles().len(), 1);
    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let im_keys = bundle.input_map.keys();
    assert_eq!(im_keys.len(), 1);
    let mut transitions = bundle.known_transitions.iter().map(|kt| &kt.transition);
    assert_eq!(transitions.len(), 1);
    let transition = transitions.next().unwrap();
    let assignments = &transition.assignments;
    assert_eq!(assignments.len(), 1);
    let (_, structured) = assignments.iter().next().unwrap();
    let structured = structured.as_structured();
    assert_eq!(structured.len(), 1);
    let seal = structured.first().unwrap().revealed_seal().unwrap();
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), 0);

    // check beneficiaries
    assert_eq!(beneficiaries.len(), 1);
    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.txid, TxPtr::WitnessTx);
    assert_eq!(seal.vout.into_u32(), 0);
}

/// UniFFI `htlc_prepare` shares `color_psbt_with_prevouts_runtime`. A known UDA whose selected
/// inputs do not carry the token used to panic on `uda_state.unwrap()` before the insufficient
/// allocation check.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_prepare_uda_missing_input_assignment_returns_coloring_error() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_uda(None, None, vec![]);

    let vanilla: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && u.rgb_allocations.is_empty())
        .expect("uncolored colorable UTXO")
        .utxo
        .outpoint
        .into();

    let address = BdkAddress::from_str(&party_send.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(vanilla).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(&asset.asset_id, HashMap::from([(vout, 1)]), blinding);

    let result = party_send.wallet.htlc_prepare(
        &mut psbt,
        coloring_info,
        vec![vanilla],
        MIN_CONFIRMATIONS,
        None,
    );
    assert!(
        matches!(
            result,
            Err(Error::InvalidColoringInfo { ref details })
                if details.contains("greater than available")
                    || details.contains("no token assignment")
        ),
        "htlc_prepare must return a coloring error, not panic; got {result:?}"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_fail() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // prepare PSBT
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let base_psbt = psbt.clone();

    // prepare coloring data
    assert_eq!(psbt.unsigned_tx.input.len(), 1);
    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    output_map.insert(output.0 as u32, AMOUNT);

    // wrong contract ID
    let fake_cid = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E";
    let asset_coloring_info = AssetColoringInfo {
        output_map: output_map.clone(),
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> =
        HashMap::from_iter([(ContractId::from_str(fake_cid).unwrap(), asset_coloring_info)]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    assert_matches!(
        result,
        Err(Error::AssetNotFound { asset_id }) if asset_id == fake_cid
    );

    // wrong output map vout
    psbt = base_psbt.clone();
    let fake_o_map: HashMap<u32, u64> = HashMap::from_iter([(666, AMOUNT)]);
    let asset_coloring_info = AssetColoringInfo {
        output_map: fake_o_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    let msg = "invalid vout in output_map, does not exist in the given PSBT";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));

    // vout equal to output count (off-by-one boundary)
    psbt = base_psbt.clone();
    let boundary_vout = psbt.outputs.len() as u32;
    let asset_coloring_info = AssetColoringInfo {
        output_map: HashMap::from_iter([(boundary_vout, AMOUNT)]),
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));

    // wrong output map amount
    psbt = base_psbt.clone();
    let fake_o_map = output_map.keys().map(|k| (*k, 999u64)).collect();
    let asset_coloring_info = AssetColoringInfo {
        output_map: fake_o_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info.clone());
    let msg = "total amount in output_map (999) greater than available (666)";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));

    // signed PSBT without OP_RETURN: cannot auto-insert
    // (previous failing color_psbt calls may have already inserted OP_RETURN)
    psbt = base_psbt;
    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let mut signed_psbt = Psbt::from_str(&signed_psbt).unwrap();
    assert!(
        !signed_psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    let asset_coloring_info = AssetColoringInfo {
        output_map: output_map.clone(),
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send
        .wallet
        .color_psbt(&mut signed_psbt, coloring_info);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_overflow_fail() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // wallets
    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();

    // create 1 UTXO and send the rest
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);

    // issue
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // total amount in output_map overflows u64: two valid vouts whose amounts sum to
    // more than u64::MAX (the checked sum must error before reaching the available check)
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let output_map: HashMap<u32, u64> = HashMap::from_iter([(0, u64::MAX), (1, 1)]);
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    let msg = "total amount in output_map exceeds u64::MAX";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));

    // vout in output_map overflows u32 when shifted by 1 for the OP_RETURN output
    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let output_map: HashMap<u32, u64> = HashMap::from_iter([(u32::MAX, AMOUNT)]);
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map: HashMap<ContractId, AssetColoringInfo> = HashMap::from_iter([(
        ContractId::from_str(&asset.asset_id).unwrap(),
        asset_coloring_info,
    )]);
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    let msg = "vout in output_map is too large";
    assert!(matches!(result, Err(Error::InvalidColoringInfo { details: m }) if m == msg));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_indexer_url_electrum_success() {
    initialize();

    let result = check_indexer_url(ELECTRUM_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Electrum));

    let result = check_indexer_url(ELECTRUM_2_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Electrum));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_indexer_url_electrum_fail() {
    initialize();

    let result = check_indexer_url(ELECTRUM_BLOCKSTREAM_URL, BitcoinNetwork::Regtest);
    let verbose_unsupported =
        "verbose transactions are unsupported by the provided electrum service";
    assert_matches!(result, Err(Error::InvalidIndexer { details: m }) if m.contains(verbose_unsupported));
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn check_indexer_url_esplora_success() {
    initialize();

    let result = check_indexer_url(ESPLORA_URL, BitcoinNetwork::Regtest);
    assert_matches!(result, Ok(IndexerProtocol::Esplora));
}

#[cfg(feature = "esplora")]
#[test]
#[parallel]
fn check_indexer_url_esplora_fail() {
    initialize();

    let result = check_indexer_url(PROXY_URL, BitcoinNetwork::Regtest);
    let invalid_indexer = s!("not a valid electrum nor esplora server");
    assert_matches!(result, Err(Error::InvalidIndexer { details: m }) if m == invalid_indexer);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_proxy_url_success() {
    initialize();

    assert!(check_proxy_url(PROXY_URL).is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn check_proxy_url_fail() {
    initialize();

    let result = check_proxy_url(PROXY_URL_MOD_PROTO);
    assert_matches!(result, Err(Error::InvalidProxyProtocol { version: _ }));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn accept_transfer_consignment_fail() {
    initialize();

    // === offline tests

    let mut offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party.wallet.accept_transfer_consignment(
        Online { id: 0 },
        PathBuf::from(s!("anyConsignmentPath")),
        FAKE_TXID.to_string(),
        0,
        0,
    );
    assert_matches!(result, Err(Error::Offline));

    // === online tests

    let mut party = get_empty_party!();

    // invalid txid
    let consignment_path = party.wallet.get_transfers_dir().join(CONSIGNMENT_FILE);
    let result = party.wallet.accept_transfer_consignment(
        party.online,
        consignment_path,
        s!("invalidTxid"),
        0,
        0,
    );
    assert_matches!(result, Err(Error::InvalidTxid));

    // invalid consignment path
    let result = party.wallet.accept_transfer_consignment(
        party.online,
        PathBuf::from(s!("invalidConsignmentPath")),
        FAKE_TXID.to_string(),
        0,
        0,
    );
    assert_matches!(result, Err(Error::InvalidFilePath { file_path: m }) if m == "invalidConsignmentPath");
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn get_tx_height_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_empty_party!();

    let _guard = stop_mining();
    let txid = party.send_btc(&rcv_party.get_address(), 1000);

    // unconfirmed TX
    let result = party.wallet.get_tx_height(party.online, txid.clone());
    assert_matches!(result, Ok(None));

    drop(_guard);
    mine(false);

    // confirmed TX
    let result = party.wallet.get_tx_height(party.online, txid);
    assert_matches!(result, Ok(Some(height)) if height > 0);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn get_tx_height_fail() {
    initialize();

    // === offline tests

    let offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party
        .wallet
        .get_tx_height(Online { id: 0 }, FAKE_TXID.to_string());
    assert_matches!(result, Err(Error::Offline));

    // === online tests

    let party = get_empty_party!();

    // invalid txid
    let result = party.wallet.get_tx_height(party.online, s!("invalidTxid"));
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn update_witnesses_fail() {
    initialize();

    let offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party
        .wallet
        .update_witnesses(Online { id: 0 }, 0, vec![]);
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn update_witnesses_success() {
    initialize();

    let party = get_empty_party!();

    let result = party.wallet.update_witnesses(party.online, 0, vec![]);
    assert!(result.is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn save_new_asset_fail() {
    initialize();

    let offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };

    let mut party = get_funded_party!();
    let mut rcv_party = get_empty_party!();
    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.witness_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: Some(WitnessData {
                amount_sat: 1000,
                blinding: None,
            }),
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let txid = party.send_retry(&recipient_map);
    let consignment_path = party
        .wallet
        .get_send_consignment_path(&asset.asset_id, &txid);
    let consignment = RgbTransfer::load_file(consignment_path).unwrap();

    let result = offline_party
        .wallet
        .save_new_asset(Online { id: 0 }, consignment, txid);
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_end_db_update_only_fail() {
    initialize();

    let mut offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party
        .wallet
        .send_end_db_update_only(Online { id: 0 }, s!(""));
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_end_db_update_only_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let begin = party
        .wallet
        .send_begin(
            party.online,
            recipient_map,
            true,
            FEE_RATE,
            MIN_CONFIRMATIONS,
            default_send_expiration(),
            false,
            None,
        )
        .unwrap();
    let signed_psbt = party.wallet.sign_psbt(begin.psbt.clone(), None).unwrap();
    party.wallet.create_consignments(begin.psbt).unwrap();

    let result = party
        .wallet
        .send_end_db_update_only(party.online, signed_psbt)
        .unwrap();

    assert!(!result.txid.is_empty());
    assert_eq!(result.batch_transfer_idx, begin.batch_transfer_idx.unwrap());
    assert_eq!(result.entropy, begin.details.entropy);
    assert!(
        party
            .check_test_transfer_status_sender(&result.txid, TransferStatus::WaitingConfirmations,)
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_end_db_update_only_unknown_transfer() {
    initialize();

    let amount: u64 = 10;
    let mut party_1 = get_funded_party!();
    let mut party_2 = get_funded_party!();

    let asset = party_1.issue_asset_nia(None);
    let receive_data = party_1.blind_receive();
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(amount),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let unsigned_psbt = party_1.send_begin_result(&recipient_map).unwrap();
    let signed_psbt = party_1.wallet.sign_psbt(unsigned_psbt.psbt, None).unwrap();
    let psbt_txid = Psbt::from_str(&signed_psbt)
        .unwrap()
        .extract_tx()
        .unwrap()
        .compute_txid()
        .to_string();

    let result = party_2
        .wallet
        .send_end_db_update_only(party_2.online, signed_psbt);
    assert_matches!(result, Err(Error::UnknownTransfer { txid }) if txid == psbt_txid);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn upsert_witness_success() {
    initialize();

    let party = get_empty_party!();

    let result = party
        .wallet
        .upsert_witness(RgbTxid::from_str(FAKE_TXID).unwrap(), WitnessOrd::Tentative);
    assert!(result.is_ok());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn create_consignments_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let psbt = party.send_begin_result(&recipient_map).unwrap().psbt;
    let result = party.wallet.create_consignments(psbt.clone());
    assert!(result.is_ok());
    let psbt = Psbt::from_str(&psbt).unwrap();
    let txid = psbt.extract_tx().unwrap().compute_txid().to_string();
    let consignment_path = party
        .wallet
        .get_asset_transfer_dir(party.wallet.get_transfers_dir().join(txid), &asset.asset_id)
        .join(CONSIGNMENT_FILE);
    assert!(consignment_path.is_file());
}

// The send consignment is derived from begin-time data (fascia, beneficiaries
// and the unsigned witness txid), so it must be byte-identical whether built
// from the unsigned or the signed PSBT.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn send_consignment_stable_across_signing() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);

    let unsigned_psbt = party.send_begin_result(&recipient_map).unwrap().psbt;

    let txid = Psbt::from_str(&unsigned_psbt)
        .unwrap()
        .unsigned_tx
        .compute_txid()
        .to_string();
    let consignment_path = party
        .wallet
        .get_send_consignment_path(&asset.asset_id, &txid);

    // consignment from the unsigned PSBT
    party
        .wallet
        .create_consignments(unsigned_psbt.clone())
        .unwrap();
    let consignment_from_unsigned = std::fs::read(&consignment_path).unwrap();
    assert!(!consignment_from_unsigned.is_empty());

    // consignment regenerated from the signed PSBT
    let signed_psbt = party.wallet.sign_psbt(unsigned_psbt, None).unwrap();
    party.wallet.create_consignments(signed_psbt).unwrap();
    let consignment_from_signed = std::fs::read(&consignment_path).unwrap();

    assert_eq!(consignment_from_unsigned, consignment_from_signed);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn create_consignments_return_path_success() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let psbt = party.send_begin_result(&recipient_map).unwrap().psbt;

    let txid = Psbt::from_str(&psbt)
        .unwrap()
        .extract_tx()
        .unwrap()
        .compute_txid()
        .to_string();
    let expected_path = party
        .wallet
        .get_asset_transfer_dir(
            party.wallet.get_transfers_dir().join(&txid),
            &asset.asset_id,
        )
        .join(CONSIGNMENT_FILE);
    let public_path = party
        .wallet
        .get_send_consignment_path(&asset.asset_id, &txid);
    assert_eq!(public_path, expected_path);

    let returned_path = party
        .wallet
        .create_consignments_return_path(psbt.clone())
        .unwrap();

    assert_eq!(returned_path, expected_path.to_string_lossy());
    assert!(expected_path.is_file());

    assert!(party.wallet.create_consignments(psbt).is_ok());
    assert!(expected_path.is_file());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn create_consignments_return_path_multi_asset_fails() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset_nia = party.issue_asset_nia(None);
    let asset_cfa = party.issue_asset_cfa(Some(&[AMOUNT * 2]), Some(FILE_STR.to_string()));
    let receive_data_nia = rcv_party.blind_receive();
    let receive_data_cfa = rcv_party.blind_receive();
    let recipient_map = HashMap::from([
        (
            asset_nia.asset_id.clone(),
            vec![Recipient {
                assignment: Assignment::Fungible(10),
                recipient_id: receive_data_nia.recipient_id.clone(),
                witness_data: None,
                transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
            }],
        ),
        (
            asset_cfa.asset_id.clone(),
            vec![Recipient {
                assignment: Assignment::Fungible(10),
                recipient_id: receive_data_cfa.recipient_id.clone(),
                witness_data: None,
                transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
            }],
        ),
    ]);
    let psbt = party.send_begin_result(&recipient_map).unwrap().psbt;

    assert!(party.wallet.create_consignments(psbt.clone()).is_ok());

    let result = party.wallet.create_consignments_return_path(psbt);
    assert_matches!(result, Err(Error::Internal { details: _ }));
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[test]
#[parallel]
fn validate_consignment_offchain_success() {
    initialize();

    let amount: u64 = 66;
    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

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

    let send_result = party.send_result(&recipient_map).unwrap();
    let txid = send_result.txid;
    assert!(!txid.is_empty());

    let (_, asset_transfer, _) = party.get_test_transfer_sender(&txid);
    let asset_id = asset_transfer.asset_id.clone().unwrap();
    let consignment_pathbuf = party.wallet.get_send_consignment_path(&asset_id, &txid);
    let consignment_path = consignment_pathbuf.to_string_lossy();

    let result = validate_consignment_offchain(
        consignment_path.as_ref(),
        &txid,
        DEFAULT_INDEXER_URL,
        BitcoinNetwork::Regtest,
    )
    .unwrap();

    assert!(
        result.valid,
        "offchain validation should succeed for consignment with bundled witness"
    );
    assert!(result.error.is_none());
    assert!(result.details.is_none());
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[test]
#[parallel]
fn validate_consignment_offchain_invalid_txid() {
    initialize();

    let amount: u64 = 66;
    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

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

    let send_result = party.send_result(&recipient_map).unwrap();
    let txid = send_result.txid;
    let (_, asset_transfer, _) = party.get_test_transfer_sender(&txid);
    let asset_id = asset_transfer.asset_id.clone().unwrap();
    let consignment_pathbuf = party.wallet.get_send_consignment_path(&asset_id, &txid);
    let consignment_path = consignment_pathbuf.to_string_lossy();

    let result = validate_consignment_offchain(
        consignment_path.as_ref(),
        "not-a-valid-txid",
        DEFAULT_INDEXER_URL,
        BitcoinNetwork::Regtest,
    );

    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[test]
#[parallel]
fn validate_consignment_offchain_file_not_found() {
    initialize();

    let result = validate_consignment_offchain(
        "/nonexistent/path/consignment.rgb",
        "e5a3e577309df31bd606f48049049d2e1e02b048206ba232944fcc053a176ccb",
        DEFAULT_INDEXER_URL,
        BitcoinNetwork::Regtest,
    );

    assert_matches!(result, Err(Error::Internal { details: _ }));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn offline() {
    initialize();

    let mut wallet = get_test_wallet(true, None);
    let result = wallet.list_unspents_vanilla(Online { id: 0 }, MIN_CONFIRMATIONS, false);
    assert_matches!(result, Err(Error::Offline));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn is_asset_known_success() {
    initialize();

    let mut party = get_funded_party!();
    let asset = party.issue_asset_nia(None);
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    assert!(party.wallet.is_asset_known(contract_id).unwrap());

    let unknown_cid =
        ContractId::from_str("rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E").unwrap();
    assert!(!party.wallet.is_asset_known(unknown_cid).unwrap());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_asset_media_success() {
    initialize();

    let mut party = get_funded_party!();

    let nia_asset = party.issue_asset_nia(None);
    let nia_medias = party
        .wallet
        .list_asset_media(nia_asset.asset_id.clone())
        .unwrap();
    assert!(nia_medias.is_empty());

    let cfa_asset = party
        .wallet
        .issue_asset_cfa(
            NAME.to_string(),
            None,
            PRECISION,
            vec![AMOUNT],
            Some(FILE_STR.to_string()),
        )
        .unwrap();
    let cfa_medias = party
        .wallet
        .list_asset_media(cfa_asset.asset_id.clone())
        .unwrap();
    assert_eq!(cfa_medias.len(), 1);
    assert_eq!(cfa_medias.iter().next().unwrap().mime, "text/plain");

    let image_str = ["tests", "qrcode.png"].join(MAIN_SEPARATOR_STR);
    let uda_asset =
        party.issue_asset_uda(Some(DETAILS), Some(FILE_STR), vec![&image_str, FILE_STR]);
    let uda_medias = party
        .wallet
        .list_asset_media(uda_asset.asset_id.clone())
        .unwrap();
    // the token media and the 2nd attachment are the same file, so they are returned once
    assert_eq!(uda_medias.len(), 2);
    let mimes: Vec<_> = uda_medias.iter().map(|m| m.mime.as_str()).collect();
    assert!(mimes.contains(&"text/plain"));
    assert!(mimes.contains(&"image/png"));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn list_asset_media_fail() {
    initialize();

    let party = get_empty_party!();
    let unknown_asset_id = "rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E".to_string();
    let result = party.wallet.list_asset_media(unknown_asset_id);
    assert!(matches!(result, Err(Error::AssetNotFound { asset_id: _ })));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn uniffi_color_psbt_and_prepare_consume_round_trip() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let inserts_opreturn_at_front = psbt
        .unsigned_tx
        .output
        .iter()
        .any(|o| o.script_pubkey.is_p2tr());
    let final_vout = if inserts_opreturn_at_front {
        vout + 1
    } else {
        vout
    };

    // Mirror bindings/uniffi `to_rgb_coloring_info` + `color_psbt_and_prepare_consume` conversions.
    let ffi_assets = vec![(
        asset.asset_id.clone(),
        HashMap::from([(vout, AMOUNT)]),
        Some(blinding),
    )];
    let mut asset_info_map = HashMap::new();
    for (asset_id, output_map, static_blinding) in ffi_assets {
        let contract_id = ContractId::from_str(&asset_id).unwrap();
        asset_info_map.insert(
            contract_id,
            AssetColoringInfo {
                output_map,
                static_blinding,
            },
        );
    }
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };

    let psbt_string = psbt.to_string();
    psbt = Psbt::from_str(&psbt_string).unwrap();
    let ColorPrepareResult { transfers, .. } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    assert_eq!(transfers.len(), 1);
    let mut consignment_bytes = vec![];
    transfers[0]
        .save(&mut consignment_bytes)
        .expect("serialize consignment");
    let loaded = RgbTransfer::load(&consignment_bytes[..]).expect("load consignment");
    assert_eq!(loaded.contract_id().to_string(), asset.asset_id);
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
    );
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let recv_online = recv_party.party_online();
    recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            loaded,
            txid,
            final_vout,
            blinding,
            expected_nia(&asset.asset_id, AMOUNT),
        )
        .unwrap();
}

/// `color_psbt_*_and_prepare_consume` registers an Initiated batch without consuming the stash, so
/// `fail_transfers` can roll back if the tx is never broadcast.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_fail_transfers_rolls_back_without_broadcast() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    // Pre-OP_RETURN index for legacy color_psbt_and_prepare_consume shift when P2TR inserts OP_RETURN.
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    assert!(party_send.check_test_transfer_status_sender(
        &psbt.unsigned_tx.compute_txid().to_string(),
        TransferStatus::Initiated
    ));

    // Stash still holds the allocation (consume deferred).
    let rows = party_send
        .wallet
        .contract_assignments_for_outpoints(contract_id, vec![input.into()])
        .unwrap();
    assert!(!rows[0].1.is_empty());

    assert!(party_send.fail_transfers_single(batch_transfer_idx));
    assert!(party_send.check_test_transfer_status_sender(
        &psbt.unsigned_tx.compute_txid().to_string(),
        TransferStatus::Failed
    ));

    // After fail, allocations remain available in the stash for a new coloring.
    let rows = party_send
        .wallet
        .contract_assignments_for_outpoints(contract_id, vec![input.into()])
        .unwrap();
    assert!(!rows[0].1.is_empty());
}

/// Once the tx is broadcast the inputs are spent for good, so `fail_transfers` has to refuse the
/// still-Initiated batch instead of crediting those inputs back.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_fail_transfers_refused_after_broadcast() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();

    let result = party_send.fail_transfers(Some(batch_transfer_idx), false, false);
    assert!(matches!(result, Err(Error::CannotFailBatchTransfer)));

    // the batch stays untouched, so the deferred consume can still be completed
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

/// The registered batch can only account for the destinations listed in `output_map`, so an
/// under-assignment, which would destroy the remainder, has to be rejected.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_rejects_partial_output_map() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT / 2)]),
        blinding,
    );

    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.contains("less than available") && m.contains("full allocation required")
    );
}

/// No transition would assign a contract missing from `coloring_info`, so spending an input that
/// carries one has to be refused instead of destroying those allocations.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_rejects_unlisted_input_contract() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let _unlisted = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // spending every allocated UTXO puts the second asset on the inputs wherever it landed
    let allocated: Vec<OutPoint> = party_send
        .list_unspents(true)
        .into_iter()
        .filter(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .map(|u| u.utxo.outpoint.into())
        .collect();
    assert!(!allocated.is_empty());

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    for outpoint in &allocated {
        tx_builder.add_utxo(*outpoint).unwrap();
    }
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let outputs_before = psbt.unsigned_tx.output.len();
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.contains("contracts not listed in coloring_info")
    );
    // the rejection happens before the caller's PSBT gets an OP_RETURN
    assert_eq!(psbt.unsigned_tx.output.len(), outputs_before);
}

/// Only the asset-owner assignment is re-assigned by the coloring, so spending an input that also
/// carries an inflation right has to be refused: the right would be destroyed, and its amount would
/// be miscounted as spendable fungible value on the way there.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_rejects_input_carrying_inflation_right() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(3), None, FEE_RATE, None);
    let asset = party_send.issue_asset_ifa(Some(&[AMOUNT]), None, None);

    let inflation_utxo: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| {
            u.rgb_allocations
                .iter()
                .any(|a| matches!(a.assignment, Assignment::InflationRight(_)))
        })
        .expect("UTXO carrying the inflation right")
        .utxo
        .outpoint
        .into();

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(inflation_utxo).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let result = party_send.wallet.color_psbt_and_prepare_consume(
        &mut psbt,
        coloring_info,
        MIN_CONFIRMATIONS,
        None,
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m }) if m.contains("inflation right")
    );
}

/// The registered batch has to carry the caller's confirmation depth, which gates both settling and
/// the reorg-safety checks, and the caller's deadline, which gates the bulk `fail_transfers` sweep.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_registers_requested_batch_parameters() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;
    let min_confirmations: u8 = 3;
    let expiration_timestamp = default_send_expiration();

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    party_send
        .wallet
        .color_psbt_and_prepare_consume(
            &mut psbt,
            coloring_info,
            min_confirmations,
            Some(expiration_timestamp),
        )
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let (_, _, batch_transfer) = party_send.get_test_transfer_sender(&txid);
    assert_eq!(batch_transfer.min_confirmations, min_confirmations);
    assert_eq!(batch_transfer.expiration, Some(expiration_timestamp as i64));
}

/// A batch whose deadline passed without a broadcast is abandoned, so the bulk sweep has to reclaim
/// its reserved inputs.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_bulk_fail_transfers_reclaims_expired_batch() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;
    let expired = (now().unix_timestamp() - 1) as u64;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, Some(expired))
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    assert!(party_send.fail_transfers_all());

    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Failed));
}

/// The same sweep must not touch an expired batch whose TX is already on-chain: crediting those
/// inputs back would let them be selected again.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_and_prepare_consume_bulk_fail_transfers_spares_broadcast_expired_batch() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;
    let expired = (now().unix_timestamp() - 1) as u64;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, Some(expired))
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();

    assert!(!party_send.fail_transfers_all());

    // the batch stays untouched, so the deferred consume can still be completed
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_prepare_writes_op_dir_for_wallet_owned_input() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let txo_count_before = party_send.db_txos().len();
    let HtlcPrepareResult {
        operation_id,
        colored_psbt,
        operation_dir,
    } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    assert!(!operation_id.is_empty());
    assert_eq!(colored_psbt, psbt.to_string());
    assert!(operation_dir.starts_with("htlc_ops/"));
    // External recipient: no new wallet TXO for the RGB destination.
    assert_eq!(party_send.db_txos().len(), txo_count_before);

    let op_dir = party_send.wallet.get_wallet_dir().join(&operation_dir);
    assert!(op_dir.join("meta.json").exists());
    assert!(op_dir.join("fascia").exists());
    assert!(op_dir.join("colored.psbt").exists());
    assert!(op_dir.join("escrow.json").exists());
    let consignment_count = std::fs::read_dir(op_dir.join("consignments"))
        .unwrap()
        .count();
    assert_eq!(consignment_count, 1);

    // Wallet-owned RGB input → empty escrow log (see foreign-escrow test for non-empty entries).
    let escrow_raw = std::fs::read_to_string(op_dir.join("escrow.json")).unwrap();
    let escrow: serde_json::Value = serde_json::from_str(&escrow_raw).unwrap();
    assert_eq!(escrow["entries"].as_array().unwrap().len(), 0);

    let meta_raw = std::fs::read_to_string(op_dir.join("meta.json")).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_raw).unwrap();
    assert!(meta["batch_transfer_idx"].as_i64().is_some());

    let transfers = party_send.list_transfers(Some(&asset.asset_id));
    let initiated = transfers
        .iter()
        .find(|t| t.status == TransferStatus::Initiated)
        .expect("initiated color-consume transfer");
    assert_eq!(initiated.kind, TransferKind::Send);
    assert!(initiated.recipient_id.is_some());

    let asset_transfers = party_send.db_asset_transfers();
    let colorings = party_send.db_colorings_filtered(asset_transfers.last().unwrap().idx);
    assert!(colorings.iter().any(|c| c.r#type == ColoringType::Input));
    assert!(!colorings.iter().any(|c| c.r#type == ColoringType::Change));

    assert_eq!(
        party_send.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Prepared
    );
}

/// Central HTLC path: spend RGB sitting on a foreign escrow outpoint (not a wallet TXO),
/// claim onto a plain wallet-owned script (no `witness_receive`), and assert SQL accounting +
/// escrow.json. The issue #90 claim destination is covered by
/// `htlc_foreign_escrow_witness_receive_apply_refresh_balance`.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_prepare_foreign_escrow_input_persists_claim_change() {
    initialize();

    let amt_sat = 500;
    let blinding_fund = 777;
    let blinding_claim = 888;

    let mut party = get_funded_noutxo_party!();
    let mut escrow_party = get_empty_party!();
    // One colored UTXO + one uncolored for claim fees.
    party.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party.issue_asset_nia(Some(&[AMOUNT]));
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    let allocated: OutPoint = party
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint
        .into();

    // Fund escrow: move RGB onto a foreign script (no wallet TXO for that outpoint).
    let escrow_address = BdkAddress::from_str(&escrow_party.get_address()).unwrap();
    let escrow_script = escrow_address.assume_checked().script_pubkey();
    let mut fund_builder = party.wallet.bdk_wallet_mut().build_tx();
    fund_builder.add_utxo(allocated).unwrap();
    fund_builder.manually_selected_only();
    fund_builder
        .add_recipient(escrow_script.clone(), BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut fund_psbt = fund_builder.finish().unwrap();
    let fund_input = fund_psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut fund_psbt, true);
    let escrow_vout = fund_psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let fund_coloring = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(escrow_vout, AMOUNT)]),
        blinding_fund,
    );
    let ColorPrepareResult {
        batch_transfer_idx: fund_batch_idx,
        ..
    } = party
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut fund_psbt,
            fund_coloring,
            vec![fund_input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    // Coloring defers the stash update: the escrow allocation only exists once the funding TX is
    // broadcast and its fascia consumed. Settling it too leaves the wallet owning nothing, so
    // whatever the claim contributes below is attributable to the claim alone.
    let escrow_txid = fund_psbt.unsigned_tx.compute_txid();
    let fund_signed = party.wallet.sign_psbt(fund_psbt.to_string(), None).unwrap();
    let fund_finalized = party.wallet.finalize_psbt(fund_signed, None).unwrap();
    let fund_tx = Psbt::from_str(&fund_finalized)
        .unwrap()
        .extract_tx()
        .expect("valid funding tx");
    party.wallet.broadcast_tx(fund_tx.clone()).unwrap();
    mine_tx(false, &escrow_txid.to_string());
    party
        .wallet
        .consume_transfer_fascia(party.party_online(), fund_batch_idx)
        .unwrap();
    party.wait_for_refresh(Some(&asset.asset_id));
    let balance_before_claim = party.get_asset_balance(&asset.asset_id);
    let escrow_outpoint = OutPoint {
        txid: escrow_txid,
        vout: escrow_vout,
    };
    let escrow_witness_utxo = fund_psbt.unsigned_tx.output[escrow_vout as usize].clone();

    assert_eq!(
        party
            .db_txos()
            .iter()
            .filter(|t| t.txid == escrow_txid.to_string() && t.vout == escrow_vout)
            .count(),
        0,
        "foreign escrow outpoint must not be a wallet TXO"
    );
    let stash_on_escrow = party
        .wallet
        .contract_assignments_for_outpoints(contract_id, vec![escrow_outpoint.into()])
        .unwrap();
    assert_eq!(stash_on_escrow.len(), 1);
    assert!(!stash_on_escrow[0].1.is_empty());

    // Claim: spend foreign escrow + uncolored fee UTXO → wallet-owned script.
    let fee_utxo: OutPoint = party
        .list_unspents(true)
        .into_iter()
        .find(|u| {
            u.rgb_allocations.is_empty()
                && OutPoint::from(u.utxo.outpoint.clone()) != allocated
                && OutPoint::from(u.utxo.outpoint.clone()) != escrow_outpoint
        })
        .expect("uncolored fee UTXO")
        .utxo
        .outpoint
        .into();
    let claim_address = BdkAddress::from_str(&party.get_address()).unwrap();
    let mut claim_builder = party.wallet.bdk_wallet_mut().build_tx();
    claim_builder.add_utxo(fee_utxo).unwrap();
    claim_builder.manually_selected_only();
    claim_builder
        .add_recipient(
            claim_address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut claim_psbt = claim_builder.finish().unwrap();
    prepend_psbt_input(
        &mut claim_psbt,
        escrow_outpoint,
        Some(escrow_witness_utxo),
        Some(fund_tx.clone()),
    );
    insert_op_return(&mut claim_psbt, true);
    let claim_vout = claim_psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let claim_coloring = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(claim_vout, AMOUNT)]),
        blinding_claim,
    );

    let txo_count_before = party.db_txos().len();
    let HtlcPrepareResult {
        operation_id,
        operation_dir,
        ..
    } = party
        .wallet
        .htlc_prepare(
            &mut claim_psbt,
            claim_coloring,
            vec![escrow_outpoint],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let op_dir = party.wallet.get_wallet_dir().join(&operation_dir);
    let escrow_raw = std::fs::read_to_string(op_dir.join("escrow.json")).unwrap();
    let escrow: serde_json::Value = serde_json::from_str(&escrow_raw).unwrap();
    let entries = escrow["entries"].as_array().unwrap();
    assert_eq!(
        entries.len(),
        1,
        "foreign input must be logged in escrow.json"
    );
    assert_eq!(entries[0]["asset_id"], asset.asset_id);
    assert_eq!(entries[0]["outpoint"]["txid"], escrow_txid.to_string());
    assert_eq!(entries[0]["outpoint"]["vout"], escrow_vout);

    // Claim Change TXO may be inserted; escrow outpoint must still be absent.
    assert!(party.db_txos().len() >= txo_count_before);
    assert_eq!(
        party
            .db_txos()
            .iter()
            .filter(|t| t.txid == escrow_txid.to_string() && t.vout == escrow_vout)
            .count(),
        0
    );

    let meta_raw = std::fs::read_to_string(op_dir.join("meta.json")).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_raw).unwrap();
    let batch_idx = meta["batch_transfer_idx"]
        .as_i64()
        .expect("batch always set") as i32;

    let asset_transfers = party.db_asset_transfers_filtered(batch_idx);
    assert_eq!(asset_transfers.len(), 1);
    let colorings = party.db_colorings_filtered(asset_transfers[0].idx);
    assert!(
        !colorings.iter().any(|c| c.r#type == ColoringType::Input),
        "foreign escrow must not get Input colorings"
    );
    let change = colorings
        .iter()
        .find(|c| c.r#type == ColoringType::Change)
        .expect("wallet claim output must project Change for balance APIs");
    assert_eq!(change.assignment, Assignment::Fungible(AMOUNT));

    // the claim tx is not broadcast: apply must refuse so RGB state stays abortable
    let apply = party.wallet.htlc_apply(party.party_online(), &operation_id);
    assert!(matches!(
        apply,
        Err(Error::InvalidHtlcOperationStatus { details })
            if details.contains("not known to the indexer")
    ));
    assert_eq!(
        party.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Prepared
    );

    // The claim batch is WaitingConfirmations, so its Change lands in `future` only. Asserting the
    // delta keeps this independent of how the funding transfer is accounted.
    let balance_after_claim = party.get_asset_balance(&asset.asset_id);
    assert_eq!(
        balance_after_claim.settled, balance_before_claim.settled,
        "unconfirmed claim must not move settled balance"
    );
    assert_eq!(
        balance_after_claim.future - balance_before_claim.future,
        AMOUNT,
        "Change projection must appear in future balance after foreign-escrow claim"
    );
}

/// Issue #90 claim: foreign HTLC UTXO spent to a `witness_receive` destination. Receive is the
/// sole allocation owner; color-prepare must not also project Change on that output.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_foreign_escrow_witness_receive_apply_refresh_balance() {
    initialize();

    let amt_sat = 500;
    let blinding_fund = 777;
    let blinding_claim = 888;

    let mut party = get_funded_noutxo_party!();
    let mut escrow_party = get_empty_party!();
    party.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party.issue_asset_nia(Some(&[AMOUNT]));
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    let allocated: OutPoint = party
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint
        .into();

    let escrow_address = BdkAddress::from_str(&escrow_party.get_address()).unwrap();
    let escrow_script = escrow_address.assume_checked().script_pubkey();
    let mut fund_builder = party.wallet.bdk_wallet_mut().build_tx();
    fund_builder.add_utxo(allocated).unwrap();
    fund_builder.manually_selected_only();
    fund_builder
        .add_recipient(escrow_script.clone(), BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut fund_psbt = fund_builder.finish().unwrap();
    let fund_input = fund_psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut fund_psbt, true);
    let escrow_vout = fund_psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let fund_coloring = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(escrow_vout, AMOUNT)]),
        blinding_fund,
    );
    let ColorPrepareResult {
        batch_transfer_idx: fund_batch_idx,
        ..
    } = party
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut fund_psbt,
            fund_coloring,
            vec![fund_input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let escrow_txid = fund_psbt.unsigned_tx.compute_txid();
    let fund_signed = party.wallet.sign_psbt(fund_psbt.to_string(), None).unwrap();
    let fund_finalized = party.wallet.finalize_psbt(fund_signed, None).unwrap();
    let fund_tx = Psbt::from_str(&fund_finalized)
        .unwrap()
        .extract_tx()
        .expect("valid funding tx");
    party.wallet.broadcast_tx(fund_tx.clone()).unwrap();
    mine_tx(false, &escrow_txid.to_string());
    party
        .wallet
        .consume_transfer_fascia(party.party_online(), fund_batch_idx)
        .unwrap();
    party.wait_for_refresh(Some(&asset.asset_id));
    let balance_before_claim = party.get_asset_balance(&asset.asset_id);
    let escrow_outpoint = OutPoint {
        txid: escrow_txid,
        vout: escrow_vout,
    };
    let escrow_witness_utxo = fund_psbt.unsigned_tx.output[escrow_vout as usize].clone();

    assert_eq!(
        party
            .db_txos()
            .iter()
            .filter(|t| t.txid == escrow_txid.to_string() && t.vout == escrow_vout)
            .count(),
        0,
        "foreign escrow outpoint must not be a wallet TXO"
    );
    let stash_on_escrow = party
        .wallet
        .contract_assignments_for_outpoints(contract_id, vec![escrow_outpoint.into()])
        .unwrap();
    assert_eq!(stash_on_escrow.len(), 1);
    assert!(!stash_on_escrow[0].1.is_empty());

    let receive_data = party.witness_receive();
    let invoice = Invoice::new(receive_data.invoice.clone()).unwrap();
    let proxy_recipient_id = invoice.invoice_data().proxy_recipient_id;
    let claim_script = script_buf_from_recipient_id(receive_data.recipient_id.clone())
        .unwrap()
        .expect("witness_receive yields a script");
    assert!(
        !party.db_pending_witness_scripts().is_empty(),
        "witness_receive must leave a pending witness script"
    );
    let incoming_before = party
        .list_transfers_filtered(AssetFilter::AnyOrNone, None)
        .into_iter()
        .find(|t| {
            t.kind == TransferKind::ReceiveWitness
                && t.recipient_id.as_deref() == Some(receive_data.recipient_id.as_str())
        })
        .expect("witness_receive must create an incoming transfer");
    assert_eq!(incoming_before.status, TransferStatus::WaitingCounterparty);

    let fee_utxo: OutPoint = party
        .list_unspents(true)
        .into_iter()
        .find(|u| {
            u.rgb_allocations.is_empty()
                && OutPoint::from(u.utxo.outpoint.clone()) != allocated
                && OutPoint::from(u.utxo.outpoint.clone()) != escrow_outpoint
        })
        .expect("uncolored fee UTXO")
        .utxo
        .outpoint
        .into();
    let mut claim_builder = party.wallet.bdk_wallet_mut().build_tx();
    claim_builder.add_utxo(fee_utxo).unwrap();
    claim_builder.manually_selected_only();
    claim_builder
        .add_recipient(claim_script.clone(), BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut claim_psbt = claim_builder.finish().unwrap();
    prepend_psbt_input(
        &mut claim_psbt,
        escrow_outpoint,
        Some(escrow_witness_utxo),
        Some(fund_tx),
    );
    insert_op_return(&mut claim_psbt, true);
    let claim_vout = claim_psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let claim_coloring = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(claim_vout, AMOUNT)]),
        blinding_claim,
    );

    let HtlcPrepareResult {
        operation_id,
        operation_dir,
        ..
    } = party
        .wallet
        .htlc_prepare(
            &mut claim_psbt,
            claim_coloring,
            vec![escrow_outpoint],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let meta_raw = std::fs::read_to_string(
        party
            .wallet
            .get_wallet_dir()
            .join(&operation_dir)
            .join("meta.json"),
    )
    .unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_raw).unwrap();
    let batch_idx = meta["batch_transfer_idx"]
        .as_i64()
        .expect("batch always set") as i32;
    let asset_transfers = party.db_asset_transfers_filtered(batch_idx);
    assert_eq!(asset_transfers.len(), 1);
    let colorings = party.db_colorings_filtered(asset_transfers[0].idx);
    assert!(
        !colorings.iter().any(|c| c.r#type == ColoringType::Change),
        "witness_receive destination must not be projected as Change"
    );
    assert!(
        !colorings.iter().any(|c| c.r#type == ColoringType::Input),
        "foreign escrow must not get Input colorings"
    );

    let incoming_after_prepare = party
        .list_transfers_filtered(AssetFilter::AnyOrNone, None)
        .into_iter()
        .find(|t| t.idx == incoming_before.idx)
        .unwrap();
    assert_eq!(
        incoming_after_prepare.status,
        TransferStatus::WaitingCounterparty,
        "prepare must not consume the open witness_receive"
    );
    let balance_after_prepare = party.get_asset_balance(&asset.asset_id);
    assert_eq!(
        balance_after_prepare.settled, balance_before_claim.settled,
        "prepare must not move settled balance"
    );
    assert_eq!(
        balance_after_prepare.future, balance_before_claim.future,
        "witness_receive owns the output: prepare must not add a Change future allocation"
    );

    // Claimant signs the fee input; escrow_party signs the foreign HTLC lock.
    let signed_by_claimant = party
        .wallet
        .sign_psbt(claim_psbt.to_string(), None)
        .unwrap();
    let signed_psbt = escrow_party
        .wallet
        .sign_psbt(signed_by_claimant, None)
        .unwrap();
    let finalized_psbt = escrow_party
        .wallet
        .finalize_psbt(signed_psbt, None)
        .unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    let claim_txid = tx.compute_txid().to_string();
    party.wallet.broadcast_tx(tx).unwrap();
    party
        .wallet
        .htlc_apply(party.party_online(), &operation_id)
        .unwrap();
    assert_eq!(
        party.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Applied
    );
    mine(false);

    let consignment_path = party
        .wallet
        .get_wallet_dir()
        .join(&operation_dir)
        .join("consignments")
        .join(format!("{}.rgb", asset.asset_id));
    party
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            proxy_recipient_id.clone(),
            consignment_path,
            claim_txid.clone(),
            Some(claim_vout),
        )
        .unwrap();

    // Open `witness_receive` has no asset_id yet; `refresh(Some(asset_id))` would skip it.
    // Drive the invoice like `send_to_oneself` (refresh, not `fetch_and_accept`: that API
    // only writes the stash, which `htlc_apply` already did).
    party.wait_for_refresh_raw(None, Some(&[receive_data.batch_transfer_idx]));
    mine(false);
    party.wait_for_refresh(None);

    let receive = party
        .list_transfers(Some(&asset.asset_id))
        .into_iter()
        .find(|t| t.kind == TransferKind::ReceiveWitness)
        .expect("incoming witness transfer");
    assert_eq!(receive.status, TransferStatus::Settled);
    assert_eq!(receive.assignments, vec![Assignment::Fungible(AMOUNT)]);
    assert_eq!(
        receive.recipient_id.as_deref(),
        Some(receive_data.recipient_id.as_str())
    );

    let claim_txo = party
        .db_txos()
        .into_iter()
        .find(|t| t.txid == claim_txid && t.vout == claim_vout)
        .expect("claim output must exist after receive processing");
    let claim_colorings: Vec<_> = party
        .db_colorings()
        .into_iter()
        .filter(|c| c.txo_idx == claim_txo.idx)
        .collect();
    assert!(
        claim_colorings
            .iter()
            .any(|c| c.r#type == ColoringType::Receive
                && c.assignment == Assignment::Fungible(AMOUNT)),
        "Receive must own the claimed allocation"
    );
    assert!(
        !claim_colorings
            .iter()
            .any(|c| c.r#type == ColoringType::Change),
        "Change + Receive on the same TXO would double-count balance"
    );

    let balance = party.get_asset_balance(&asset.asset_id);
    assert_eq!(balance.settled, AMOUNT);
    assert_eq!(balance.future, AMOUNT);
    assert_eq!(balance.spendable, AMOUNT);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_status_errors_for_unknown_and_invalid_transition() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    // Too short / not 32 hex → rejected before path join.
    assert!(matches!(
        party_send.wallet.htlc_reconcile("deadbeefdeadbeef"),
        Err(Error::HtlcOperationNotFound { .. })
    ));
    assert!(matches!(
        party_send
            .wallet
            .htlc_apply(party_send.party_online(), "../escape"),
        Err(Error::HtlcOperationNotFound { .. })
    ));
    // Valid format, unknown id.
    assert!(matches!(
        party_send.wallet.htlc_apply(
            party_send.party_online(),
            "0123456789abcdef0123456789abcdef",
        ),
        Err(Error::HtlcOperationNotFound { .. })
    ));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let HtlcPrepareResult { operation_id, .. } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    // Broadcast + apply once, then apply again must fail closed.
    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();
    party_send
        .wallet
        .htlc_apply(party_send.party_online(), &operation_id)
        .unwrap();
    assert!(matches!(
        party_send
            .wallet
            .htlc_apply(party_send.party_online(), &operation_id),
        Err(Error::InvalidHtlcOperationStatus { .. })
    ));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_rejects_path_traversal_operation_id_and_tampered_meta() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let wallet_dir = party_send.wallet.get_wallet_dir();
    let sentinel = wallet_dir.join("sentinel_outside_htlc_ops.txt");
    std::fs::write(&sentinel, b"untouched").unwrap();

    let online = party_send.party_online();
    for bad_id in [
        "../sentinel_outside_htlc_ops.txt",
        "..",
        "abc",
        "0123456789ABCDEF0123456789abcdef", // uppercase rejected
        "0123456789abcdef0123456789abcde/", // slash
    ] {
        assert!(
            matches!(
                party_send
                    .wallet
                    .htlc_apply(party_send.party_online(), bad_id),
                Err(Error::HtlcOperationNotFound { .. })
            ),
            "expected rejection for {bad_id:?}"
        );
        assert!(
            matches!(
                party_send.wallet.htlc_reconcile(bad_id),
                Err(Error::HtlcOperationNotFound { .. })
            ),
            "expected reconcile rejection for {bad_id:?}"
        );
        assert!(
            matches!(
                party_send.wallet.htlc_abort(online, bad_id),
                Err(Error::HtlcOperationNotFound { .. })
            ),
            "expected abort rejection for {bad_id:?}"
        );
    }
    assert_eq!(
        std::fs::read(&sentinel).unwrap(),
        b"untouched",
        "traversal must not touch files outside htlc_ops"
    );

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let HtlcPrepareResult {
        operation_id,
        operation_dir,
        ..
    } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    // Tamper meta.operation_id to a traversal value while keeping the file under the real dir.
    let meta_path = wallet_dir.join(&operation_dir).join("meta.json");
    let mut meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&meta_path).unwrap()).unwrap();
    meta["operation_id"] = serde_json::json!("../../sentinel_outside_htlc_ops.txt");
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

    assert!(matches!(
        party_send
            .wallet
            .htlc_apply(party_send.party_online(), &operation_id),
        Err(Error::Internal { .. })
    ));
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"untouched");
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_apply_recovers_after_crash_between_stash_consume_and_db_commit() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let HtlcPrepareResult {
        operation_id,
        operation_dir,
        ..
    } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();

    crate::wallet::rust_only::MOCK_FAIL_AFTER_STASH_CONSUME.with(|f| *f.borrow_mut() = true);
    assert!(matches!(
        party_send.wallet.htlc_apply(party_send.party_online(),&operation_id),
        Err(Error::Internal { details }) if details.contains("mock failure after HTLC stash consume")
    ));

    let op_dir = party_send.wallet.get_wallet_dir().join(&operation_dir);
    assert!(
        op_dir.join("stash_consumed").exists(),
        "durable marker must exist after stash consume"
    );
    let meta: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(op_dir.join("meta.json")).unwrap()).unwrap();
    assert_eq!(meta["status"], "prepared");

    // Aborting now would fail the batch while the stash keeps the consumed fascia.
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let online = party_send.party_online();
    assert!(matches!(
        party_send.wallet.htlc_abort(online, &operation_id),
        Err(Error::InvalidHtlcOperationStatus { details }) if details.contains("already consumed")
    ));
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    // Retry finishes without re-consuming.
    party_send
        .wallet
        .htlc_apply(party_send.party_online(), &operation_id)
        .unwrap();
    assert_eq!(
        party_send.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Applied
    );
    assert!(!op_dir.join("stash_consumed").exists());
}

/// The accept paths reach the indexer/resolver, which unwrap the online data, so they have to
/// fail closed on an offline wallet instead of panicking.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn accept_paths_fail_when_offline() {
    initialize();

    let mut offline_party = {
        let wallet = get_test_wallet(true, None);
        party!(wallet, Online { id: 0 })
    };
    let result = offline_party.wallet.accept_transfer(
        Online { id: 0 },
        FAKE_TXID.to_string(),
        0,
        &PROXY_ENDPOINT,
        777,
    );
    assert_matches!(result, Err(Error::Offline));

    let result = offline_party
        .wallet
        .fetch_and_accept_transfer_by_recipient_id(
            Online { id: 0 },
            FAKE_TXID.to_string(),
            s!("bcrt:wvout:not-checked-before-the-online-guard"),
            &PROXY_ENDPOINT,
            777,
            MIN_CONFIRMATIONS,
            expected_nia(FAKE_TXID, AMOUNT),
        );
    assert_matches!(result, Err(Error::Offline));

    let result = offline_party
        .wallet
        .consume_transfer_fascia(Online { id: 0 }, 1);
    assert_matches!(result, Err(Error::Offline));
}

/// `consume_transfer_fascia` mutates the stash before its SQL commit, so a crash in between must
/// leave a durable marker that lets a retry finish without consuming the fascia twice.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_recovers_after_crash_between_stash_consume_and_db_commit() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();

    crate::wallet::rust_only::MOCK_FAIL_AFTER_STASH_CONSUME.with(|f| *f.borrow_mut() = true);
    assert!(matches!(
        party_send.wallet.consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Internal { details }) if details.contains("mock failure after stash consume")
    ));

    let marker = party_send
        .wallet
        .get_transfers_dir()
        .join(&txid)
        .join("stash_consumed");
    assert!(
        marker.exists(),
        "durable marker must exist after stash consume"
    );
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    // Retry finishes the SQL side without a second consume_fascia.
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(!marker.exists());
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

/// Once the fascia is in the stash, only the SQL side is still rollable back, so failing the batch
/// would diverge the two. The consume path now requires a broadcast first; the remaining crash
/// window is after `consume_fascia` and before the SQL commit, when both the indexer and the
/// durable marker tell `fail_transfers` to refuse.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fail_transfers_refused_after_stash_consume_before_sql_commit() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    broadcast_wallet_psbt(&party_send.wallet, &psbt);

    crate::wallet::rust_only::MOCK_FAIL_AFTER_STASH_CONSUME.with(|f| *f.borrow_mut() = true);
    assert!(matches!(
        party_send.wallet.consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Internal { details }) if details.contains("mock failure after stash consume")
    ));
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    let result = party_send.fail_transfers(Some(batch_transfer_idx), false, false);
    assert!(matches!(result, Err(Error::CannotFailBatchTransfer)));

    // the batch stays untouched, so the interrupted consume can still be completed
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));
    party_send
        .wallet
        .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx)
        .unwrap();
    assert!(
        party_send.check_test_transfer_status_sender(&txid, TransferStatus::WaitingConfirmations)
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_projects_change_for_wallet_owned_output() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let allocated: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint
        .into();

    // Self-send: RGB destination is a wallet-owned script → Change coloring, not Burn.
    let self_address = BdkAddress::from_str(&party_send.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            self_address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let transfers = party_send.list_transfers(Some(&asset.asset_id));
    let initiated = transfers
        .iter()
        .find(|t| t.status == TransferStatus::Initiated && t.kind == TransferKind::Send)
        .expect("self-send color transfer must be Send, not Burn");
    assert!(initiated.recipient_id.is_some());

    let asset_transfers = party_send.db_asset_transfers_filtered(batch_transfer_idx);
    assert_eq!(asset_transfers.len(), 1);
    let colorings = party_send.db_colorings_filtered(asset_transfers[0].idx);
    assert!(colorings.iter().any(|c| c.r#type == ColoringType::Input));
    let change = colorings
        .iter()
        .find(|c| c.r#type == ColoringType::Change)
        .expect("wallet-owned output_map vout must project Change");
    assert_eq!(change.assignment, Assignment::Fungible(AMOUNT));

    let change_txo = party_send
        .db_txos()
        .into_iter()
        .find(|t| t.idx == change.txo_idx)
        .unwrap();
    assert_eq!(change_txo.vout, vout);
    assert_eq!(change_txo.txid, psbt.unsigned_tx.compute_txid().to_string());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_uda_change_is_non_fungible() {
    initialize();

    let amt_sat = 500;

    let mut party_send = get_funded_noutxo_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset = party_send.issue_asset_uda(None, None, vec![]);

    let allocated: OutPoint = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint
        .into();

    let self_address = BdkAddress::from_str(&party_send.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            self_address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(&asset.asset_id, HashMap::from([(vout, 1)]), 777);

    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let asset_transfers = party_send.db_asset_transfers_filtered(batch_transfer_idx);
    assert_eq!(asset_transfers.len(), 1);
    let colorings = party_send.db_colorings_filtered(asset_transfers[0].idx);
    let change = colorings
        .iter()
        .find(|c| c.r#type == ColoringType::Change)
        .expect("UDA self-send must project Change");
    assert_eq!(
        change.assignment,
        Assignment::NonFungible,
        "UDA Change must not be stored as Fungible(1)"
    );
    let xfers = party_send.db_transfers_filtered(asset_transfers[0].idx);
    assert_eq!(xfers.len(), 1);
    assert_eq!(xfers[0].requested_assignment, Some(Assignment::NonFungible));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_multi_contract_inputs_and_send() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    let asset_a = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_b = party_send.issue_asset_cfa(Some(&[AMOUNT]), None);

    let allocated: Vec<OutPoint> = party_send
        .list_unspents(true)
        .into_iter()
        .filter(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .map(|u| u.utxo.outpoint.into())
        .collect();
    assert!(allocated.len() >= 2);

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated[0]).unwrap();
    tx_builder.add_utxo(allocated[1]).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);

    let inputs: Vec<_> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|i| i.previous_output)
        .collect();
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;

    let mut asset_info_map = HashMap::new();
    for asset_id in [&asset_a.asset_id, &asset_b.asset_id] {
        asset_info_map.insert(
            ContractId::from_str(asset_id).unwrap(),
            AssetColoringInfo {
                output_map: HashMap::from([(vout, AMOUNT)]),
                static_blinding: Some(blinding),
            },
        );
    }
    let coloring_info = ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    };

    let ColorPrepareResult {
        batch_transfer_idx,
        transfers,
    } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            inputs,
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    assert_eq!(transfers.len(), 2);

    let asset_transfers = party_send.db_asset_transfers_filtered(batch_transfer_idx);
    assert_eq!(asset_transfers.len(), 2);
    for at in &asset_transfers {
        let colorings = party_send.db_colorings_filtered(at.idx);
        assert!(
            colorings.iter().any(|c| c.r#type == ColoringType::Input),
            "each contract needs Input coloring"
        );
        assert!(!colorings.iter().any(|c| c.r#type == ColoringType::Change));
        let xfers = party_send.db_transfers_filtered(at.idx);
        assert_eq!(xfers.len(), 1);
        assert!(xfers[0].recipient_id.is_some());
    }

    for asset_id in [&asset_a.asset_id, &asset_b.asset_id] {
        let kind = party_send
            .list_transfers(Some(asset_id))
            .into_iter()
            .find(|t| t.status == TransferStatus::Initiated)
            .unwrap()
            .kind;
        assert_eq!(kind, TransferKind::Send);
    }

    assert_eq!(
        party_send
            .db_txos()
            .iter()
            .filter(|t| t.txid == psbt.unsigned_tx.compute_txid().to_string() && t.vout == vout)
            .count(),
        0,
        "foreign recipient output must not be inserted as wallet TXO"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_persist_updates_backup_info() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let bak_before = party_send.db_backup_info();
    party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let bak_after = party_send.db_backup_info();
    assert!(
        bak_after.last_operation_timestamp.parse::<i128>().unwrap()
            > bak_before.last_operation_timestamp.parse::<i128>().unwrap()
    );
    assert!(party_send.wallet.backup_info().unwrap());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_abort_from_prepared_marks_failed() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let HtlcPrepareResult { operation_id, .. } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    let online = party_send.party_online();
    party_send.wallet.htlc_abort(online, &operation_id).unwrap();

    assert_eq!(
        party_send.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Failed
    );
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Failed));

    let rows = party_send
        .wallet
        .contract_assignments_for_outpoints(contract_id, vec![input.into()])
        .unwrap();
    assert!(!rows[0].1.is_empty());
}

/// A second live batch for the same txid would reserve the same inputs twice and leave the
/// txid-based batch recovery ambiguous, so registering one has to be refused.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_prepare_rejects_second_live_batch_for_same_txid() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    // Preparing leaves the stash untouched and the coloring uses a static blinding, so the same
    // PSBT prepared twice commits to the same witness txid.
    let mut retried_psbt = psbt.clone();
    party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info.clone(),
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    let result = party_send.wallet.htlc_prepare(
        &mut retried_psbt,
        coloring_info,
        vec![input],
        MIN_CONFIRMATIONS,
        None,
    );
    assert_eq!(retried_psbt.unsigned_tx.compute_txid().to_string(), txid);
    assert_matches!(
        result,
        Err(Error::BatchTransferAlreadyExists { txid: ref t, .. }) if *t == txid
    );
}

/// `htlc_apply` must not consume RGB state until the indexer can see the witness TX, otherwise
/// there is no safe abort path.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_apply_refused_before_broadcast() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let HtlcPrepareResult { operation_id, .. } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let online = party_send.party_online();
    assert!(matches!(
        party_send.wallet.htlc_apply(online, &operation_id),
        Err(Error::InvalidHtlcOperationStatus { details })
            if details.contains("not known to the indexer")
    ));
    assert_eq!(
        party_send.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Prepared
    );

    // abort is still the way out: the stash was never consumed
    party_send
        .wallet
        .htlc_abort(party_send.party_online(), &operation_id)
        .unwrap();
    assert_eq!(
        party_send.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Failed
    );
}

/// `consume_transfer_fascia` must not consume RGB state until the indexer can see the witness TX,
/// otherwise there is no safe `fail_transfers` path.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_refused_before_broadcast() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult {
        batch_transfer_idx, ..
    } = party_send
        .wallet
        .color_psbt_and_prepare_consume(&mut psbt, coloring_info, MIN_CONFIRMATIONS, None)
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();

    assert!(matches!(
        party_send
            .wallet
            .consume_transfer_fascia(party_send.party_online(), batch_transfer_idx),
        Err(Error::Internal { details })
            if details.contains("not known to the indexer")
    ));
    assert!(party_send.check_test_transfer_status_sender(&txid, TransferStatus::Initiated));

    // fail_transfers is still the way out: the stash was never consumed
    assert!(party_send.fail_transfers_single(batch_transfer_idx));
}

/// `consume_transfer_fascia` is only for batches created by `color_psbt_*_and_prepare_consume`.
/// A `send_begin` batch writes fascia to the same transfer dir but must still go through `send_end`.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn consume_transfer_fascia_rejects_send_begin_batch() {
    initialize();

    let mut party = get_funded_party!();
    let mut rcv_party = get_funded_party!();

    let asset = party.issue_asset_nia(None);
    let receive_data = rcv_party.blind_receive_asset_expiry(None, None);
    let recipient_map = HashMap::from([(
        asset.asset_id.clone(),
        vec![Recipient {
            assignment: Assignment::Fungible(10),
            recipient_id: receive_data.recipient_id.clone(),
            witness_data: None,
            transport_endpoints: TRANSPORT_ENDPOINTS.clone(),
        }],
    )]);
    let begin = party.send_begin_result(&recipient_map).unwrap();
    let batch_transfer_idx = begin.batch_transfer_idx.unwrap();

    assert!(matches!(
        party
            .wallet
            .consume_transfer_fascia(party.party_online(), batch_transfer_idx),
        Err(Error::Internal { details })
            if details.contains("was not created by color_psbt_*_and_prepare_consume")
    ));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn htlc_prepare_apply_round_trip() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let HtlcPrepareResult {
        operation_id,
        operation_dir,
        ..
    } = party_send
        .wallet
        .htlc_prepare(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let op_dir = party_send.wallet.get_wallet_dir().join(&operation_dir);
    let consignment_path = std::fs::read_dir(op_dir.join("consignments"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    party_send
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            txid.clone(),
            consignment_path,
            txid.clone(),
            Some(vout),
        )
        .unwrap();

    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();

    party_send
        .wallet
        .htlc_apply(party_send.party_online(), &operation_id)
        .unwrap();
    assert_eq!(
        party_send.wallet.htlc_reconcile(&operation_id).unwrap(),
        HtlcOperationStatus::Applied
    );

    let recv_online = recv_party.party_online();
    recv_party
        .wallet
        .accept_transfer(recv_online, txid, vout, &PROXY_ENDPOINT, blinding)
        .unwrap();
}

/// `rebuild_psbt_preserving_maps(.., false)`: no P2TR ⇒ OP_RETURN appended; original output maps
/// must stay at the same indices (unlike the P2TR front-insert / skip(1) path).
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_appends_opreturn_without_p2tr_preserves_output_maps() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    // Same funding shape as `success` (1 colored UTXO, BTC drained) but P2WPKH so color_psbt
    // takes the append path. Destination must also be P2WPKH — a taproot recipient would flip
    // onto the front-insert / +1-shift path.
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::SegWitV0);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let mut wallet = get_test_wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
    let online = wallet.go_online(test_go_online_options(None)).unwrap();
    let mut party_send = party!(wallet, online);
    fund_wallet(party_send.get_address());
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);

    let mnemonic = Mnemonic::parse_in(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let xprv = Xpriv::new_master(BdkNetwork::Regtest, &mnemonic.to_seed("")).unwrap();
    let custom_bdk_wallet =
        BdkWallet::create(format!("wpkh({xprv}/0/*)"), format!("wpkh({xprv}/1/*)"))
            .network(BdkNetwork::Regtest)
            .create_wallet_no_persist()
            .unwrap();
    let p2wpkh_addr = custom_bdk_wallet
        .peek_address(KeychainKind::External, 0)
        .address;
    party_send.send_btc(&p2wpkh_addr.to_string(), 99_998_200);

    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(p2wpkh_addr.script_pubkey(), BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr() || o.script_pubkey.is_op_return()),
        "fixture must be no-P2TR and no OP_RETURN so color_psbt takes the append rebuild branch"
    );

    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );
    stamp_output_map_sentinels(&mut psbt);
    let psbt_before = psbt.clone();
    party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info)
        .unwrap();

    assert!(
        psbt.unsigned_tx
            .output
            .last()
            .unwrap()
            .script_pubkey
            .is_op_return()
    );
    assert_output_maps_preserved(&psbt_before, &psbt);
}

/// Legacy `color_psbt` P2TR / `OpretFirst` indexing: with a pre-inserted OP_RETURN at vout 0,
/// keys are still pre-OP_RETURN indices and get +1 (same as when this method inserts OP_RETURN).
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_existing_op_return_with_p2tr_uses_legacy_vout_shift() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr()),
        "test wallet must produce P2TR outputs"
    );
    let output_count_before = psbt.unsigned_tx.output.len();
    // Pre-existing OP_RETURN at vout 0 + P2TR: legacy still applies +1 to output_map keys.
    insert_op_return(&mut psbt, true);
    assert_eq!(psbt.unsigned_tx.output.len(), output_count_before + 1);
    assert!(psbt.unsigned_tx.output[0].script_pubkey.is_op_return());
    let witness_utxo_before = psbt.inputs[0].witness_utxo.clone();
    let tap_internal_key_before = psbt.inputs[0].tap_internal_key;
    assert!(witness_utxo_before.is_some());

    let final_recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    assert_ne!(
        final_recipient_vout, 0,
        "recipient must not be the OP_RETURN vout"
    );
    let pre_opreturn_vout = final_recipient_vout - 1;

    // Passing a final index under the legacy +1 shift seals the next output (or fails OOB).
    let mut psbt_final = psbt.clone();
    let final_index_coloring = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(final_recipient_vout, AMOUNT)]),
        blinding,
    );
    match party_send
        .wallet
        .color_psbt(&mut psbt_final, final_index_coloring)
    {
        Err(Error::InvalidColoringInfo { .. }) => {}
        Ok((fascia, _)) => {
            let (_, bundle) = fascia.bundles().iter().next().unwrap();
            let seal = bundle
                .known_transitions
                .iter()
                .next()
                .unwrap()
                .transition
                .assignments
                .iter()
                .next()
                .unwrap()
                .1
                .as_fungible()
                .first()
                .unwrap()
                .revealed_seal()
                .unwrap();
            assert_eq!(seal.vout.into_u32(), final_recipient_vout + 1);
        }
        Err(e) => panic!("unexpected error: {e}"),
    }

    // Pre-OP_RETURN index (legacy): +1 lands on the recipient.
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(pre_opreturn_vout, AMOUNT)]),
        blinding,
    );
    let (fascia, beneficiaries) = party_send
        .wallet
        .color_psbt(&mut psbt, coloring_info)
        .unwrap();
    assert_eq!(
        psbt.unsigned_tx.output.len(),
        output_count_before + 1,
        "must not insert a second OP_RETURN"
    );
    assert_eq!(psbt.inputs[0].witness_utxo, witness_utxo_before);
    assert_eq!(psbt.inputs[0].tap_internal_key, tap_internal_key_before);

    let (_cid, bundle) = fascia.bundles().iter().next().unwrap();
    let transition = bundle
        .known_transitions
        .iter()
        .next()
        .unwrap()
        .transition
        .clone();
    let (_, fungible) = transition.assignments.iter().next().unwrap();
    let seal = fungible
        .as_fungible()
        .first()
        .unwrap()
        .revealed_seal()
        .unwrap();
    assert_eq!(seal.vout.into_u32(), final_recipient_vout);
    assert_eq!(seal.blinding, blinding);

    let (_cid, seals) = beneficiaries.first_key_value().unwrap();
    let seal = match seals.first().unwrap() {
        BuilderSeal::Revealed(r) => r,
        BuilderSeal::Concealed(_) => panic!("revealed expected"),
    };
    assert_eq!(seal.vout.into_u32(), final_recipient_vout);
}

/// With P2TR + pre-existing OP_RETURN at index > 0, legacy +1 would silently mis-seal.
/// Reject instead (same rule as `color_psbt_for_outpoints`); do not change the vout-0 legacy path.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_rejects_opreturn_not_first_when_p2tr() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr()),
        "test wallet must produce P2TR outputs"
    );
    insert_op_return(&mut psbt, false);
    let op_return_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| o.script_pubkey.is_op_return())
        .unwrap();
    assert_ne!(
        op_return_vout, 0,
        "fixture must place OP_RETURN after vout 0"
    );

    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );
    let result = party_send.wallet.color_psbt(&mut psbt, coloring_info);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "OP_RETURN must be the first PSBT output"
    );
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
fn broadcast_wallet_psbt(wallet: &Wallet, psbt: &Psbt) {
    let signed_psbt = wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    wallet.broadcast_tx(tx).unwrap();
}

/// 1-of-1 bare CHECKMULTISIG: not P2PKH / P2SH / P2WPKH / P2WSH / P2TR.
fn bare_multisig_script() -> ScriptBuf {
    let mut bytes = vec![0x51, 0x21, 0x02];
    bytes.extend([0x11u8; 32]);
    bytes.extend([0x51, 0xae]);
    ScriptBuf::from_bytes(bytes)
}

fn insert_op_return(psbt: &mut Psbt, at_front: bool) {
    let txout = TxOut {
        value: BdkAmount::ZERO,
        script_pubkey: ScriptBuf::new_op_return([]),
    };
    let map = bdk_wallet::bitcoin::psbt::Output::default();
    if at_front {
        psbt.unsigned_tx.output.insert(0, txout);
        psbt.outputs.insert(0, map);
    } else {
        psbt.unsigned_tx.output.push(txout);
        psbt.outputs.push(map);
    }
}

/// Prepend a non-wallet (e.g. HTLC escrow) input to an already-built PSBT.
///
/// `non_witness_utxo` is the full previous transaction. BDK's default `SignOptions` reject
/// signing when a non-taproot (or taproot without `tap_internal_key`) input has only
/// `witness_utxo`.
fn prepend_psbt_input(
    psbt: &mut Psbt,
    previous_output: OutPoint,
    witness_utxo: Option<TxOut>,
    non_witness_utxo: Option<bitcoin::Transaction>,
) {
    psbt.unsigned_tx.input.insert(
        0,
        bitcoin::TxIn {
            previous_output,
            script_sig: Default::default(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Default::default(),
        },
    );
    let input = bdk_wallet::bitcoin::psbt::Input {
        witness_utxo,
        non_witness_utxo,
        ..Default::default()
    };
    psbt.inputs.insert(0, input);
}

/// Proprietary marker used to verify `rebuild_psbt_preserving_maps` keeps per-output maps aligned.
/// Prefer this over bip32/tap origins: RGB coloring may touch those after the rebuild.
fn output_map_sentinel_key() -> bitcoin::psbt::raw::ProprietaryKey {
    bitcoin::psbt::raw::ProprietaryKey {
        prefix: b"rgb-lib-test".to_vec(),
        subtype: 0x7A,
        key: vec![0x01],
    }
}

fn stamp_output_map_sentinels(psbt: &mut Psbt) {
    let key = output_map_sentinel_key();
    for (i, out) in psbt.outputs.iter_mut().enumerate() {
        out.proprietary.insert(key.clone(), vec![i as u8]);
    }
}

/// Assert PSBT output maps survive a rebuild that inserts `offset` outputs at the front
/// (`rebuild_psbt_preserving_maps(.., true)` uses `skip(offset)`).
fn assert_output_maps_offset_by(before: &Psbt, after: &Psbt, offset: usize) {
    let key = output_map_sentinel_key();
    assert_eq!(after.outputs.len(), before.outputs.len() + offset);
    assert!(
        before
            .outputs
            .iter()
            .any(|o| o.proprietary.contains_key(&key)),
        "expected stamped output-map sentinels before coloring"
    );
    for i in 0..offset {
        assert!(
            !after.outputs[i].proprietary.contains_key(&key),
            "inserted output {i} must not carry maps from a shifted original"
        );
    }
    for (i, out_before) in before.outputs.iter().enumerate() {
        assert_eq!(
            after.outputs[i + offset].proprietary.get(&key),
            out_before.proprietary.get(&key),
            "output-map sentinel mismatch at shifted output {}",
            i + offset
        );
    }
}

/// Assert PSBT output maps survive a rebuild that appends outputs (`opreturn_first = false`).
fn assert_output_maps_preserved(before: &Psbt, after: &Psbt) {
    let key = output_map_sentinel_key();
    assert!(after.outputs.len() >= before.outputs.len());
    assert!(
        before
            .outputs
            .iter()
            .any(|o| o.proprietary.contains_key(&key)),
        "expected stamped output-map sentinels before coloring"
    );
    for (i, out_before) in before.outputs.iter().enumerate() {
        assert_eq!(
            after.outputs[i].proprietary.get(&key),
            out_before.proprietary.get(&key),
            "output-map sentinel mismatch at output {i}"
        );
    }
}

fn coloring_info_for(asset_id: &str, output_map: HashMap<u32, u64>, blinding: u64) -> ColoringInfo {
    let asset_coloring_info = AssetColoringInfo {
        output_map,
        static_blinding: Some(blinding),
    };
    let asset_info_map =
        HashMap::from_iter([(ContractId::from_str(asset_id).unwrap(), asset_coloring_info)]);
    ColoringInfo {
        asset_info_map,
        static_blinding: Some(blinding),
        nonce: None,
    }
}

fn expected_nia(asset_id: &str, amount: u64) -> ExpectedTransfer {
    ExpectedTransfer {
        asset_id: asset_id.to_string(),
        asset_schema: AssetSchema::Nia,
        assignment: Assignment::Fungible(amount),
    }
}

/// Broadcast (and optionally mine) a colored witness transfer posted to the proxy under `txid`.
#[cfg(feature = "electrum")]
fn setup_fetch_accept_pin_fixture(
    mine_after: bool,
) -> (
    SinglesigParty,
    SinglesigParty,
    String,
    String,
    ScriptBuf,
    &'static str,
    u64,
    PathBuf,
) {
    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let recipient_script = address.assume_checked().script_pubkey();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(recipient_script.clone(), BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult { transfers, .. } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfers_dir = party_send.wallet.get_transfers_dir().join(&txid);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    transfers
        .first()
        .unwrap()
        .save_file(&consignment_path)
        .unwrap();
    party_send
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            txid.clone(),
            consignment_path.clone(),
            txid.clone(),
            Some(vout),
        )
        .unwrap();

    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();
    if mine_after {
        mine(false);
    }

    (
        party_send,
        recv_party,
        asset.asset_id,
        txid,
        recipient_script,
        PROXY_ENDPOINT.as_str(),
        blinding,
        consignment_path,
    )
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_fail() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    output_map.insert(output.0 as u32, AMOUNT);
    let coloring_info = coloring_info_for(&asset.asset_id, output_map, blinding);

    let result =
        party_send
            .wallet
            .color_psbt_for_outpoints(&mut psbt, coloring_info.clone(), vec![]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m }) if m == "input_outpoints is empty"
    );

    let missing = OutPoint::from_str(FAKE_OUTPOINT).unwrap();
    let result =
        party_send
            .wallet
            .color_psbt_for_outpoints(&mut psbt, coloring_info.clone(), vec![missing]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "input_outpoints must be a subset of PSBT inputs"
    );

    let result =
        party_send
            .wallet
            .color_psbt_for_outpoints(&mut psbt, coloring_info.clone(), vec![input]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "PSBT must include an OP_RETURN output"
    );

    insert_op_return(&mut psbt, false);
    assert!(
        psbt.unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr()),
        "test wallet must produce P2TR outputs for OpretFirst validation"
    );
    let result = party_send
        .wallet
        .color_psbt_for_outpoints(&mut psbt, coloring_info, vec![input]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "OP_RETURN must be the first PSBT output"
    );

    insert_op_return(&mut psbt, true);
    let op_return_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| o.script_pubkey.is_op_return())
        .unwrap() as u32;
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(op_return_vout, AMOUNT)]),
        blinding,
    );
    let result = party_send
        .wallet
        .color_psbt_for_outpoints(&mut psbt, coloring_info, vec![input]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == format!("output_map vout {op_return_vout} points to the OP_RETURN output")
    );
}

/// Coloring itself does not inspect the destination script, but persist has to encode a witness
/// recipient ID. A bare-multisig output is not an AddressPayload and must fail closed.
#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_and_prepare_consume_rejects_nonstandard_output_script() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    psbt.unsigned_tx.output[vout as usize].script_pubkey = bare_multisig_script();
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);

    let result = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == format!("output_map vout {vout} script is not a standard address payload")
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_rejects_omitted_allocations() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_997_000);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT, AMOUNT]));

    let allocated: Vec<OutPoint> = party_send
        .list_unspents(true)
        .into_iter()
        .filter(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .map(|u| u.utxo.outpoint.into())
        .collect();
    assert!(allocated.len() >= 2);

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated[0]).unwrap();
    tx_builder.add_utxo(allocated[1]).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);

    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    output_map.insert(output.0 as u32, AMOUNT);
    let coloring_info = coloring_info_for(&asset.asset_id, output_map, blinding);

    let result =
        party_send
            .wallet
            .color_psbt_for_outpoints(&mut psbt, coloring_info, vec![allocated[0]]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.contains("PSBT inputs omitted from input_outpoints carry RGB allocations")
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_rejects_uncolored_allocations() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(2), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_997_000);
    let asset_a = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let asset_b = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let mut allocated: Vec<OutPoint> = party_send
        .list_unspents(true)
        .into_iter()
        .filter(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .map(|u| u.utxo.outpoint.into())
        .collect();
    allocated.sort_by_key(|o| (o.txid, o.vout));
    allocated.dedup();
    assert!(allocated.len() >= 2);

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder.add_utxo(allocated[0]).unwrap();
    tx_builder.add_utxo(allocated[1]).unwrap();
    tx_builder.manually_selected_only();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);

    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    output_map.insert(output.0 as u32, AMOUNT);
    let coloring_info = coloring_info_for(&asset_a.asset_id, output_map, blinding);

    let result = party_send.wallet.color_psbt_for_outpoints(
        &mut psbt,
        coloring_info,
        vec![allocated[0], allocated[1]],
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.contains("contracts not listed in coloring_info")
                && m.contains(&asset_b.asset_id)
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_rejects_signed_psbt_with_existing_op_return() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);

    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    output_map.insert(output.0 as u32, AMOUNT);
    let coloring_info = coloring_info_for(&asset.asset_id, output_map, blinding);

    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let mut signed_psbt = Psbt::from_str(&signed_psbt).unwrap();
    let result = party_send
        .wallet
        .color_psbt(&mut signed_psbt, coloring_info.clone());
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
    );

    let input = psbt.unsigned_tx.input[0].previous_output;
    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let mut signed_psbt = Psbt::from_str(&signed_psbt).unwrap();
    let result =
        party_send
            .wallet
            .color_psbt_for_outpoints(&mut signed_psbt, coloring_info, vec![input]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_preserves_metadata_and_prepare_consume() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);
    let input = psbt.unsigned_tx.input[0].previous_output;
    let witness_utxo_before = psbt.inputs[0].witness_utxo.clone();
    let tap_internal_key_before = psbt.inputs[0].tap_internal_key;
    assert!(witness_utxo_before.is_some());

    let mut output_map = HashMap::new();
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    let vout = output.0 as u32;
    output_map.insert(vout, AMOUNT);
    let coloring_info = coloring_info_for(&asset.asset_id, output_map, blinding);

    let ColorPrepareResult { transfers, .. } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    assert_eq!(psbt.inputs[0].witness_utxo, witness_utxo_before);
    assert_eq!(psbt.inputs[0].tap_internal_key, tap_internal_key_before);
    assert_eq!(transfers.len(), 1);

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfer = transfers.into_iter().next().unwrap();
    let recv_online = recv_party.party_online();
    recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer,
            txid,
            vout,
            blinding,
            expected_nia(&asset.asset_id, AMOUNT),
        )
        .unwrap();
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn contract_assignments_for_outpoints_includes_empty() {
    initialize();

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let allocated = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint;
    let empty = Outpoint {
        txid: FAKE_TXID.to_string(),
        vout: 0,
    };
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();
    let rows = party_send
        .wallet
        .contract_assignments_for_outpoints(contract_id, vec![allocated.clone(), empty.clone()])
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, allocated);
    assert!(!rows[0].1.is_empty());
    assert_eq!(rows[1].0, empty);
    assert!(rows[1].1.is_empty());

    let mut uppercase = allocated.clone();
    uppercase.txid = uppercase.txid.to_uppercase();
    let rows = party_send
        .wallet
        .contract_assignments_for_outpoints(contract_id, vec![uppercase.clone()])
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, uppercase);
    assert!(!rows[0].1.is_empty());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_rejects_under_allocation() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);
    let input = psbt.unsigned_tx.input[0].previous_output;
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(output.0 as u32, AMOUNT / 2)]),
        blinding,
    );
    let result = party_send
        .wallet
        .color_psbt_for_outpoints(&mut psbt, coloring_info, vec![input]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m.contains("less than available") && m.contains("full allocation required")
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn contract_assignments_for_outpoints_unknown_contract() {
    initialize();

    let mut party_send = get_funded_noutxo_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let allocated = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint;
    let fake_cid =
        ContractId::from_str("rgb:Ar4ouaLv-b7f7Dc_-z5EMvtu-FA5KNh1-nlae~jk-8xMBo7E").unwrap();
    let result = party_send.wallet.contract_assignments_for_outpoints(
        fake_cid,
        vec![Outpoint {
            txid: allocated.txid,
            vout: allocated.vout,
        }],
    );
    assert_matches!(
        result,
        Err(Error::AssetNotFound { asset_id }) if asset_id == fake_cid.to_string()
    );

    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();
    let result = party_send.wallet.contract_assignments_for_outpoints(
        contract_id,
        vec![Outpoint {
            txid: "not-a-txid".into(),
            vout: 0,
        }],
    );
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fetch_consignment_by_recipient_id_unchecked_success() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let recipient_script = address.assume_checked().script_pubkey();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(recipient_script.clone(), BdkAmount::from_sat(amt_sat))
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    let input = psbt.unsigned_tx.input[0].previous_output;
    insert_op_return(&mut psbt, true);
    let output = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap();
    let vout = output.0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult { transfers, .. } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfers_dir = party_send.wallet.get_transfers_dir().join(&txid);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    transfers
        .first()
        .unwrap()
        .save_file(&consignment_path)
        .unwrap();
    party_send
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            txid.clone(),
            consignment_path,
            txid.clone(),
            Some(vout),
        )
        .unwrap();

    let (transfer, fetched_txid, fetched_vout) = party_send
        .wallet
        .fetch_consignment_by_recipient_id_unchecked(txid.clone(), &PROXY_ENDPOINT)
        .unwrap();
    assert_eq!(fetched_txid, txid);
    assert_eq!(fetched_vout, vout);
    let mut expected_bytes = vec![];
    transfers
        .first()
        .unwrap()
        .save(&mut expected_bytes)
        .unwrap();
    let mut fetched_bytes = vec![];
    transfer.save(&mut fetched_bytes).unwrap();
    assert_eq!(expected_bytes, fetched_bytes);

    let signed_psbt = party_send.wallet.sign_psbt(psbt.to_string(), None).unwrap();
    let finalized_psbt = party_send.wallet.finalize_psbt(signed_psbt, None).unwrap();
    let tx = Psbt::from_str(&finalized_psbt)
        .unwrap()
        .extract_tx()
        .expect("valid tx");
    party_send.wallet.broadcast_tx(tx).unwrap();
    mine(false);

    let witness_recipient_id =
        recipient_id_from_script_buf(recipient_script, BitcoinNetwork::Regtest).unwrap();
    let recv_online = recv_party.party_online();
    let (_accepted, assignments) = recv_party
        .wallet
        .fetch_and_accept_transfer_by_recipient_id(
            recv_online,
            txid.clone(),
            witness_recipient_id,
            &PROXY_ENDPOINT,
            blinding,
            MIN_CONFIRMATIONS,
            expected_nia(&asset.asset_id, AMOUNT),
        )
        .unwrap();
    assert_eq!(assignments, vec![Assignment::Fungible(AMOUNT)]);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fetch_and_accept_pin_rejects_mismatch_blinded_and_oor_vout() {
    initialize();

    let (
        mut party_send,
        mut recv_party,
        asset_id,
        txid,
        recipient_script,
        consignment_endpoint,
        blinding,
        consignment_path,
    ) = setup_fetch_accept_pin_fixture(true);

    let expected = expected_nia(&asset_id, AMOUNT);
    let recv_online = recv_party.party_online();
    let correct_witness_recipient_id =
        recipient_id_from_script_buf(recipient_script.clone(), BitcoinNetwork::Regtest).unwrap();

    // Wrong chain-net prefix (mainnet ID, regtest wallet) even if script bytes would match
    let mainnet_witness_recipient_id =
        recipient_id_from_script_buf(recipient_script.clone(), BitcoinNetwork::Mainnet).unwrap();
    let result = recv_party.wallet.fetch_and_accept_transfer_by_recipient_id(
        recv_online,
        txid.clone(),
        mainnet_witness_recipient_id,
        consignment_endpoint,
        blinding,
        MIN_CONFIRMATIONS,
        expected.clone(),
    );
    assert_matches!(result, Err(Error::InvalidRecipientNetwork));

    // (a) malicious proxy / wrong script: another party's address does not match output[vout]
    let wrong_script = BdkAddress::from_str(&party_send.get_address())
        .unwrap()
        .assume_checked()
        .script_pubkey();
    let wrong_witness_recipient_id =
        recipient_id_from_script_buf(wrong_script, BitcoinNetwork::Regtest).unwrap();
    let result = recv_party.wallet.fetch_and_accept_transfer_by_recipient_id(
        recv_online,
        txid.clone(),
        wrong_witness_recipient_id,
        consignment_endpoint,
        blinding,
        MIN_CONFIRMATIONS,
        expected.clone(),
    );
    assert_matches!(
        result,
        Err(Error::WitnessOutputMismatch { details: m })
            if m.contains("witness output script does not match")
    );

    // (b) blinded recipient IDs cannot be pinned
    let blinded_recipient_id =
        "bcrt:utxob:tjVmHbI2-U0_umHn-bU4cmP6-l3VW00H-ewoi2uz-XZG6O3i-wUFBW".to_string();
    assert!(
        script_buf_from_recipient_id(blinded_recipient_id.clone())
            .unwrap()
            .is_none()
    );
    let result = recv_party.wallet.fetch_and_accept_transfer_by_recipient_id(
        recv_online,
        txid.clone(),
        blinded_recipient_id,
        consignment_endpoint,
        blinding,
        MIN_CONFIRMATIONS,
        expected.clone(),
    );
    assert_matches!(result, Err(Error::InvalidRecipientID));

    // (d) proxy returns a vout past the end of the witness TX
    let bad_proxy_id = format!("{txid}-oor-vout");
    party_send
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            bad_proxy_id.clone(),
            consignment_path,
            txid,
            Some(999),
        )
        .unwrap();
    let result = recv_party.wallet.fetch_and_accept_transfer_by_recipient_id(
        recv_online,
        bad_proxy_id,
        correct_witness_recipient_id,
        consignment_endpoint,
        blinding,
        MIN_CONFIRMATIONS,
        expected,
    );
    assert_matches!(
        result,
        Err(Error::WitnessOutputMismatch { details: m })
            if m.contains("out of range")
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fetch_and_accept_rejects_unconfirmed_then_accepts_after_mine() {
    initialize();

    let (
        _party_send,
        mut recv_party,
        asset_id,
        txid,
        recipient_script,
        consignment_endpoint,
        blinding,
        _,
    ) = setup_fetch_accept_pin_fixture(false);
    let witness_recipient_id =
        recipient_id_from_script_buf(recipient_script, BitcoinNetwork::Regtest).unwrap();
    let expected = expected_nia(&asset_id, AMOUNT);
    let recv_online = recv_party.party_online();

    let result = recv_party.wallet.fetch_and_accept_transfer_by_recipient_id(
        recv_online,
        txid.clone(),
        witness_recipient_id.clone(),
        consignment_endpoint,
        blinding,
        1,
        expected.clone(),
    );
    assert_matches!(
        result,
        Err(Error::InsufficientConfirmations { needed: 1, got: 0 })
    );

    mine(false);

    let (_accepted, assignments) = recv_party
        .wallet
        .fetch_and_accept_transfer_by_recipient_id(
            recv_online,
            txid,
            witness_recipient_id,
            consignment_endpoint,
            blinding,
            1,
            expected,
        )
        .unwrap();
    assert_eq!(assignments, vec![Assignment::Fungible(AMOUNT)]);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fetch_and_accept_allows_mempool_when_min_confirmations_zero() {
    initialize();

    let (
        _party_send,
        mut recv_party,
        asset_id,
        txid,
        recipient_script,
        consignment_endpoint,
        blinding,
        _,
    ) = setup_fetch_accept_pin_fixture(false);
    let witness_recipient_id =
        recipient_id_from_script_buf(recipient_script, BitcoinNetwork::Regtest).unwrap();
    let recv_online = recv_party.party_online();

    let (_accepted, assignments) = recv_party
        .wallet
        .fetch_and_accept_transfer_by_recipient_id(
            recv_online,
            txid,
            witness_recipient_id,
            consignment_endpoint,
            blinding,
            0,
            expected_nia(&asset_id, AMOUNT),
        )
        .unwrap();
    assert_eq!(assignments, vec![Assignment::Fungible(AMOUNT)]);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn accept_transfer_from_consignment_unchecked_rejects_wrong_witness() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);
    let input = psbt.unsigned_tx.input[0].previous_output;
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult { transfers, .. } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfer = transfers.into_iter().next().unwrap();
    let expected = expected_nia(&asset.asset_id, AMOUNT);
    let recv_online = recv_party.party_online();

    let result = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer.clone(),
            s!("not-a-txid"),
            vout,
            blinding,
            expected.clone(),
        );
    assert_matches!(result, Err(Error::InvalidTxid));

    let result = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer.clone(),
            FAKE_TXID.to_string(),
            vout,
            blinding,
            expected.clone(),
        );
    assert_matches!(result, Err(Error::InvalidConsignment));

    // Wrong vout yields no seal assignments — rejected as unexpected transfer.
    let result = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer.clone(),
            txid.clone(),
            999,
            blinding,
            expected.clone(),
        );
    assert_matches!(
        result,
        Err(Error::UnexpectedTransfer { details: m }) if m.contains("no assignments")
    );

    // Wrong amount is rejected even when the consignment is otherwise valid.
    let result = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer.clone(),
            txid.clone(),
            vout,
            blinding,
            expected_nia(&asset.asset_id, AMOUNT - 1),
        );
    assert_matches!(
        result,
        Err(Error::UnexpectedTransfer { details: m }) if m.contains("assignment mismatch")
    );

    // Wrong contract id is rejected before accept.
    let result = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer.clone(),
            txid.clone(),
            vout,
            blinding,
            ExpectedTransfer {
                asset_id: FAKE_TXID.to_string(),
                asset_schema: AssetSchema::Nia,
                assignment: Assignment::Fungible(AMOUNT),
            },
        );
    assert_matches!(
        result,
        Err(Error::UnexpectedTransfer { details: m }) if m.contains("contract id mismatch")
    );

    // Wrong schema is rejected before accept.
    let result = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer.clone(),
            txid.clone(),
            vout,
            blinding,
            ExpectedTransfer {
                asset_id: asset.asset_id.clone(),
                asset_schema: AssetSchema::Cfa,
                assignment: Assignment::Fungible(AMOUNT),
            },
        );
    assert_matches!(
        result,
        Err(Error::UnexpectedTransfer { details: m }) if m.contains("schema mismatch")
    );

    // Assignment::Any is not a valid caller intent.
    let result = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer.clone(),
            txid.clone(),
            vout,
            blinding,
            ExpectedTransfer {
                asset_id: asset.asset_id.clone(),
                asset_schema: AssetSchema::Nia,
                assignment: Assignment::Any,
            },
        );
    assert_matches!(result, Err(Error::InvalidAssignment));

    let (_consignment, assignments) = recv_party
        .wallet
        .accept_transfer_from_consignment_unchecked(
            recv_online,
            transfer,
            txid,
            vout,
            blinding,
            expected,
        )
        .unwrap();
    assert_eq!(assignments, vec![Assignment::Fungible(AMOUNT)]);
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn fetch_consignment_by_recipient_id_unchecked_missing_vout() {
    initialize();

    let amt_sat = 500;
    let blinding = 777;

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let address = BdkAddress::from_str(&recv_party.get_address()).unwrap();
    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .add_recipient(
            address.assume_checked().script_pubkey(),
            BdkAmount::from_sat(amt_sat),
        )
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    insert_op_return(&mut psbt, true);
    let input = psbt.unsigned_tx.input[0].previous_output;
    let vout = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, o)| o.value.to_sat() == amt_sat)
        .unwrap()
        .0 as u32;
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(vout, AMOUNT)]), blinding);
    let ColorPrepareResult { transfers, .. } = party_send
        .wallet
        .color_psbt_for_outpoints_and_prepare_consume(
            &mut psbt,
            coloring_info,
            vec![input],
            MIN_CONFIRMATIONS,
            None,
        )
        .unwrap();

    let recipient_id = format!("{}-no-vout", psbt.unsigned_tx.compute_txid());
    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfers_dir = party_send.wallet.get_transfers_dir().join(&recipient_id);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    transfers
        .first()
        .unwrap()
        .save_file(&consignment_path)
        .unwrap();
    party_send
        .wallet
        .post_consignment_to_proxy(
            &get_proxy_client(None),
            recipient_id.clone(),
            consignment_path,
            txid,
            None,
        )
        .unwrap();

    let result = party_send
        .wallet
        .fetch_consignment_by_recipient_id_unchecked(recipient_id, &PROXY_ENDPOINT);
    assert_matches!(
        result,
        Err(Error::Internal { details: m })
            if m == "missing vout in consignment response"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn contract_assignments_for_outpoints_preserves_order_and_duplicates() {
    initialize();

    let mut party_send = get_funded_noutxo_party!();
    let mut recv_party = get_empty_party!();
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);
    party_send.send_btc(&recv_party.get_address(), 99_998_200);
    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));
    let allocated = party_send
        .list_unspents(true)
        .into_iter()
        .find(|u| u.utxo.colorable && !u.rgb_allocations.is_empty())
        .unwrap()
        .utxo
        .outpoint;
    let empty = Outpoint {
        txid: FAKE_TXID.to_string(),
        vout: 0,
    };
    let contract_id = ContractId::from_str(&asset.asset_id).unwrap();
    let rows = party_send
        .wallet
        .contract_assignments_for_outpoints(
            contract_id,
            vec![allocated.clone(), allocated.clone(), empty.clone()],
        )
        .unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].0, allocated);
    assert!(!rows[0].1.is_empty());
    assert_eq!(rows[1].0, allocated);
    assert!(!rows[1].1.is_empty());
    assert_eq!(rows[2].0, empty);
    assert!(rows[2].1.is_empty());
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_allows_opreturn_at_end_without_p2tr() {
    initialize();

    let blinding = 777;

    // Fully P2WPKH + one colored UTXO (BTC drained) so the PSBT input carries the asset and
    // outputs stay non-P2TR even after we append OP_RETURN.
    let keys = generate_keys(BitcoinNetwork::Regtest, WitnessVersion::SegWitV0);
    let wallet_keys = SinglesigKeys::from_keys(&keys, None);
    let mut wallet = get_test_wallet_raw(&wallet_keys, None, BitcoinNetwork::Regtest);
    let online = wallet.go_online(test_go_online_options(None)).unwrap();
    let mut party_send = party!(wallet, online);
    fund_wallet(party_send.get_address());
    party_send.create_utxos(false, Some(1), None, FEE_RATE, None);

    let mnemonic = Mnemonic::parse_in(
        Language::English,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let xprv = Xpriv::new_master(BdkNetwork::Regtest, &mnemonic.to_seed("")).unwrap();
    let custom_bdk_wallet =
        BdkWallet::create(format!("wpkh({xprv}/0/*)"), format!("wpkh({xprv}/1/*)"))
            .network(BdkNetwork::Regtest)
            .create_wallet_no_persist()
            .unwrap();
    let p2wpkh_addr = custom_bdk_wallet
        .peek_address(KeychainKind::External, 0)
        .address;
    party_send.send_btc(&p2wpkh_addr.to_string(), 99_998_200);

    let asset = party_send.issue_asset_nia(Some(&[AMOUNT]));

    let mut tx_builder = party_send.wallet.bdk_wallet_mut().build_tx();
    tx_builder
        .drain_wallet()
        .drain_to(p2wpkh_addr.script_pubkey())
        .fee_rate(FeeRate::from_sat_per_vb_u32(FEE_RATE as u32));
    let mut psbt = tx_builder.finish().unwrap();
    assert!(
        !psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr())
    );
    insert_op_return(&mut psbt, false);
    let input = psbt.unsigned_tx.input[0].previous_output;
    let recipient_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| !o.script_pubkey.is_op_return())
        .unwrap() as u32;
    assert!(
        psbt.unsigned_tx.output[recipient_vout as usize]
            .script_pubkey
            .is_p2wpkh()
    );
    let op_return_vout = psbt
        .unsigned_tx
        .output
        .iter()
        .position(|o| o.script_pubkey.is_op_return())
        .unwrap() as u32;
    assert_ne!(op_return_vout, 0);

    let coloring_info = coloring_info_for(
        &asset.asset_id,
        HashMap::from([(recipient_vout, AMOUNT)]),
        blinding,
    );
    party_send
        .wallet
        .color_psbt_for_outpoints(&mut psbt, coloring_info, vec![input])
        .unwrap();
}
