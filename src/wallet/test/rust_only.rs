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
    let mut psbt_copy = psbt.clone();
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

    // color PSBT and consume
    let transfers = party_send
        .wallet
        .color_psbt_and_consume(&mut psbt_copy, coloring_info)
        .unwrap();

    // check that the two color_psbt* methods produce matching PSBTs (no additional changes)
    assert_eq!(psbt, psbt_copy);

    // push consignment to proxy
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
    party_send
        .wallet
        .post_consignment(
            PROXY_URL,
            txid.clone(),
            consignment_path,
            txid.clone(),
            Some(vout),
        )
        .unwrap();

    // accept transfer
    let consignment_endpoint = RgbTransport::from_str(&PROXY_ENDPOINT).unwrap();
    recv_party
        .wallet
        .accept_transfer(txid.clone(), vout, consignment_endpoint, blinding)
        .unwrap();

    // consume fascia
    party_send.wallet.consume_fascia(fascia, None).unwrap();
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
    assert!(
        matches!(result, Err(Error::Internal { details: m }) if m.contains(&format!("contract {fake_cid} is unknown")))
    );

    // wrong output map vout
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
    let coloring_info =
        coloring_info_for(&asset.asset_id, HashMap::from([(op_return_vout, AMOUNT)]), blinding);
    let result = party_send
        .wallet
        .color_psbt_for_outpoints(&mut psbt, coloring_info, vec![input]);
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == format!("output_map vout {op_return_vout} points to the OP_RETURN output")
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
    let result = party_send.wallet.color_psbt_for_outpoints(
        &mut signed_psbt,
        coloring_info,
        vec![input],
    );
    assert_matches!(
        result,
        Err(Error::InvalidColoringInfo { details: m })
            if m == "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
    );
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn color_psbt_for_outpoints_preserves_metadata_and_consume() {
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

    let transfers = party_send
        .wallet
        .color_psbt_for_outpoints_and_consume(&mut psbt, coloring_info, vec![input])
        .unwrap();
    assert_eq!(psbt.inputs[0].witness_utxo, witness_utxo_before);
    assert_eq!(psbt.inputs[0].tap_internal_key, tap_internal_key_before);
    assert_eq!(transfers.len(), 1);

    let txid = psbt.unsigned_tx.compute_txid().to_string();
    let transfer = transfers.into_iter().next().unwrap();
    recv_party
        .wallet
        .accept_transfer_from_consignment(transfer, txid, vout, blinding)
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
    assert!(matches!(result, Err(Error::Internal { details: m }) if m.contains("contract rgb:")));

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
fn fetch_consignment_by_recipient_id_success() {
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
    let vout = output.0 as u32;
    output_map.insert(vout, AMOUNT);
    insert_op_return(&mut psbt, true);
    let coloring_info = coloring_info_for(&asset.asset_id, output_map, blinding);
    let transfers = party_send
        .wallet
        .color_psbt_for_outpoints_and_consume(&mut psbt, coloring_info, vec![input])
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
        .post_consignment(
            PROXY_URL,
            txid.clone(),
            consignment_path,
            txid.clone(),
            Some(vout),
        )
        .unwrap();

    let consignment_endpoint = RgbTransport::from_str(&PROXY_ENDPOINT).unwrap();
    let (transfer, fetched_txid, fetched_vout) = party_send
        .wallet
        .fetch_consignment_by_recipient_id(txid.clone(), consignment_endpoint)
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
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn post_consignment_fail() {
    initialize();

    // wallets
    let party = get_empty_party!();

    // fake data
    let fake_txid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let transfers_dir = party.wallet.get_transfers_dir().join(fake_txid);
    let consignment_path = transfers_dir.join(CONSIGNMENT_FILE);
    std::fs::create_dir_all(&transfers_dir).unwrap();
    std::fs::File::create(&consignment_path).unwrap();

    // proxy error
    let invalid_proxy_url = "http://127.6.6.6:7777/json-rpc";
    let result = party.wallet.post_consignment(
        invalid_proxy_url,
        fake_txid.to_string(),
        consignment_path.clone(),
        fake_txid.to_string(),
        Some(0),
    );
    assert_matches!(
        result,
        Err(Error::Proxy { details: m })
        if m.contains("error sending request for url")
            || m.contains("request or response body error for url"));

    // invalid transport endpoint
    let invalid_proxy_url = &format!("http://{PROXY_HOST_MOD_API}");
    let result = party.wallet.post_consignment(
        invalid_proxy_url,
        fake_txid.to_string(),
        consignment_path.clone(),
        fake_txid.to_string(),
        Some(0),
    );
    assert!(
        matches!(result, Err(Error::InvalidTransportEndpoint { details: m }) if m == "invalid result")
    );
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
fn accept_transfer_fail() {
    initialize();

    let mut party = get_empty_party!();

    // invalid txid
    let consignment_endpoint = RgbTransport::from_str(&PROXY_ENDPOINT).unwrap();
    let result = party
        .wallet
        .accept_transfer(s!("invalidTxid"), 0, consignment_endpoint, 0);
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn get_tx_height_fail() {
    initialize();

    let party = get_empty_party!();

    // invalid txid
    let result = party.wallet.get_tx_height(s!("invalidTxid"));
    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(feature = "electrum")]
#[test]
#[parallel]
fn update_witnesses_success() {
    initialize();

    let party = get_empty_party!();

    let result = party.wallet.update_witnesses(0, vec![]);
    assert!(result.is_ok());
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

    let indexer_url = if cfg!(feature = "electrum") {
        ELECTRUM_URL
    } else {
        ESPLORA_URL
    };

    let result = validate_consignment_offchain(
        consignment_path.as_ref(),
        &txid,
        indexer_url,
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

    let indexer_url = if cfg!(feature = "electrum") {
        ELECTRUM_URL
    } else {
        ESPLORA_URL
    };

    let result = validate_consignment_offchain(
        consignment_path.as_ref(),
        "not-a-valid-txid",
        indexer_url,
        BitcoinNetwork::Regtest,
    );

    assert_matches!(result, Err(Error::InvalidTxid));
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[test]
#[parallel]
fn validate_consignment_offchain_file_not_found() {
    initialize();

    let indexer_url = if cfg!(feature = "electrum") {
        ELECTRUM_URL
    } else {
        ESPLORA_URL
    };

    let result = validate_consignment_offchain(
        "/nonexistent/path/consignment.rgb",
        "e5a3e577309df31bd606f48049049d2e1e02b048206ba232944fcc053a176ccb",
        indexer_url,
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
