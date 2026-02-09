//! RGB Rust-only methods module
//!
//! This module defines additional utility methods that are not exposed via FFI

use super::*;

/// RGB asset-specific information to color a transaction
#[derive(Clone, Debug)]
pub struct AssetColoringInfo {
    /// Map of vouts and asset amounts to color the transaction outputs
    pub output_map: HashMap<u32, u64>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
}

/// RGB information to color a transaction
#[derive(Clone, Debug)]
pub struct ColoringInfo {
    /// Asset-specific information
    pub asset_info_map: HashMap<ContractId, AssetColoringInfo>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
    /// Nonce for offchain TXs ordering
    pub nonce: Option<u64>,
}

/// Map of contract ID and list of its beneficiaries
pub type AssetBeneficiariesMap = BTreeMap<ContractId, Vec<BuilderSeal<GraphSeal>>>;

/// Indexer protocol
#[derive(Clone, Debug)]
pub enum IndexerProtocol {
    /// An indexer implementing the electrum protocol
    Electrum,
    /// An indexer implementing the esplora protocol
    Esplora,
}

impl fmt::Display for IndexerProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Return the indexer protocol for the provided URL.
/// An error is raised if the provided indexer URL is invalid or if the service is for the wrong
/// network or doesn't have the required functionality.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn check_indexer_url(
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<IndexerProtocol, Error> {
    let (indexer, _) = get_indexer_and_resolver(indexer_url, bitcoin_network)?;
    let indexer_protocol = match indexer {
        #[cfg(feature = "electrum")]
        Indexer::Electrum(_) => IndexerProtocol::Electrum,
        #[cfg(feature = "esplora")]
        Indexer::Esplora(_) => IndexerProtocol::Esplora,
    };

    Ok(indexer_protocol)
}

/// Check whether the provided URL points to a valid proxy.
/// An error is raised if the provided proxy URL is invalid or if the service is running an
/// unsupported protocol version.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn check_proxy_url(proxy_url: &str) -> Result<(), Error> {
    check_proxy(proxy_url, None)
}

impl Wallet {
    fn color_psbt_with_prevouts(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger, "Coloring PSBT...");
        let mut transaction = match psbt.clone().extract_tx() {
            Ok(tx) => tx,
            Err(ExtractTxError::MissingInputValue { tx }) => tx, // required for non-standard TXs
            Err(e) => return Err(InternalError::from(e).into()),
        };
        let mut opreturn_first = false;
        if transaction.output.iter().any(|o| o.script_pubkey.is_p2tr()) {
            opreturn_first = true;
        }

        if !transaction
            .output
            .iter()
            .any(|o| o.script_pubkey.is_op_return())
        {
            let opreturn_output = TxOut {
                value: BdkAmount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            };
            if opreturn_first {
                transaction.output.insert(0, opreturn_output);
            } else {
                transaction.output.push(opreturn_output);
            }
            *psbt = Psbt::from_unsigned_tx(transaction).unwrap();
        }

        let runtime = self.rgb_runtime()?;

        let mut all_transitions: HashMap<ContractId, Transition> = HashMap::new();
        let mut asset_beneficiaries: AssetBeneficiariesMap = bmap![];
        let assignment_name = FieldName::from(RGB_STATE_ASSET_OWNER);

        for (contract_id, asset_coloring_info) in coloring_info.asset_info_map.clone() {
            let schema = AssetSchema::get_from_contract_id(contract_id, &runtime)?;

            let mut asset_transition_builder =
                runtime.transition_builder(contract_id, "transfer")?;

            let mut asset_available_amt = 0;
            let mut uda_state = None;
            for (_, opout_state_map) in
                runtime.contract_assignments_for(contract_id, prev_outputs.iter().copied())?
            {
                for (opout, state) in opout_state_map {
                    if let AllocatedState::Amount(amt) = &state {
                        asset_available_amt += amt.as_u64();
                    } else if let AllocatedState::Data(_) = &state {
                        asset_available_amt = 1;
                        // there can be only a single state when contract is UDA
                        uda_state = Some(state.clone());
                    }
                    asset_transition_builder = asset_transition_builder.add_input(opout, state)?;
                }
            }

            let mut beneficiaries = vec![];
            let mut sending_amt = 0;
            for (mut vout, amount) in asset_coloring_info.output_map {
                if amount == 0 {
                    continue;
                }
                if opreturn_first {
                    vout += 1;
                }
                sending_amt += amount;
                if vout as usize > psbt.outputs.len() {
                    return Err(Error::InvalidColoringInfo {
                        details: s!("invalid vout in output_map, does not exist in the given PSBT"),
                    });
                }
                let graph_seal = if let Some(blinding) = asset_coloring_info.static_blinding {
                    GraphSeal::with_blinded_vout(vout, blinding)
                } else {
                    GraphSeal::new_random_vout(vout)
                };
                let seal = BuilderSeal::Revealed(graph_seal);
                beneficiaries.push(seal);

                match schema {
                    AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => {
                        asset_transition_builder = asset_transition_builder.add_fungible_state(
                            assignment_name.clone(),
                            seal,
                            amount,
                        )?;
                    }
                    AssetSchema::Uda => {
                        if let AllocatedState::Data(state) = uda_state.clone().unwrap() {
                            asset_transition_builder = asset_transition_builder
                                .add_data(assignment_name.clone(), seal, Allocation::from(state))
                                .map_err(Error::from)?;
                        }
                    }
                }
            }
            if sending_amt > asset_available_amt {
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "total amount in output_map ({sending_amt}) greater than available ({asset_available_amt})"
                    ),
                });
            }

            if let Some(nonce) = coloring_info.nonce {
                asset_transition_builder = asset_transition_builder.set_nonce(nonce);
            }

            let transition = asset_transition_builder.complete_transition()?;
            all_transitions.insert(contract_id, transition);
            asset_beneficiaries.insert(contract_id, beneficiaries);
        }

        let opreturn_index = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, o)| o.script_pubkey.is_op_return())
            .expect("psbt should have an op_return output")
            .0;
        let opreturn_output = psbt.outputs.get_mut(opreturn_index).unwrap();
        opreturn_output.set_opret_host();
        if let Some(blinding) = coloring_info.static_blinding {
            opreturn_output
                .set_mpc_entropy(blinding)
                .map_err(InternalError::from)?;
        }

        for (contract_id, transition) in all_transitions {
            for opout in transition.inputs() {
                psbt.set_rgb_contract_consumer(contract_id, opout, transition.id())
                    .map_err(InternalError::from)?;
            }
            psbt.push_rgb_transition(transition)
                .map_err(InternalError::from)?;
        }

        psbt.set_rgb_close_method(CloseMethod::OpretFirst);
        psbt.set_as_unmodifiable();
        let fascia = psbt.rgb_commit().map_err(|e| Error::Internal {
            details: e.to_string(),
        })?;

        info!(self.logger, "Color PSBT completed");
        Ok((fascia, asset_beneficiaries))
    }

    /// Color a PSBT.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();
        self.color_psbt_with_prevouts(psbt, coloring_info, prev_outputs)
    }

    /// Color a PSBT, consume the RGB fascia and return the related consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn color_psbt_and_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<Vec<RgbTransfer>, Error> {
        info!(self.logger, "Coloring PSBT and consuming...");
        let (fascia, asset_beneficiaries) = self.color_psbt(psbt, coloring_info.clone())?;

        let witness_txid = psbt.get_txid();

        let mut runtime = self.rgb_runtime()?;
        runtime.consume_fascia(fascia, witness_txid, None)?;

        let mut transfers = vec![];
        for (contract_id, beneficiaries) in asset_beneficiaries {
            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer(
                contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                Some(witness_txid),
            )?);
        }

        info!(self.logger, "Color PSBT and consume completed");
        Ok(transfers)
    }

    /// Color a PSBT using a provided set of input outpoints.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    pub fn color_psbt_for_outpoints(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        let override_set: HashSet<OutPoint> = input_outpoints.into_iter().collect();
        if override_set.is_empty() {
            return Err(Error::InvalidColoringInfo {
                details: s!("input_outpoints is empty"),
            });
        }
        let psbt_inputs: HashSet<OutPoint> = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();
        if !override_set.is_subset(&psbt_inputs) {
            return Err(Error::InvalidColoringInfo {
                details: s!("input_outpoints must be a subset of PSBT inputs"),
            });
        }
        self.color_psbt_with_prevouts(psbt, coloring_info, override_set)
    }

    /// Color a PSBT with a provided set of input outpoints and consume the resulting fascia.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    pub fn color_psbt_for_outpoints_and_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<Vec<RgbTransfer>, Error> {
        info!(self.logger, "Coloring PSBT and consuming...");
        let (fascia, asset_beneficiaries) =
            self.color_psbt_for_outpoints(psbt, coloring_info.clone(), input_outpoints)?;

        let witness_txid = psbt.get_txid();

        let mut runtime = self.rgb_runtime()?;
        runtime.consume_fascia(fascia, witness_txid, None)?;

        let mut transfers = vec![];
        for (contract_id, beneficiaries) in asset_beneficiaries {
            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer(
                contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                Some(witness_txid),
            )?);
        }

        info!(self.logger, "Color PSBT and consume completed");
        Ok(transfers)
    }

    /// Accept an RGB transfer using a TXID to retrieve its consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer(
        &mut self,
        txid: String,
        vout: u32,
        consignment_endpoint: RgbTransport,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        info!(self.logger, "Accepting transfer...");
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let proxy_url = TransportEndpoint::try_from(consignment_endpoint)?.endpoint;

        let consignment_res = self.get_consignment(&proxy_url, txid.clone())?;
        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;

        let schema_id = consignment.schema_id().to_string();
        let asset_schema: AssetSchema = schema_id.try_into()?;
        self.check_schema_support(&asset_schema)?;
        debug!(
            self.logger,
            "Got consignment for asset with {} schema", asset_schema
        );

        let mut runtime = self.rgb_runtime()?;

        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        runtime.store_secret_seal(graph_seal)?;

        let resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };

        debug!(self.logger, "Validating consignment...");
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        let trusted_typesystem = asset_schema.types();
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem,
            ..Default::default()
        };
        let valid_consignment = match consignment.clone().validate(&resolver, &validation_config) {
            Ok(consignment) => consignment,
            Err(ValidationError::InvalidConsignment(e)) => {
                error!(self.logger, "Consignment is invalid: {}", e);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(e)) => {
                warn!(self.logger, "Network error during consignment validation");
                return Err(Error::Network {
                    details: e.to_string(),
                });
            }
        };
        let validity = valid_consignment.validation_status().validity();
        debug!(self.logger, "Consignment validity: {:?}", validity);

        let valid_contract = valid_consignment.clone().into_valid_contract();
        runtime
            .import_contract(valid_contract, self.blockchain_resolver())
            .expect("failure importing validated contract");

        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);

        let _status = runtime.accept_transfer(valid_consignment, &resolver)?;

        info!(self.logger, "Accept transfer completed");
        Ok((
            consignment,
            received_rgb_assignments.into_values().collect(),
        ))
    }

    /// Consume an RGB fascia.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn consume_fascia(
        &self,
        fascia: Fascia,
        witness_txid: RgbTxid,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        info!(self.logger, "Consuming fascia...");
        self.rgb_runtime()?
            .consume_fascia(fascia.clone(), witness_txid, witness_ord)?;
        info!(self.logger, "Consume fascia completed");
        Ok(())
    }

    /// Inspect arbitrary outpoints for assignments of a given contract.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn contract_assignments_for_outpoints(
        &self,
        contract_id: ContractId,
        outpoints: Vec<Outpoint>,
    ) -> Result<HashMap<Outpoint, Vec<Assignment>>, Error> {
        let btc_outpoints: Vec<OutPoint> = outpoints
            .iter()
            .map(|o| {
                let txid =
                    crate::bitcoin::Txid::from_str(&o.txid).map_err(|_| Error::InvalidTxid)?;
                Ok(OutPoint { txid, vout: o.vout })
            })
            .collect::<Result<_, Error>>()?;

        let runtime = self.rgb_runtime()?;
        let state = runtime.contract_assignments_for(contract_id, btc_outpoints)?;

        let mut res: HashMap<Outpoint, Vec<Assignment>> = HashMap::new();
        for (seal, opout_state_map) in state {
            let outpoint = Outpoint {
                txid: seal.txid.to_string(),
                vout: seal.vout.into_u32(),
            };
            let mut assignments = Vec::with_capacity(opout_state_map.len());
            for (opout, state) in opout_state_map {
                assignments.push(Assignment::from_opout_and_state(opout, &state));
            }
            res.insert(outpoint, assignments);
        }

        Ok(res)
    }

    /// Get the height for a Bitcoin TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn get_tx_height(&self, txid: String) -> Result<Option<u32>, Error> {
        info!(self.logger, "Getting TX height...");
        let txid = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let height = match self
            .blockchain_resolver()
            .resolve_witness(txid)
            .map_err(|e| Error::Network {
                details: e.to_string(),
            })? {
            WitnessStatus::Resolved(_, WitnessOrd::Mined(witness_pos)) => {
                Some(witness_pos.height().get())
            }
            _ => None,
        };
        info!(self.logger, "Get TX height completed");
        Ok(height)
    }

    /// Update RGB witnesses.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn update_witnesses(
        &self,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, Error> {
        info!(self.logger, "Updating witnesses...");
        let update_res = self.rgb_runtime()?.update_witnesses(
            self.blockchain_resolver(),
            after_height,
            force_witnesses,
        )?;
        info!(self.logger, "Update witnesses completed");
        Ok(update_res)
    }

    /// Manually set the [`WitnessOrd`] of a witness TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn upsert_witness(
        &self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Error> {
        let mut runtime = self.rgb_runtime()?;
        runtime.upsert_witness(witness_id, witness_ord)?;
        Ok(())
    }

    /// Post a consignment to the proxy server.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn post_consignment<P: AsRef<Path>>(
        &self,
        proxy_url: &str,
        recipient_id: String,
        consignment_path: P,
        txid: String,
        vout: Option<u32>,
    ) -> Result<(), Error> {
        info!(self.logger, "Posting consignment...");
        let consignment_res = self.rest_client.clone().post_consignment(
            proxy_url,
            recipient_id.clone(),
            consignment_path,
            txid.clone(),
            vout,
        )?;
        debug!(
            self.logger,
            "Consignment POST response: {:?}", consignment_res
        );

        if let Some(err) = consignment_res.error {
            if err.code == -101 {
                return Err(Error::RecipientIDAlreadyUsed)?;
            }
            return Err(Error::InvalidTransportEndpoint {
                details: format!("proxy error: {}", err.message),
            });
        }
        if consignment_res.result.is_none() {
            return Err(Error::InvalidTransportEndpoint {
                details: s!("invalid result"),
            });
        }

        info!(self.logger, "Post consignment completed");
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn save_new_asset_internal(
        &self,
        runtime: &RgbRuntime,
        contract_id: ContractId,
        asset_schema: AssetSchema,
        valid_contract: ValidContract,
        valid_transfer: ValidTransfer,
    ) -> Result<(), Error> {
        let timestamp = valid_contract.genesis.timestamp;
        let (local_asset_data, token) = match &asset_schema {
            AssetSchema::Nia => {
                let contract = runtime.contract_wrapper::<NonInflatableAsset>(contract_id)?;
                let spec = contract.spec();
                let ticker = spec.ticker().to_string();
                let name = spec.name().to_string();
                let details = spec.details().map(|d| d.to_string());
                let precision = spec.precision.into();
                let initial_supply = contract.total_issued_supply().into();
                let media_idx = if let Some(attachment) = contract.contract_terms().media {
                    Some(self.get_or_insert_media(
                        hex::encode(attachment.digest),
                        attachment.ty.to_string(),
                    )?)
                } else {
                    None
                };
                (
                    LocalAssetData {
                        name,
                        precision,
                        ticker: Some(ticker),
                        details,
                        media_idx,
                        initial_supply,
                        max_supply: None,
                        known_circulating_supply: None,
                        reject_list_url: None,
                    },
                    None,
                )
            }
            AssetSchema::Uda => {
                let contract = runtime.contract_wrapper::<UniqueDigitalAsset>(contract_id)?;
                let spec = contract.spec();
                let ticker = spec.ticker().to_string();
                let name = spec.name().to_string();
                let details = spec.details().map(|d| d.to_string());
                let precision = spec.precision.into();
                let initial_supply = 1;
                let media_idx = if let Some(attachment) = contract.contract_terms().media {
                    Some(self.get_or_insert_media(
                        hex::encode(attachment.digest),
                        attachment.ty.to_string(),
                    )?)
                } else {
                    None
                };
                let token_full =
                    Token::from_token_data(&contract.token_data(), self.get_media_dir());
                (
                    LocalAssetData {
                        name,
                        precision,
                        ticker: Some(ticker),
                        details,
                        media_idx,
                        initial_supply,
                        max_supply: None,
                        known_circulating_supply: None,
                        reject_list_url: None,
                    },
                    Some(token_full),
                )
            }
            AssetSchema::Cfa => {
                let contract = runtime.contract_wrapper::<CollectibleFungibleAsset>(contract_id)?;
                let name = contract.name().to_string();
                let details = contract.details().map(|d| d.to_string());
                let precision = contract.precision().into();
                let initial_supply = contract.total_issued_supply().into();
                let media_idx = if let Some(attachment) = contract.contract_terms().media {
                    Some(self.get_or_insert_media(
                        hex::encode(attachment.digest),
                        attachment.ty.to_string(),
                    )?)
                } else {
                    None
                };
                (
                    LocalAssetData {
                        name,
                        precision,
                        ticker: None,
                        details,
                        media_idx,
                        initial_supply,
                        max_supply: None,
                        known_circulating_supply: None,
                        reject_list_url: None,
                    },
                    None,
                )
            }
            AssetSchema::Ifa => {
                let contract = runtime.contract_wrapper::<InflatableFungibleAsset>(contract_id)?;
                let spec = contract.spec();
                let ticker = spec.ticker().to_string();
                let name = spec.name().to_string();
                let details = spec.details().map(|d| d.to_string());
                let precision = spec.precision.into();
                let media_idx = if let Some(attachment) = contract.contract_terms().media {
                    Some(self.get_or_insert_media(
                        hex::encode(attachment.digest),
                        attachment.ty.to_string(),
                    )?)
                } else {
                    None
                };
                let initial_supply = contract.total_issued_supply().into();
                let max_supply = contract.max_supply().into();
                let known_circulating_supply = IfaWrapper::with(valid_transfer.contract_data())
                    .total_issued_supply()
                    .into();
                let reject_list_url = contract.reject_list_url().map(|u| u.to_string());
                (
                    LocalAssetData {
                        name,
                        precision,
                        ticker: Some(ticker),
                        details,
                        media_idx,
                        initial_supply,
                        max_supply: Some(max_supply),
                        known_circulating_supply: Some(known_circulating_supply),
                        reject_list_url,
                    },
                    None,
                )
            }
        };

        let db_asset = self.add_asset_to_db(
            contract_id.to_string(),
            &asset_schema,
            None,
            timestamp,
            local_asset_data,
        )?;

        if let Some(token) = token {
            let db_token = DbTokenActMod {
                asset_idx: ActiveValue::Set(db_asset.idx),
                index: ActiveValue::Set(token.index),
                ticker: ActiveValue::Set(token.ticker),
                name: ActiveValue::Set(token.name),
                details: ActiveValue::Set(token.details),
                embedded_media: ActiveValue::Set(token.embedded_media.is_some()),
                reserves: ActiveValue::Set(token.reserves.is_some()),
                ..Default::default()
            };
            let token_idx = self.database.set_token(db_token)?;

            if let Some(media) = &token.media {
                self.save_token_media(token_idx, media.get_digest(), media.mime.clone(), None)?;
            }
            for (attachment_id, media) in token.attachments {
                self.save_token_media(
                    token_idx,
                    media.get_digest(),
                    media.mime.clone(),
                    Some(attachment_id),
                )?;
            }
        }

        Ok(())
    }

    /// Extract the metadata of a new RGB asset and save the asset into the DB.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn save_new_asset(
        &self,
        consignment: RgbTransfer,
        offchain_txid: String,
    ) -> Result<(), Error> {
        info!(self.logger, "Saving new asset...");
        let runtime = self.rgb_runtime()?;

        let contract_id = consignment.contract_id();

        let witness_id = RgbTxid::from_str(&offchain_txid).map_err(|_| Error::InvalidTxid)?;
        let resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };
        let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
        let trusted_typesystem = asset_schema.types();
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem,
            ..Default::default()
        };
        let valid_transfer = consignment
            .clone()
            .validate(&resolver, &validation_config)
            .expect("valid consignment");
        let valid_contract = valid_transfer.clone().into_valid_contract();

        self.save_new_asset_internal(
            &runtime,
            contract_id,
            asset_schema,
            valid_contract,
            valid_transfer,
        )?;

        self.update_backup_info(false)?;

        info!(self.logger, "Save new asset completed");
        Ok(())
    }

    /// List the Bitcoin unspents of the vanilla wallet, using BDK's objects, filtered by
    /// `min_confirmations`.
    ///
    /// <div class="warning">This method is meant for special usage, for most cases the method
    /// <code>list_unspents</code> is sufficient</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn list_unspents_vanilla(
        &mut self,
        online: Online,
        min_confirmations: u8,
        skip_sync: bool,
    ) -> Result<Vec<LocalOutput>, Error> {
        info!(self.logger, "Listing unspents vanilla...");
        self.sync_if_requested(Some(online), skip_sync)?;

        let unspents = self.internal_unspents();

        let res = if min_confirmations > 0 {
            unspents
                .filter_map(|u| {
                    match self
                        .indexer()
                        .get_tx_confirmations(&u.outpoint.txid.to_string())
                    {
                        Ok(confirmations) => {
                            if let Some(confirmations) = confirmations {
                                if confirmations >= min_confirmations as u64 {
                                    return Some(Ok(u));
                                }
                            }
                            None
                        }
                        Err(e) => Some(Err(e)),
                    }
                })
                .collect::<Result<Vec<LocalOutput>, Error>>()
        } else {
            Ok(unspents.collect())
        };

        info!(self.logger, "List unspents vanilla completed");
        res
    }

    /// Return the consignment file path for a send transfer of an asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn get_send_consignment_path(&self, asset_id: &str, transfer_id: &str) -> PathBuf {
        let transfer_dir = self.get_transfer_dir(transfer_id);
        let asset_transfer_dir = self.get_asset_transfer_dir(transfer_dir, asset_id);
        asset_transfer_dir.join(CONSIGNMENT_FILE)
    }
}
