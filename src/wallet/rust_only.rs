//! Extra wallet helpers for special flows (color PSBT, post consignment, indexer checks).
//!
//! Includes submarine / HTLC helpers (`color_psbt_for_outpoints*`,
//! `fetch_consignment_by_recipient_id`, `accept_transfer_from_consignment`) that operate on
//! escrow outpoints without treating them as wallet UTXOs.
//!
//! UniFFI exports [`Wallet::color_psbt_and_consume`],
//! [`Wallet::color_psbt_for_outpoints_and_consume`],
//! [`Wallet::fetch_consignment_by_recipient_id`],
//! [`Wallet::accept_transfer_from_consignment`], and
//! [`Wallet::contract_assignments_for_outpoints`].
//! Proxy `post_consignment` stays rust-only / HTTP in the client.
use super::*;
use rgbstd::Operation as _;

/// RGB asset-specific information to color a transaction
#[derive(Debug, Clone)]
pub struct AssetColoringInfo {
    /// Map of vouts and asset amounts to color the transaction outputs
    pub output_map: HashMap<u32, u64>,
    /// Static blinding to keep the transaction construction deterministic
    pub static_blinding: Option<u64>,
}

/// RGB information to color a transaction
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub enum IndexerProtocol {
    /// An indexer implementing the electrum protocol
    Electrum,
    /// An indexer implementing the esplora protocol
    Esplora,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
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

/// Return an [`AnyResolver`] for the provided indexer URL, auto-detecting the protocol
/// (Electrum or Esplora).
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn get_resolver(
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<AnyResolver, Error> {
    let (_, resolver) = get_indexer_and_resolver(indexer_url, bitcoin_network)?;
    Ok(resolver)
}

/// Check whether the provided URL points to a valid proxy.
/// An error is raised if the provided proxy URL is invalid or if the service is running an
/// unsupported protocol version.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn check_proxy_url(proxy_url: &str) -> Result<(), Error> {
    check_proxy(proxy_url)
}

/// Validate a consignment using the witness bundled in the consignment (offchain).
/// This works before the witness transaction is broadcast, unlike [`get_resolver`]-based
/// validation which requires the TX to be in the indexer.
///
/// The `txid` is the witness transaction ID (from consignment.post params).
/// The `indexer_url` is used as fallback when the witness is not found in the consignment.
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn validate_consignment_offchain(
    file_path: &str,
    txid: &str,
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<ValidateConsignmentResult, Error> {
    use rgbstd::validation::ValidationError;

    let consignment = RgbTransfer::load_file(file_path).map_err(|e| Error::Internal {
        details: format!("Failed to load consignment: {e}"),
    })?;

    let witness_id = RgbTxid::from_str(txid).map_err(|_| Error::InvalidTxid)?;
    let chain_net: ChainNet = bitcoin_network.into();
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let trusted_typesystem = asset_schema.types();

    let fallback_resolver = get_resolver(indexer_url, bitcoin_network)?;

    let resolver = crate::utils::OffchainResolver {
        witness_id,
        consignment: &consignment,
        fallback: &fallback_resolver,
    };

    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem,
        ..Default::default()
    };

    match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid_consignment) => {
            let status = valid_consignment.validation_status();
            Ok(ValidateConsignmentResult {
                valid: true,
                warnings: Some(
                    status
                        .warnings
                        .iter()
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>(),
                ),
                error: None,
                details: None,
            })
        }
        Err(ValidationError::InvalidConsignment(failure)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some(failure.to_string()),
        }),
        Err(ValidationError::ResolverError(e)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("resolver".to_string()),
            details: Some(e.to_string()),
        }),
    }
}

/// Result of consignment validation (offchain or indexer-based).
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct ValidateConsignmentResult {
    /// Whether the consignment is valid.
    pub valid: bool,
    /// Warnings from validation (when valid).
    pub warnings: Option<Vec<String>>,
    /// Error type when invalid ("invalid" or "resolver").
    pub error: Option<String>,
    /// Error details when invalid.
    pub details: Option<String>,
}

/// Validate a consignment using the indexer only (witness TX must be visible to the indexer).
///
/// For transfers where the witness is not on-chain yet, use [`validate_consignment_offchain`].
///
/// <div class="warning">This method is meant for special usage and is normally not needed, use
/// it only if you know what you're doing</div>
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub fn validate_consignment(
    file_path: &str,
    indexer_url: &str,
    bitcoin_network: BitcoinNetwork,
) -> Result<ValidateConsignmentResult, Error> {
    use rgbstd::validation::ValidationError;

    let consignment = RgbTransfer::load_file(file_path).map_err(|e| Error::Internal {
        details: format!("Failed to load consignment: {e}"),
    })?;

    let chain_net: ChainNet = bitcoin_network.into();
    let asset_schema: AssetSchema = consignment.schema_id().try_into()?;
    let trusted_typesystem = asset_schema.types();

    let resolver = get_resolver(indexer_url, bitcoin_network)?;

    let validation_config = ValidationConfig {
        chain_net,
        trusted_typesystem,
        ..Default::default()
    };

    match consignment.clone().validate(&resolver, &validation_config) {
        Ok(valid_consignment) => {
            let status = valid_consignment.validation_status();
            Ok(ValidateConsignmentResult {
                valid: true,
                warnings: Some(
                    status
                        .warnings
                        .iter()
                        .map(|w| w.to_string())
                        .collect::<Vec<_>>(),
                ),
                error: None,
                details: None,
            })
        }
        Err(ValidationError::InvalidConsignment(failure)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("invalid".to_string()),
            details: Some(failure.to_string()),
        }),
        Err(ValidationError::ResolverError(e)) => Ok(ValidateConsignmentResult {
            valid: false,
            warnings: None,
            error: Some("resolver".to_string()),
            details: Some(e.to_string()),
        }),
    }
}

/// Rust-only APIs of the wallet.
impl Wallet {
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

    fn color_psbt_with_prevouts(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger(), "Coloring PSBT...");
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
        let fascia = psbt.rgb_commit().map_err(InternalError::from)?;

        info!(self.logger(), "Color PSBT completed");
        Ok((fascia, asset_beneficiaries))
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
        info!(self.logger(), "Coloring PSBT and consuming...");
        let (fascia, asset_beneficiaries) = self.color_psbt(psbt, coloring_info.clone())?;

        let witness_txid = psbt.get_txid();

        let mut runtime = self.rgb_runtime()?;
        runtime.consume_fascia(fascia, None)?;

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

        info!(self.logger(), "Color PSBT and consume completed");
        Ok(transfers)
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
        info!(self.logger(), "Coloring PSBT and consuming...");
        let (fascia, asset_beneficiaries) =
            self.color_psbt_for_outpoints(psbt, coloring_info.clone(), input_outpoints)?;

        let witness_txid = psbt.get_txid();

        let mut runtime = self.rgb_runtime()?;
        runtime.consume_fascia(fascia, None)?;

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

        info!(self.logger(), "Color PSBT and consume completed");
        Ok(transfers)
    }

    /// Create consignments for a PSBT created with the [`send_begin`](Wallet::send_begin) method.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn create_consignments(&self, psbt: String) -> Result<(), Error> {
        info!(self.logger(), "Creating consignments...");

        let psbt = Psbt::from_str(&psbt)?;
        let (_, transfer_dir, info_contents, fascia) = self.get_transfer_end_data(&psbt)?;
        self.gen_consignments(&fascia, &info_contents.transfers, &transfer_dir)?;

        info!(self.logger(), "Create consignments completed");
        Ok(())
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
        info!(self.logger(), "Accepting transfer...");
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let proxy_url = TransportEndpoint::try_from(consignment_endpoint)?.endpoint;

        let consignment_res = self.get_consignment(&proxy_url, txid.clone())?;
        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;

        self.accept_transfer_with_consignment(consignment, witness_id, vout, blinding)
    }

    /// Accept an RGB transfer from a pre-fetched consignment.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer_from_consignment(
        &mut self,
        consignment: RgbTransfer,
        txid: String,
        vout: u32,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        self.accept_transfer_with_consignment(consignment, witness_id, vout, blinding)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn accept_transfer_with_consignment(
        &mut self,
        consignment: RgbTransfer,
        witness_id: RgbTxid,
        vout: u32,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        let schema_id = consignment.schema_id().to_string();
        let asset_schema: AssetSchema = schema_id.try_into()?;
        self.check_schema_support(&asset_schema)?;
        debug!(
            self.logger(),
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

        debug!(self.logger(), "Validating consignment...");
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
                error!(self.logger(), "Consignment is invalid: {}", e);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(e)) => {
                warn!(self.logger(), "Network error during consignment validation");
                return Err(Error::Network {
                    details: e.to_string(),
                });
            }
        };
        let validity = valid_consignment.validation_status().validity();
        debug!(self.logger(), "Consignment validity: {:?}", validity);

        let valid_contract = valid_consignment.clone().into_valid_contract();
        runtime
            .import_contract(valid_contract, self.blockchain_resolver())
            .expect("failure importing validated contract");

        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);

        runtime.accept_transfer(valid_consignment, &resolver)?;

        info!(self.logger(), "Accept transfer completed");
        Ok((
            consignment,
            received_rgb_assignments.into_values().collect(),
        ))
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
                Ok(OutPoint {
                    txid,
                    vout: o.vout,
                })
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

    /// Fetch an RGB consignment by recipient_id (proxy lookup key).
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn fetch_consignment_by_recipient_id(
        &self,
        recipient_id: String,
        consignment_endpoint: RgbTransport,
    ) -> Result<(RgbTransfer, String, u32), Error> {
        let proxy_url = TransportEndpoint::try_from(consignment_endpoint)?.endpoint;
        let consignment_res = self.get_consignment(&proxy_url, recipient_id)?;
        let vout = consignment_res.vout.ok_or_else(|| Error::Internal {
            details: s!("missing vout in consignment response"),
        })?;

        let consignment_bytes = general_purpose::STANDARD
            .decode(consignment_res.consignment)
            .map_err(InternalError::from)?;
        let consignment = RgbTransfer::load(&consignment_bytes[..]).map_err(InternalError::from)?;

        Ok((consignment, consignment_res.txid, vout))
    }

    /// Consume an RGB fascia.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn consume_fascia(
        &self,
        fascia: Fascia,
        witness_ord: Option<WitnessOrd>,
    ) -> Result<(), Error> {
        info!(self.logger(), "Consuming fascia...");
        self.rgb_runtime()?
            .consume_fascia(fascia.clone(), witness_ord)?;
        info!(self.logger(), "Consume fascia completed");
        Ok(())
    }

    /// Get the height for a Bitcoin TX.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn get_tx_height(&self, txid: String) -> Result<Option<u32>, Error> {
        info!(self.logger(), "Getting TX height...");
        let height = self.tx_height(txid)?;
        info!(self.logger(), "Get TX height completed");
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
        info!(self.logger(), "Updating witnesses...");
        let update_res = self.rgb_runtime()?.update_witnesses(
            self.blockchain_resolver(),
            after_height,
            force_witnesses,
        )?;
        info!(self.logger(), "Update witnesses completed");
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
        info!(self.logger(), "Posting consignment...");
        let proxy_client = ProxyClient::new(proxy_url)?;
        self.post_consignment_to_proxy(&proxy_client, recipient_id, consignment_path, txid, vout)?;
        info!(self.logger(), "Post consignment completed");
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
        info!(self.logger(), "Saving new asset...");
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

        let txn = self.database().begin_transaction()?;
        self.save_new_asset_internal(
            &txn,
            &runtime,
            contract_id,
            asset_schema,
            valid_contract,
            Some(valid_transfer),
        )?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();

        info!(self.logger(), "Save new asset completed");
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
        info!(self.logger(), "Listing unspents vanilla...");
        let txn = self.database().begin_transaction()?;
        self.sync_if_requested(&txn, Some(online), skip_sync, KeychainKind::Internal)?;
        txn.commit()?;

        let unspents = self.internal_unspents();

        let res = if min_confirmations > 0 {
            unspents
                .filter_map(|u| {
                    match self
                        .indexer()
                        .get_tx_confirmations(&u.outpoint.txid.to_string())
                    {
                        Ok(confirmations) => {
                            if let Some(confirmations) = confirmations
                                && confirmations >= min_confirmations as u64
                            {
                                return Some(Ok(u));
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

        info!(self.logger(), "List unspents vanilla completed");
        res
    }

    /// Return the consignment file path for a send transfer of an asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn get_send_consignment_path(&self, asset_id: &str, transfer_id: &str) -> PathBuf {
        self.send_consignment_path(asset_id, transfer_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn display_indexer_protocol() {
        assert_eq!(IndexerProtocol::Electrum.to_string(), "Electrum");
        assert_eq!(IndexerProtocol::Esplora.to_string(), "Esplora");
    }
}
