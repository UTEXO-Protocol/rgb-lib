//! Extra wallet helpers for special flows (color PSBT, post consignment, indexer checks).
//!
//! Includes submarine / HTLC helpers (`color_psbt_for_outpoints*`, `htlc_prepare` /
//! `htlc_apply` / `htlc_abort` / `htlc_reconcile`, `fetch_and_accept_transfer_by_recipient_id`,
//! `contract_assignments_for_outpoints`) that operate on escrow outpoints without treating
//! them as wallet UTXOs.
//!
//! UniFFI exports [`Wallet::htlc_prepare`], [`Wallet::htlc_apply`], [`Wallet::htlc_abort`],
//! [`Wallet::htlc_reconcile`], [`Wallet::fetch_and_accept_transfer_by_recipient_id`], and
//! [`Wallet::contract_assignments_for_outpoints`].
//! Low-level `color_psbt_*` / `consume_transfer_fascia` and unchecked fetch/accept stay rust-only.

use super::*;
use crate::utils::recipient_id_from_script_buf;
use bdk_wallet::bitcoin::Transaction;
use rgbstd::Operation as _;
use serde::{Deserialize, Serialize};

#[cfg(any(feature = "electrum", feature = "esplora"))]
const HTLC_OPS_DIR: &str = "htlc_ops";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const HTLC_META_FILE: &str = "meta.json";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const HTLC_ESCROW_FILE: &str = "escrow.json";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const HTLC_COLORED_PSBT_FILE: &str = "colored.psbt";
#[cfg(any(feature = "electrum", feature = "esplora"))]
const HTLC_CONSIGNMENTS_DIR: &str = "consignments";

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

/// Result of importing an RGB contract without receiving asset allocations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportAssetContractResult {
    /// Imported contract ID.
    pub asset_id: String,
    /// Whether the wallet's RGB stock and asset database both contained the contract before the
    /// call.
    pub already_imported: bool,
    /// Metadata derived from the validated contract.
    pub metadata: Metadata,
}

/// Map of contract ID and list of its beneficiaries
pub type AssetBeneficiariesMap = BTreeMap<ContractId, Vec<BuilderSeal<GraphSeal>>>;

/// Result of [`Wallet::color_psbt_and_consume`] / [`Wallet::color_psbt_for_outpoints_and_consume`].
///
/// Consignments are ready to post, but the RGB stash is **not** updated until
/// [`Wallet::consume_transfer_fascia`] (after broadcast). While
/// [`ColorConsumeResult::batch_transfer_idx`] is [`TransferStatus::Initiated`],
/// [`Wallet::fail_transfers`] can roll the DB reservation back if the tx never lands.
#[derive(Debug)]
pub struct ColorConsumeResult {
    /// Per-asset consignments built from the fascia (before stash consume).
    pub transfers: Vec<RgbTransfer>,
    /// Fallible batch transfer created for recovery via `fail_transfers`.
    pub batch_transfer_idx: i32,
}

/// Status of a file-backed HTLC coloring operation.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HtlcOperationStatus {
    /// Colored PSBT + payloads on disk; RGB stash not updated.
    Prepared,
    /// Fascia consumed into the RGB stash after broadcast.
    Applied,
    /// Aborted before apply (never broadcast).
    Failed,
    /// Reconciled as settled against wallet/batch state.
    Settled,
}

/// Result of [`Wallet::htlc_prepare`].
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone)]
pub struct HtlcPrepareResult {
    /// Opaque operation ID (directory name under `htlc_ops/`).
    pub operation_id: String,
    /// Colored unsigned PSBT (caller signs and broadcasts).
    pub colored_psbt: String,
    /// Wallet-relative directory containing file-backed payloads.
    pub operation_dir: String,
}

/// Caller intent for HTLC / special accept paths.
///
/// Acceptance rejects consignments that do not match these fields, including an empty
/// assignment result for the witness seal.
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedTransfer {
    /// Expected contract / asset ID
    pub asset_id: String,
    /// Expected RGB schema
    pub asset_schema: AssetSchema,
    /// Expected assignment type and amount (`Any` is rejected)
    pub assignment: Assignment,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HtlcOpMeta {
    operation_id: String,
    status: HtlcOperationStatus,
    txid: String,
    created_at: i64,
    batch_transfer_idx: Option<i32>,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HtlcEscrowEntry {
    asset_id: String,
    outpoint: Outpoint,
    assignments: Vec<Assignment>,
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
type HtlcSpentByContract = HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>>;

#[cfg(any(feature = "electrum", feature = "esplora"))]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HtlcEscrowFile {
    entries: Vec<HtlcEscrowEntry>,
}

fn psbt_has_input_signatures(psbt: &Psbt) -> bool {
    psbt.inputs.iter().any(|input| {
        !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || !input.tap_script_sigs.is_empty()
            || input.final_script_sig.is_some()
            || input.final_script_witness.is_some()
    })
}

/// Pin a witness UTXO to `witness_recipient_id` by checking that `output[vout]`'s
/// script matches the recipient ID, and that the witness meets `min_confirmations`.
///
/// Errors (actionable for HTLC callers):
/// - [`Error::InvalidRecipientID`]: blinded ID (no script to pin)
/// - [`Error::InvalidRecipientNetwork`]: recipient ID network ≠ wallet chain
/// - [`Error::WitnessOutputMismatch`]: wrong script / bad vout / Ignored|Archived
/// - [`Error::InsufficientConfirmations`]: Tentative or too few confs (retry/wait)
///
/// Confirmation policy:
/// - `0`: allow a mempool-only / [`WitnessOrd::Tentative`] witness. Intentional for
///   HTLC claim/refund paths that must race on first sight of the witness; the
///   caller accepts reorg/RBF exposure.
/// - `>= 1`: require [`WitnessOrd::Mined`] and at least that many confirmations,
///   derived as `tip_height - mined_height + 1` (same tip query as the indexer
///   height API). Avoids a second `get_tx_confirmations` round trip that can
///   disagree with `resolve_witness` across a block boundary.
#[cfg(any(feature = "electrum", feature = "esplora"))]
fn pin_witness_output_to_recipient_id(
    resolver: &AnyResolver,
    indexer: &Indexer,
    chain_net: ChainNet,
    witness_recipient_id: &str,
    txid: &str,
    vout: u32,
    min_confirmations: u8,
) -> Result<(), Error> {
    let xchainnet_beneficiary = XChainNet::<Beneficiary>::from_str(witness_recipient_id)
        .map_err(|_| Error::InvalidRecipientID)?;
    if xchainnet_beneficiary.chain_network() != chain_net {
        return Err(Error::InvalidRecipientNetwork);
    }
    let expected_script = match xchainnet_beneficiary.into_inner() {
        Beneficiary::WitnessVout(pay_2_vout, _) => pay_2_vout.to_script(),
        // Blinded IDs have no on-chain script to pin against.
        Beneficiary::BlindedSeal(_) => return Err(Error::InvalidRecipientID),
    };
    let witness_id = RgbTxid::from_str(txid).map_err(|_| Error::InvalidTxid)?;
    let status = resolver
        .resolve_witness(witness_id)
        .map_err(|e| Error::Network {
            details: e.to_string(),
        })?;
    let (tx, witness_ord) = match status {
        WitnessStatus::Resolved(tx, ord) => (tx, ord),
        _ => {
            return Err(Error::Network {
                details: s!("witness transaction not found on indexer"),
            });
        }
    };
    let Some(output) = tx.output.get(vout as usize) else {
        return Err(Error::WitnessOutputMismatch {
            details: format!("witness vout {vout} out of range for transaction"),
        });
    };
    if output.script_pubkey != expected_script {
        return Err(Error::WitnessOutputMismatch {
            details: s!("witness output script does not match witness_recipient_id"),
        });
    }

    match witness_ord {
        WitnessOrd::Ignored | WitnessOrd::Archived => {
            return Err(Error::WitnessOutputMismatch {
                details: format!(
                    "witness TX {txid} has non-spendable WitnessOrd status ({witness_ord})"
                ),
            });
        }
        WitnessOrd::Tentative | WitnessOrd::Mined(_) => {}
    }

    if min_confirmations == 0 {
        // Tentative (mempool) allowed — caller opted into reorg/RBF exposure.
        return Ok(());
    }

    let WitnessOrd::Mined(pos) = witness_ord else {
        return Err(Error::InsufficientConfirmations {
            needed: min_confirmations,
            got: 0,
        });
    };

    let tip_height = indexer.get_latest_block_height()?;
    let tx_height = pos.height().get();
    let confirmations = u64::from(tip_height.saturating_sub(tx_height)) + 1;
    if confirmations < min_confirmations as u64 {
        return Err(Error::InsufficientConfirmations {
            needed: min_confirmations,
            got: confirmations,
        });
    }
    Ok(())
}

fn rebuild_psbt_preserving_maps(
    psbt: &Psbt,
    mut unsigned_tx: Transaction,
    opreturn_first: bool,
) -> Result<Psbt, Error> {
    for txin in &mut unsigned_tx.input {
        txin.script_sig = ScriptBuf::new();
        txin.witness.clear();
    }
    let mut rebuilt = Psbt::from_unsigned_tx(unsigned_tx).map_err(|e| Error::Internal {
        details: format!("Failed to create PSBT: {e}"),
    })?;
    rebuilt.version = psbt.version;
    rebuilt.xpub = psbt.xpub.clone();
    rebuilt.proprietary = psbt.proprietary.clone();
    rebuilt.unknown = psbt.unknown.clone();
    for (rebuilt_input, input) in rebuilt.inputs.iter_mut().zip(psbt.inputs.iter()) {
        *rebuilt_input = input.clone();
    }
    if opreturn_first {
        for (rebuilt_output, output) in rebuilt.outputs.iter_mut().skip(1).zip(psbt.outputs.iter())
        {
            *rebuilt_output = output.clone();
        }
    } else {
        for (rebuilt_output, output) in rebuilt.outputs.iter_mut().zip(psbt.outputs.iter()) {
            *rebuilt_output = output.clone();
        }
    }
    Ok(rebuilt)
}

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
    /// Export an RGB contract known to this wallet.
    ///
    /// The returned consignment contains the public contract definition and genesis metadata, but
    /// no transfer or allocation state. It can be distributed as public contract metadata and
    /// imported with [`import_asset_contract`](Wallet::import_asset_contract).
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed,
    /// use it only if you know what you're doing</div>
    pub fn export_asset_contract(&self, asset_id: String) -> Result<RgbContract, Error> {
        let contract_id = ContractId::from_str(&asset_id).map_err(|error| Error::Internal {
            details: format!("invalid asset ID: {error}"),
        })?;
        self.rgb_runtime()?
            .export_contract(contract_id)
            .map_err(Error::from)
    }

    /// Validate and import an RGB contract without importing any asset allocations.
    ///
    /// This registers the contract and its metadata in the wallet. It does not transfer ownership
    /// and the imported asset therefore starts with a zero balance. Re-importing a fully persisted
    /// contract is idempotent and returns the existing metadata. If an earlier import was
    /// interrupted between its RGB stock and database writes, retrying repairs the partial state.
    ///
    /// Contract attachments are not embedded in a contract consignment. Contracts declaring
    /// attachments must be imported through a flow that supplies and verifies those files.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed,
    /// use it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn import_asset_contract(
        &self,
        contract: RgbContract,
    ) -> Result<ImportAssetContractResult, Error> {
        let contract_id = contract.contract_id();
        let asset_id = contract_id.to_string();

        let asset_schema: AssetSchema = contract.schema_id().try_into()?;
        self.check_schema_support(&asset_schema)?;
        let validation_config = ValidationConfig {
            chain_net: self.chain_net(),
            trusted_typesystem: asset_schema.types(),
            ..Default::default()
        };
        let valid_contract = contract
            .validate(&DumbResolver, &validation_config)
            .map_err(|_| Error::InvalidConsignment)?;

        // The RGB runtime lock serializes the stock and database state transition. Persisting the
        // stock before committing the database makes every interrupted state repairable on retry.
        let mut runtime = self.rgb_runtime()?;
        let contract_in_stock = runtime.export_contract(contract_id).is_ok();
        let txn = self.database().begin_transaction()?;
        let asset_in_database = txn.get_asset(asset_id.clone())?.is_some();
        let already_imported = contract_in_stock && asset_in_database;

        if already_imported {
            drop(txn);
            drop(runtime);
            return Ok(ImportAssetContractResult {
                asset_id: asset_id.clone(),
                already_imported: true,
                metadata: self.get_asset_metadata(asset_id)?,
            });
        }

        if !asset_in_database
            && !self
                .extract_attachments(&valid_contract, asset_schema)
                .is_empty()
        {
            return Err(Error::InvalidAttachments {
                details: "contract import requires the declared attachment files".to_string(),
            });
        }

        if !contract_in_stock {
            runtime.require_explicit_persistence();
            runtime.import_contract(valid_contract.clone(), &DumbResolver)?;
        }

        if !asset_in_database {
            self.save_new_asset_internal(
                &txn,
                &runtime,
                contract_id,
                asset_schema,
                valid_contract,
                None,
            )?;
        }
        self.update_backup_info(&txn, false)?;
        if !contract_in_stock {
            runtime.persist()?;
        }
        txn.commit()?;
        drop(runtime);
        self.trigger_auto_backup();

        Ok(ImportAssetContractResult {
            asset_id: asset_id.clone(),
            already_imported,
            metadata: self.get_asset_metadata(asset_id)?,
        })
    }

    /// Color a PSBT.
    ///
    /// # `output_map` index convention (differs from [`Self::color_psbt_for_outpoints`])
    ///
    /// Keys are PSBT output indices. When any output is P2TR (RGB `OpretFirst`), OP_RETURN is
    /// placed at vout 0 (inserted if missing) and keys are treated as **pre-OP_RETURN** indices:
    /// they are shifted by +1 internally. That applies even if OP_RETURN was already present at
    /// vout 0. With P2TR, a pre-existing OP_RETURN at index > 0 is rejected (would silently
    /// mis-seal under the +1 rule). With no P2TR, OP_RETURN is appended and keys are final.
    ///
    /// Sibling API: [`Self::color_psbt_for_outpoints`] always takes **final** vouts and never
    /// shifts. Passing the wrong base places a seal on the wrong output with **no error**.
    ///
    /// Coloring must happen **before** any input is signed. Partial signatures (including
    /// `SIGHASH_SINGLE|ANYONECANPAY` on HTLC paths) are rejected because embedding the RGB
    /// commitment rewrites the OP_RETURN output and invalidates existing sighashes.
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
        self.color_psbt_with_prevouts(psbt, coloring_info, prev_outputs, false)
    }

    /// Ensure the PSBT can be colored: reject signed inputs, insert OP_RETURN if missing.
    ///
    /// Returns whether `output_map` keys should be +1-shifted ([`Self::color_psbt`] legacy
    /// `OpretFirst` rule): `true` when any output is P2TR and OP_RETURN is (or will be) at
    /// vout 0. With P2TR, a pre-existing OP_RETURN at index > 0 is rejected so +1 cannot
    /// silently mis-seal. [`Self::color_psbt_for_outpoints`] ignores this flag.
    ///
    /// Uses `unsigned_tx` directly (no `extract_tx`): fee-rate guards are irrelevant to RGB
    /// commitment layout, and HTLC PSBTs may trip `AbsurdFeeRate` without being invalid to color.
    fn prepare_psbt_for_coloring(&self, psbt: &mut Psbt) -> Result<bool, Error> {
        if psbt_has_input_signatures(psbt) {
            return Err(Error::InvalidColoringInfo {
                details: s!(
                    "cannot color a signed PSBT: RGB commitment rewrites the OP_RETURN output"
                ),
            });
        }
        let opreturn_first = psbt
            .unsigned_tx
            .output
            .iter()
            .any(|o| o.script_pubkey.is_p2tr());
        match psbt
            .unsigned_tx
            .output
            .iter()
            .position(|o| o.script_pubkey.is_op_return())
        {
            None => {
                let mut transaction = psbt.unsigned_tx.clone();
                let opreturn_output = TxOut {
                    value: BdkAmount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return([]),
                };
                if opreturn_first {
                    transaction.output.insert(0, opreturn_output);
                } else {
                    transaction.output.push(opreturn_output);
                }
                *psbt = rebuild_psbt_preserving_maps(psbt, transaction, opreturn_first)?;
            }
            Some(0) => {}
            // +1 assumes OP_RETURN at / inserted at vout 0; otherwise seals shift with no insert.
            Some(_) if opreturn_first => {
                return Err(Error::InvalidColoringInfo {
                    details: s!("OP_RETURN must be the first PSBT output"),
                });
            }
            Some(_) => {}
        }

        Ok(opreturn_first)
    }

    fn color_psbt_with_prevouts(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
        require_full_allocation: bool,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger(), "Coloring PSBT...");
        let shift_output_map_for_opreturn_first = self.prepare_psbt_for_coloring(psbt)?;
        let runtime = self.rgb_runtime()?;
        self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info,
            prev_outputs,
            require_full_allocation,
            shift_output_map_for_opreturn_first,
        )
    }

    fn color_psbt_with_prevouts_runtime(
        &self,
        runtime: &RgbRuntime,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        prev_outputs: HashSet<OutPoint>,
        require_full_allocation: bool,
        shift_output_map_for_opreturn_first: bool,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        let mut all_transitions: HashMap<ContractId, Transition> = HashMap::new();
        let mut asset_beneficiaries: AssetBeneficiariesMap = bmap![];
        let assignment_name = FieldName::from(RGB_STATE_ASSET_OWNER);

        for (contract_id, asset_coloring_info) in coloring_info.asset_info_map.clone() {
            let schema = AssetSchema::get_from_contract_id(contract_id, runtime)?;

            let mut asset_transition_builder =
                runtime.transition_builder(contract_id, "transfer")?;

            let mut asset_available_amt: u64 = 0;
            let mut uda_state = None;
            for (_, opout_state_map) in
                runtime.contract_assignments_for(contract_id, prev_outputs.iter().copied())?
            {
                for (opout, state) in opout_state_map {
                    if let AllocatedState::Amount(amt) = &state {
                        asset_available_amt = asset_available_amt
                            .checked_add(amt.as_u64())
                            .expect("total available asset amount cannot exceed u64::MAX");
                    } else if let AllocatedState::Data(_) = &state {
                        asset_available_amt = 1;
                        // there can be only a single state when contract is UDA
                        uda_state = Some(state.clone());
                    }
                    asset_transition_builder = asset_transition_builder.add_input(opout, state)?;
                }
            }

            let mut beneficiaries = vec![];
            let mut sending_amt: u64 = 0;
            for (mut vout, amount) in asset_coloring_info.output_map {
                if amount == 0 {
                    continue;
                }
                if shift_output_map_for_opreturn_first {
                    vout = vout
                        .checked_add(1)
                        .ok_or_else(|| Error::InvalidColoringInfo {
                            details: s!("vout in output_map is too large"),
                        })?;
                }
                sending_amt =
                    sending_amt
                        .checked_add(amount)
                        .ok_or_else(|| Error::InvalidColoringInfo {
                            details: s!("total amount in output_map exceeds u64::MAX"),
                        })?;
                if vout as usize >= psbt.unsigned_tx.output.len() {
                    return Err(Error::InvalidColoringInfo {
                        details: s!("invalid vout in output_map, does not exist in the given PSBT"),
                    });
                }
                if psbt.unsigned_tx.output[vout as usize]
                    .script_pubkey
                    .is_op_return()
                {
                    return Err(Error::InvalidColoringInfo {
                        details: format!("output_map vout {vout} points to the OP_RETURN output"),
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
            if require_full_allocation && sending_amt < asset_available_amt {
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "total amount in output_map ({sending_amt}) less than available ({asset_available_amt}); full allocation required"
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

    /// Color a PSBT, build consignments, and register a fallible batch transfer.
    ///
    /// `output_map` indexing follows [`Self::color_psbt`] (legacy P2TR / `OpretFirst` +1 shift).
    ///
    /// Consignments are built from the fascia **before** any stash update. The fascia is saved
    /// under the wallet transfer dir and a [`TransferStatus::Initiated`] batch is written so
    /// [`crate::wallet::Wallet::fail_transfers`] can roll back if the tx is never broadcast.
    /// Call [`Self::consume_transfer_fascia`] with [`ColorConsumeResult::batch_transfer_idx`]
    /// **after** broadcast to apply the fascia to the RGB stash.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn color_psbt_and_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
    ) -> Result<ColorConsumeResult, Error> {
        info!(self.logger(), "Coloring PSBT and preparing consume...");
        let prev_outputs = psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect::<HashSet<OutPoint>>();
        let shift_output_map_for_opreturn_first = self.prepare_psbt_for_coloring(psbt)?;
        let mut runtime = self.rgb_runtime()?;
        let (fascia, asset_beneficiaries) = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info.clone(),
            prev_outputs.clone(),
            false,
            shift_output_map_for_opreturn_first,
        )?;
        let result = self.prepare_consume_and_transfer_runtime(
            &mut runtime,
            psbt,
            fascia,
            asset_beneficiaries,
            &prev_outputs,
            &coloring_info,
            shift_output_map_for_opreturn_first,
        )?;
        info!(self.logger(), "Color PSBT prepare-consume completed");
        Ok(result)
    }

    /// Shared setup for [`Self::color_psbt_for_outpoints`] and
    /// [`Self::color_psbt_for_outpoints_and_consume`]: empty/subset checks, validate allocations,
    /// prepare PSBT. Returns `(runtime, override_set)`.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn prepare_color_psbt_for_outpoints(
        &self,
        psbt: &mut Psbt,
        coloring_info: &ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<(RgbRuntime, HashSet<OutPoint>), Error> {
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
        let runtime = self.rgb_runtime()?;
        self.validate_color_psbt_for_outpoints_inputs(
            &runtime,
            psbt,
            &override_set,
            &psbt_inputs,
            coloring_info,
        )?;
        // Signed-PSBT check; OP_RETURN is already required. Ignore the legacy P2TR shift flag —
        // this API always uses final vout indices.
        let _ = self.prepare_psbt_for_coloring(psbt)?;
        Ok((runtime, override_set))
    }

    /// Color a PSBT using a provided set of input outpoints.
    ///
    /// `input_outpoints` must be a non-empty subset of the PSBT inputs. Any PSBT input that
    /// still carries RGB allocations is rejected: omitted inputs must not carry allocations,
    /// and included inputs must have every allocated contract listed in `coloring_info`.
    ///
    /// The PSBT must already contain an OP_RETURN output. If any output is P2TR (RGB
    /// `OpretFirst`), that OP_RETURN must be output 0 so the fascia commitment precedes taproot
    /// outputs. This entry point is meant for externally constructed (HTLC) transactions whose
    /// output layout must not be rewritten.
    ///
    /// # `output_map` index convention (differs from [`Self::color_psbt`])
    ///
    /// Keys are always **final PSBT vout indices**. This method never inserts outputs and never
    /// shifts keys. Do **not** pass the pre-OP_RETURN indices used by [`Self::color_psbt`] when
    /// that method applies the P2TR / `OpretFirst` +1 shift — using the wrong base silently seals
    /// the wrong output.
    ///
    /// Coloring must happen **before** any input is signed (same rule as [`Self::color_psbt`]).
    ///
    /// Every contract listed in `coloring_info` must allocate the full available amount from the
    /// selected inputs; under-allocation is rejected (no implicit burn).
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn color_psbt_for_outpoints(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<(Fascia, AssetBeneficiariesMap), Error> {
        info!(self.logger(), "Coloring PSBT...");
        let (runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints)?;
        let result = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info,
            override_set,
            true,
            false,
        );
        info!(self.logger(), "Color PSBT completed");
        result
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn validate_color_psbt_for_outpoints_inputs(
        &self,
        runtime: &RgbRuntime,
        psbt: &Psbt,
        override_set: &HashSet<OutPoint>,
        psbt_inputs: &HashSet<OutPoint>,
        coloring_info: &ColoringInfo,
    ) -> Result<(), Error> {
        let omitted: Vec<OutPoint> = psbt_inputs.difference(override_set).copied().collect();
        if !omitted.is_empty() {
            let assigning = runtime.contracts_assigning(omitted)?;
            if !assigning.is_empty() {
                let contracts = assigning
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(Error::InvalidColoringInfo {
                    details: format!(
                        "PSBT inputs omitted from input_outpoints carry RGB allocations for {contracts}"
                    ),
                });
            }
        }
        let colored_contracts: BTreeSet<ContractId> =
            coloring_info.asset_info_map.keys().copied().collect();
        let included_assigning = runtime.contracts_assigning(override_set.iter().copied())?;
        let uncolored: Vec<ContractId> = included_assigning
            .difference(&colored_contracts)
            .copied()
            .collect();
        if !uncolored.is_empty() {
            let contracts = uncolored
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::InvalidColoringInfo {
                details: format!(
                    "PSBT inputs in input_outpoints carry RGB allocations for contracts not listed in coloring_info: {contracts}"
                ),
            });
        }
        let outputs = &psbt.unsigned_tx.output;
        let has_p2tr = outputs.iter().any(|o| o.script_pubkey.is_p2tr());
        match outputs.iter().position(|o| o.script_pubkey.is_op_return()) {
            None => {
                return Err(Error::InvalidColoringInfo {
                    details: s!("PSBT must include an OP_RETURN output"),
                });
            }
            Some(0) => {}
            // RGB OpretFirst: with P2TR outputs the fascia OP_RETURN must precede them (vout 0).
            Some(_) if has_p2tr => {
                return Err(Error::InvalidColoringInfo {
                    details: s!("OP_RETURN must be the first PSBT output"),
                });
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Color a PSBT for explicit input outpoints, build consignments, register a fallible batch.
    ///
    /// Same recovery model as [`Self::color_psbt_and_consume`]: stash is updated only by
    /// [`Self::consume_transfer_fascia`] after broadcast; use `fail_transfers` if the tx is dropped.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn color_psbt_for_outpoints_and_consume(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<ColorConsumeResult, Error> {
        info!(self.logger(), "Coloring PSBT and preparing consume...");
        let (mut runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints)?;
        let (fascia, asset_beneficiaries) = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info.clone(),
            override_set.clone(),
            true,
            false,
        )?;
        let result = self.prepare_consume_and_transfer_runtime(
            &mut runtime,
            psbt,
            fascia,
            asset_beneficiaries,
            &override_set,
            &coloring_info,
            false,
        )?;
        info!(self.logger(), "Color PSBT prepare-consume completed");
        Ok(result)
    }

    /// Apply a fascia previously prepared by [`Self::color_psbt_and_consume`] (or the outpoints
    /// variant) into the RGB stash after the Bitcoin tx has been broadcast.
    ///
    /// Updates the batch to [`TransferStatus::WaitingConfirmations`]. The batch must still be
    /// [`TransferStatus::Initiated`].
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn consume_transfer_fascia(&self, batch_transfer_idx: i32) -> Result<(), Error> {
        info!(
            self.logger(),
            "Consuming transfer fascia for batch {batch_transfer_idx}..."
        );
        let txn = self.database().begin_transaction()?;
        let db_data = txn.get_db_data(false)?;
        let batch_transfer =
            txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;
        if batch_transfer.status != TransferStatus::Initiated {
            return Err(Error::Internal {
                details: format!(
                    "batch transfer {batch_transfer_idx} is {:?}, expected Initiated",
                    batch_transfer.status
                ),
            });
        }
        let txid = batch_transfer
            .txid
            .as_ref()
            .ok_or_else(|| Error::Internal {
                details: s!("color-consume batch transfer is missing txid"),
            })?;
        let fascia_path = self.get_transfer_dir(txid).join(FASCIA_FILE);
        let fascia_str = fs::read_to_string(&fascia_path)?;
        let fascia: Fascia = serde_json::from_str(&fascia_str).map_err(InternalError::from)?;
        self.rgb_runtime()?.consume_fascia(fascia, None)?;
        let mut updated: DbBatchTransferActMod = batch_transfer.into();
        updated.status = ActiveValue::Set(TransferStatus::WaitingConfirmations);
        txn.update_batch_transfer(&mut updated)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Consume transfer fascia completed");
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn htlc_ops_root(&self) -> PathBuf {
        self.wallet_dir().join(HTLC_OPS_DIR)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn htlc_op_dir(&self, operation_id: &str) -> PathBuf {
        self.htlc_ops_root().join(operation_id)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn htlc_read_meta(&self, operation_id: &str) -> Result<HtlcOpMeta, Error> {
        let path = self.htlc_op_dir(operation_id).join(HTLC_META_FILE);
        if !path.exists() {
            return Err(Error::HtlcOperationNotFound {
                operation_id: operation_id.to_string(),
            });
        }
        let raw = fs::read_to_string(&path)?;
        serde_json::from_str(&raw).map_err(|e| Error::Internal {
            details: format!("invalid HTLC operation meta: {e}"),
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn htlc_write_meta(&self, meta: &HtlcOpMeta) -> Result<(), Error> {
        let path = self.htlc_op_dir(&meta.operation_id).join(HTLC_META_FILE);
        let tmp = path.with_extension("json.tmp");
        let raw = serde_json::to_string_pretty(meta).map_err(InternalError::from)?;
        fs::write(&tmp, raw)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn new_htlc_operation_id() -> String {
        format!(
            "{:016x}{:016x}",
            rand::rng().random::<u64>(),
            rand::rng().random::<u64>()
        )
    }

    /// Color an HTLC (or other external) PSBT for explicit input outpoints, write file-backed
    /// payloads under `htlc_ops/{operation_id}/`, and persist SQL accounting for colored contracts.
    ///
    /// `output_map` keys are **final** PSBT vouts (same as [`Self::color_psbt_for_outpoints`]).
    /// Foreign escrow outpoints are listed in `escrow.json` (write-only audit log for integrators;
    /// the library never reads it back) and are **not** inserted as wallet TXOs / Input colorings.
    /// Wallet-owned destinations in `output_map` still get Change/Send rows so
    /// `get_asset_balance` / `list_unspents` stay consistent after claim.
    /// RGB stash is unchanged until [`Self::htlc_apply`].
    ///
    /// Other files under the op dir (`colored.psbt`, `consignments/*.rgb`) are also write-only
    /// artifacts for the caller; only `fascia` and `meta.json` are read by later HTLC methods.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn htlc_prepare(
        &self,
        psbt: &mut Psbt,
        coloring_info: ColoringInfo,
        input_outpoints: Vec<OutPoint>,
    ) -> Result<HtlcPrepareResult, Error> {
        info!(self.logger(), "Preparing HTLC color operation...");
        let (runtime, override_set) =
            self.prepare_color_psbt_for_outpoints(psbt, &coloring_info, input_outpoints)?;
        let (fascia, asset_beneficiaries) = self.color_psbt_with_prevouts_runtime(
            &runtime,
            psbt,
            coloring_info.clone(),
            override_set.clone(),
            true,
            false,
        )?;

        let witness_txid = psbt.get_txid();
        let mut transfers = vec![];
        let mut spent: HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>> = HashMap::new();

        for (contract_id, beneficiaries) in &asset_beneficiaries {
            let mut by_outpoint: HashMap<OutPoint, Vec<Assignment>> = HashMap::new();
            for (explicit_seal, opout_state_map) in
                runtime.contract_assignments_for(*contract_id, override_set.iter().copied())?
            {
                let outpoint = explicit_seal.to_outpoint();
                for (opout, state) in opout_state_map {
                    by_outpoint
                        .entry(outpoint)
                        .or_default()
                        .push(Assignment::from_opout_and_state(opout, &state));
                }
            }
            spent.insert(*contract_id, by_outpoint);

            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(*secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer_from_fascia(
                *contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                &fascia,
            )?);
        }

        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let escrow = self.collect_htlc_escrow_entries(&spent)?;

        let operation_id = Self::new_htlc_operation_id();
        let op_dir = self.htlc_op_dir(&operation_id);
        fs::create_dir_all(op_dir.join(HTLC_CONSIGNMENTS_DIR))?;

        let fascia_path = op_dir.join(FASCIA_FILE);
        let serialized_fascia = serde_json::to_string(&fascia).map_err(InternalError::from)?;
        fs::write(&fascia_path, serialized_fascia)?;
        fs::write(op_dir.join(HTLC_COLORED_PSBT_FILE), psbt.to_string())?;

        for transfer in &transfers {
            let asset_id = transfer.contract_id().to_string();
            let path = op_dir
                .join(HTLC_CONSIGNMENTS_DIR)
                .join(format!("{asset_id}.rgb"));
            transfer.save_file(&path).map_err(InternalError::from)?;
        }

        let escrow_raw = serde_json::to_string_pretty(&HtlcEscrowFile { entries: escrow })
            .map_err(InternalError::from)?;
        fs::write(op_dir.join(HTLC_ESCROW_FILE), escrow_raw)?;

        // Always persist SQL accounting for colored contracts. Foreign inputs are skipped for
        // Input colorings inside persist; wallet-owned `output_map` destinations still get
        // Change/Send rows so balance APIs stay consistent after claim/refund.
        let batch_transfer_idx = self.persist_color_consume_batch(
            psbt,
            &txid,
            &spent,
            &fascia,
            &coloring_info,
            false,
            &runtime,
        )?;
        drop(runtime);

        let meta = HtlcOpMeta {
            operation_id: operation_id.clone(),
            status: HtlcOperationStatus::Prepared,
            txid,
            created_at: now().unix_timestamp(),
            batch_transfer_idx: Some(batch_transfer_idx),
        };
        self.htlc_write_meta(&meta)?;
        self.trigger_auto_backup();

        let operation_dir = PathBuf::from(HTLC_OPS_DIR)
            .join(&operation_id)
            .to_string_lossy()
            .into_owned();
        info!(
            self.logger(),
            "HTLC prepare completed (operation_id={operation_id})"
        );
        Ok(HtlcPrepareResult {
            operation_id,
            colored_psbt: psbt.to_string(),
            operation_dir,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    /// Collect the spent outpoints that the wallet does not own, i.e. the escrow inputs of the
    /// operation. Wallet-owned inputs need no separate handling: they are covered by the batch.
    fn collect_htlc_escrow_entries(
        &self,
        spent: &HtlcSpentByContract,
    ) -> Result<Vec<HtlcEscrowEntry>, Error> {
        let txn = self.database().begin_transaction()?;
        let mut escrow = Vec::new();
        for (contract_id, by_outpoint) in spent {
            for (outpoint, assignments) in by_outpoint {
                let outpoint_obj: Outpoint = (*outpoint).into();
                if txn.get_txo(&outpoint_obj)?.is_none() {
                    escrow.push(HtlcEscrowEntry {
                        asset_id: contract_id.to_string(),
                        outpoint: outpoint_obj,
                        assignments: assignments.clone(),
                    });
                }
            }
        }
        Ok(escrow)
    }

    /// Apply a prepared HTLC operation's fascia into the RGB stash after broadcast.
    ///
    /// Order: validate linked batch (if any) → `consume_fascia` → SQL status → `meta.json`.
    /// Reordering cannot make stock+SQL crash-atomic; a durable journal is a follow-up. This
    /// order at least fails closed before mutating the stash when the batch is not `Initiated`.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn htlc_apply(&self, operation_id: &str) -> Result<(), Error> {
        info!(self.logger(), "Applying HTLC operation {operation_id}...");
        let mut meta = self.htlc_read_meta(operation_id)?;
        if meta.status != HtlcOperationStatus::Prepared {
            return Err(Error::InvalidHtlcOperationStatus {
                details: format!(
                    "operation {operation_id} is {:?}, expected Prepared",
                    meta.status
                ),
            });
        }

        if let Some(batch_transfer_idx) = meta.batch_transfer_idx {
            let txn = self.database().begin_transaction()?;
            let db_data = txn.get_db_data(false)?;
            let batch_transfer =
                txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;
            if batch_transfer.status != TransferStatus::Initiated {
                return Err(Error::Internal {
                    details: format!(
                        "HTLC batch transfer {batch_transfer_idx} is {:?}, expected Initiated",
                        batch_transfer.status
                    ),
                });
            }
            // Leave txn uncommitted until after consume_fascia; re-check below under a new txn.
            drop(txn);
        }

        let fascia_path = self.htlc_op_dir(operation_id).join(FASCIA_FILE);
        let fascia_str = fs::read_to_string(&fascia_path)?;
        let fascia: Fascia = serde_json::from_str(&fascia_str).map_err(InternalError::from)?;
        self.rgb_runtime()?.consume_fascia(fascia, None)?;

        if let Some(batch_transfer_idx) = meta.batch_transfer_idx {
            let txn = self.database().begin_transaction()?;
            let db_data = txn.get_db_data(false)?;
            let batch_transfer =
                txn.get_batch_transfer_or_fail(batch_transfer_idx, &db_data.batch_transfers)?;
            if batch_transfer.status != TransferStatus::Initiated {
                return Err(Error::Internal {
                    details: format!(
                        "HTLC batch transfer {batch_transfer_idx} is {:?}, expected Initiated",
                        batch_transfer.status
                    ),
                });
            }
            let mut updated: DbBatchTransferActMod = batch_transfer.into();
            updated.status = ActiveValue::Set(TransferStatus::WaitingConfirmations);
            txn.update_batch_transfer(&mut updated)?;
            self.update_backup_info(&txn, false)?;
            txn.commit()?;
        }

        meta.status = HtlcOperationStatus::Applied;
        self.htlc_write_meta(&meta)?;
        if meta.batch_transfer_idx.is_none() {
            let txn = self.database().begin_transaction()?;
            self.update_backup_info(&txn, false)?;
            txn.commit()?;
        }
        self.trigger_auto_backup();
        info!(self.logger(), "HTLC apply completed");
        Ok(())
    }

    /// Abort a prepared HTLC operation before apply (tx never broadcast).
    ///
    /// Rolls back a linked Initiated batch via `fail_transfers` when present.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn htlc_abort(&mut self, online: Online, operation_id: &str) -> Result<(), Error> {
        info!(self.logger(), "Aborting HTLC operation {operation_id}...");
        let mut meta = self.htlc_read_meta(operation_id)?;
        if meta.status != HtlcOperationStatus::Prepared {
            return Err(Error::InvalidHtlcOperationStatus {
                details: format!(
                    "operation {operation_id} is {:?}, expected Prepared",
                    meta.status
                ),
            });
        }
        if let Some(batch_transfer_idx) = meta.batch_transfer_idx {
            self.fail_transfers(online, Some(batch_transfer_idx), false, true)?;
        }
        meta.status = HtlcOperationStatus::Failed;
        self.htlc_write_meta(&meta)?;
        // Meta status change (and any fail_transfers DB update) must be durable under backup/VSS.
        let txn = self.database().begin_transaction()?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "HTLC abort completed");
        Ok(())
    }

    /// Read HTLC operation status; marks Settled when a linked batch has settled.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn htlc_reconcile(&self, operation_id: &str) -> Result<HtlcOperationStatus, Error> {
        let mut meta = self.htlc_read_meta(operation_id)?;
        if meta.status == HtlcOperationStatus::Applied
            && let Some(batch_transfer_idx) = meta.batch_transfer_idx
        {
            let txn = self.database().begin_transaction()?;
            let db_data = txn.get_db_data(false)?;
            if let Some(batch) = db_data
                .batch_transfers
                .iter()
                .find(|b| b.idx == batch_transfer_idx)
                && batch.status == TransferStatus::Settled
            {
                meta.status = HtlcOperationStatus::Settled;
                self.htlc_write_meta(&meta)?;
            }
        }
        Ok(meta.status)
    }

    /// Build consignments, persist an [`TransferStatus::Initiated`] batch + fascia on disk.
    /// Does **not** call `consume_fascia` (send-path ordering: recover via `fail_transfers` until
    /// [`Self::consume_transfer_fascia`] after broadcast).
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn prepare_consume_and_transfer_runtime(
        &self,
        runtime: &mut RgbRuntime,
        psbt: &Psbt,
        fascia: Fascia,
        asset_beneficiaries: AssetBeneficiariesMap,
        prev_outputs: &HashSet<OutPoint>,
        coloring_info: &ColoringInfo,
        shift_output_map_for_opreturn_first: bool,
    ) -> Result<ColorConsumeResult, Error> {
        let witness_txid = psbt.get_txid();
        let mut transfers = vec![];
        let mut spent: HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>> = HashMap::new();

        for (contract_id, beneficiaries) in &asset_beneficiaries {
            let mut by_outpoint: HashMap<OutPoint, Vec<Assignment>> = HashMap::new();
            for (explicit_seal, opout_state_map) in
                runtime.contract_assignments_for(*contract_id, prev_outputs.iter().copied())?
            {
                let outpoint = explicit_seal.to_outpoint();
                for (opout, state) in opout_state_map {
                    by_outpoint
                        .entry(outpoint)
                        .or_default()
                        .push(Assignment::from_opout_and_state(opout, &state));
                }
            }
            spent.insert(*contract_id, by_outpoint);

            let mut beneficiaries_witness = vec![];
            let mut beneficiaries_blinded = vec![];
            for builder_seal in beneficiaries {
                match builder_seal {
                    BuilderSeal::Revealed(seal) => {
                        let explicit_seal = ExplicitSeal::with(witness_txid, seal.vout);
                        beneficiaries_witness.push(explicit_seal);
                    }
                    BuilderSeal::Concealed(secret_seal) => {
                        beneficiaries_blinded.push(*secret_seal);
                    }
                };
            }
            transfers.push(runtime.transfer_from_fascia(
                *contract_id,
                beneficiaries_witness,
                beneficiaries_blinded,
                &fascia,
            )?);
        }

        let txid = psbt.unsigned_tx.compute_txid().to_string();
        let batch_transfer_idx = self.persist_color_consume_batch(
            psbt,
            &txid,
            &spent,
            &fascia,
            coloring_info,
            shift_output_map_for_opreturn_first,
            runtime,
        )?;
        self.trigger_auto_backup();
        Ok(ColorConsumeResult {
            transfers,
            batch_transfer_idx,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn persist_color_consume_batch(
        &self,
        psbt: &Psbt,
        txid: &str,
        spent: &HashMap<ContractId, HashMap<OutPoint, Vec<Assignment>>>,
        fascia: &Fascia,
        coloring_info: &ColoringInfo,
        shift_output_map_for_opreturn_first: bool,
        runtime: &RgbRuntime,
    ) -> Result<i32, Error> {
        let transfer_dir = self.get_transfer_dir(txid);
        fs::create_dir_all(&transfer_dir)?;
        let fascia_path = transfer_dir.join(FASCIA_FILE);
        let serialized_fascia = serde_json::to_string(fascia).map_err(InternalError::from)?;
        fs::write(fascia_path, serialized_fascia)?;

        let created_at = now().unix_timestamp();
        let bitcoin_network = self.bitcoin_network();
        let txn = self.database().begin_transaction()?;
        let batch_transfer = DbBatchTransferActMod {
            txid: ActiveValue::Set(Some(txid.to_string())),
            status: ActiveValue::Set(TransferStatus::Initiated),
            expiration: ActiveValue::Set(None),
            created_at: ActiveValue::Set(created_at),
            min_confirmations: ActiveValue::Set(1),
            ..Default::default()
        };
        let batch_transfer_idx = txn.set_batch_transfer(batch_transfer)?;

        for (contract_id, by_outpoint) in spent {
            let asset_id = contract_id.to_string();
            let asset_schema = AssetSchema::get_from_contract_id(*contract_id, runtime)?;
            let asset_transfer = DbAssetTransferActMod {
                user_driven: ActiveValue::Set(true),
                batch_transfer_idx: ActiveValue::Set(batch_transfer_idx),
                asset_id: ActiveValue::Set(Some(asset_id)),
                ..Default::default()
            };
            let asset_transfer_idx = txn.set_asset_transfer(asset_transfer)?;

            for (outpoint, assignments) in by_outpoint {
                let outpoint: Outpoint = (*outpoint).into();
                // Only wallet-owned TXOs (already synced) get Input colorings. Foreign /
                // HTLC escrow outpoints must not be inserted as live wallet TXOs — track
                // them via `htlc_prepare` escrow.json instead.
                let Some(txo) = txn.get_txo(&outpoint)? else {
                    continue;
                };
                let txo_idx = txo.idx;

                for assignment in assignments {
                    let db_coloring = DbColoringActMod {
                        txo_idx: ActiveValue::Set(txo_idx),
                        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                        r#type: ActiveValue::Set(ColoringType::Input),
                        assignment: ActiveValue::Set(assignment.clone()),
                        ..Default::default()
                    };
                    txn.set_coloring(db_coloring)?;
                }
            }

            let mut external_destinations: Vec<(u32, u64, String)> = Vec::new();
            let mut change_destinations: Vec<(u32, u64, String)> = Vec::new();
            if let Some(asset_coloring) = coloring_info.asset_info_map.get(contract_id) {
                for (mut vout, amount) in asset_coloring.output_map.clone() {
                    if amount == 0 {
                        continue;
                    }
                    if shift_output_map_for_opreturn_first {
                        vout += 1;
                    }
                    if vout as usize >= psbt.unsigned_tx.output.len() {
                        return Err(Error::InvalidColoringInfo {
                            details: s!(
                                "invalid vout in output_map, does not exist in the given PSBT"
                            ),
                        });
                    }
                    let txout = &psbt.unsigned_tx.output[vout as usize];
                    if txout.script_pubkey.is_op_return() {
                        return Err(Error::InvalidColoringInfo {
                            details: format!(
                                "output_map vout {vout} points to the OP_RETURN output"
                            ),
                        });
                    }
                    let recipient_id =
                        recipient_id_from_script_buf(txout.script_pubkey.clone(), bitcoin_network);
                    let output_assignment =
                        Self::assignment_for_coloring_output(asset_schema, amount);
                    if self.bdk_wallet().is_mine(txout.script_pubkey.clone()) {
                        let outpoint = Outpoint {
                            txid: txid.to_string(),
                            vout,
                        };
                        let txo_idx = match txn.get_txo(&outpoint)? {
                            Some(txo) => txo.idx,
                            None => {
                                let db_utxo = DbTxoActMod {
                                    txid: ActiveValue::Set(txid.to_string()),
                                    vout: ActiveValue::Set(vout),
                                    btc_amount: ActiveValue::Set(txout.value.to_sat().to_string()),
                                    spent: ActiveValue::Set(false),
                                    exists: ActiveValue::Set(false),
                                    pending_witness: ActiveValue::Set(false),
                                    ..Default::default()
                                };
                                txn.set_txo(db_utxo)?
                            }
                        };
                        let db_coloring = DbColoringActMod {
                            txo_idx: ActiveValue::Set(txo_idx),
                            asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                            r#type: ActiveValue::Set(ColoringType::Change),
                            assignment: ActiveValue::Set(output_assignment.clone()),
                            ..Default::default()
                        };
                        txn.set_coloring(db_coloring)?;
                        change_destinations.push((vout, amount, recipient_id));
                    } else {
                        external_destinations.push((vout, amount, recipient_id));
                    }
                }
            }

            let transfer_destinations = if !external_destinations.is_empty() {
                external_destinations
            } else {
                // Pure self-send / change: still need a non-Burn transfer row.
                change_destinations
            };

            if transfer_destinations.is_empty() {
                // No output_map destinations (should not happen for colored sends); keep a
                // Send-shaped row so refresh does not treat an empty list as incoming.
                let first_assignment = by_outpoint.values().flatten().next().cloned();
                txn.set_transfer(DbTransferActMod {
                    asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                    requested_assignment: ActiveValue::Set(first_assignment),
                    incoming: ActiveValue::Set(false),
                    recipient_id: ActiveValue::Set(Some(format!("color:{txid}"))),
                    recipient_type: ActiveValue::Set(Some(RecipientTypeFull::Witness {
                        vout: None,
                        recipient_nonce: vec![],
                    })),
                    ..Default::default()
                })?;
            } else {
                for (vout, amount, recipient_id) in transfer_destinations {
                    let requested = Self::assignment_for_coloring_output(asset_schema, amount);
                    txn.set_transfer(DbTransferActMod {
                        asset_transfer_idx: ActiveValue::Set(asset_transfer_idx),
                        requested_assignment: ActiveValue::Set(Some(requested)),
                        incoming: ActiveValue::Set(false),
                        recipient_id: ActiveValue::Set(Some(recipient_id)),
                        recipient_type: ActiveValue::Set(Some(RecipientTypeFull::Witness {
                            vout: Some(vout),
                            recipient_nonce: vec![],
                        })),
                        ..Default::default()
                    })?;
                }
            }
        }

        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        Ok(batch_transfer_idx)
    }

    /// Map a coloring `output_map` amount to the SQL [`Assignment`] for this schema.
    ///
    /// `output_map` only carries fungible amounts / UDA presence (1). Explicit inflation-right
    /// destinations are not expressible via this map; those remain a follow-up for a richer API.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn assignment_for_coloring_output(asset_schema: AssetSchema, amount: u64) -> Assignment {
        match asset_schema {
            AssetSchema::Uda => Assignment::NonFungible,
            AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => Assignment::Fungible(amount),
        }
    }

    /// Inspect arbitrary outpoints for assignments of a given contract.
    ///
    /// Results are returned in the same order as `outpoints`, including duplicate entries.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    pub fn contract_assignments_for_outpoints(
        &self,
        contract_id: ContractId,
        outpoints: Vec<Outpoint>,
    ) -> Result<Vec<(Outpoint, Vec<Assignment>)>, Error> {
        let parsed: Vec<(Outpoint, OutPoint)> = outpoints
            .into_iter()
            .map(|outpoint| {
                let vout = outpoint.vout;
                let txid = crate::bitcoin::Txid::from_str(&outpoint.txid)
                    .map_err(|_| Error::InvalidTxid)?;
                Ok((outpoint, OutPoint { txid, vout }))
            })
            .collect::<Result<_, Error>>()?;

        let runtime = self.rgb_runtime()?;
        // Existence probe only — genesis contents are unused.
        runtime.genesis(contract_id)?;
        let state = runtime
            .contract_assignments_for(contract_id, parsed.iter().map(|(_, outpoint)| *outpoint))?;

        let mut by_outpoint: HashMap<OutPoint, Vec<Assignment>> = HashMap::new();
        for (seal, opout_state_map) in state {
            let btc_outpoint = OutPoint {
                txid: crate::bitcoin::Txid::from_str(&seal.txid.to_string()).map_err(|_| {
                    Error::Internal {
                        details: s!("invalid seal txid in contract assignments"),
                    }
                })?,
                vout: seal.vout.into_u32(),
            };
            let mut assignments = Vec::with_capacity(opout_state_map.len());
            for (opout, state) in opout_state_map {
                assignments.push(Assignment::from_opout_and_state(opout, &state));
            }
            by_outpoint.insert(btc_outpoint, assignments);
        }

        Ok(parsed
            .into_iter()
            .map(|(outpoint, btc_outpoint)| {
                let assignments = by_outpoint.get(&btc_outpoint).cloned().unwrap_or_default();
                (outpoint, assignments)
            })
            .collect())
    }

    /// Fetch an RGB consignment by recipient_id (proxy lookup key).
    ///
    /// **Unchecked:** the returned `txid` and `vout` come from the proxy and are **not**
    /// validated here. Prefer [`Self::fetch_and_accept_transfer_by_recipient_id`], which pins
    /// the witness output before accept. If you must use this with
    /// [`Self::accept_transfer_from_consignment_unchecked`], pin first: for witness recipient
    /// IDs, assert `output[vout].script_pubkey == script_buf_from_recipient_id(recipient_id)`.
    /// A malicious proxy can otherwise steer acceptance to an attacker-chosen witness.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn fetch_consignment_by_recipient_id_unchecked(
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

    /// Fetch a consignment by proxy key, pin the witness output to `witness_recipient_id`, and
    /// accept the transfer.
    ///
    /// `proxy_recipient_id` is the proxy lookup key (often the witness TXID). `witness_recipient_id`
    /// must be a witness recipient ID (`bc:wvout:...`) whose script is checked against
    /// `output[vout]` on the witness transaction before acceptance. Blinded recipient IDs cannot
    /// be pinned here; use the Rust-only [`Self::fetch_consignment_by_recipient_id_unchecked`] /
    /// [`Self::accept_transfer_from_consignment_unchecked`] pair with your own pin check.
    ///
    /// `expected` binds acceptance to the caller's intended contract, schema, assignment type, and
    /// amount; mismatches and empty assignment results are rejected.
    ///
    /// `min_confirmations` controls whether an unconfirmed (mempool / Tentative) witness is
    /// accepted: `0` allows it (reorg-exposed, useful for HTLC races); `>= 1` requires a mined
    /// witness with at least that many confirmations (`tip - mined_height + 1`).
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn fetch_and_accept_transfer_by_recipient_id(
        &mut self,
        proxy_recipient_id: String,
        witness_recipient_id: String,
        consignment_endpoint: RgbTransport,
        blinding: u64,
        min_confirmations: u8,
        expected: ExpectedTransfer,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        let (consignment, txid, vout) = self.fetch_consignment_by_recipient_id_unchecked(
            proxy_recipient_id,
            consignment_endpoint,
        )?;
        pin_witness_output_to_recipient_id(
            self.blockchain_resolver(),
            self.indexer(),
            self.chain_net(),
            &witness_recipient_id,
            &txid,
            vout,
            min_confirmations,
        )?;
        self.accept_transfer_from_consignment_unchecked(consignment, txid, vout, blinding, expected)
    }

    /// Create consignments for a PSBT created with the [`send_begin`](Wallet::send_begin) method.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn create_consignments(&self, psbt: String) -> Result<(), Error> {
        self.create_consignments_impl(psbt).map(|_| ())
    }

    /// Create consignments for a PSBT created with the [`send_begin`](Wallet::send_begin) method,
    /// returning the filesystem path of the consignment for the transferred asset.
    ///
    /// This requires the PSBT to send exactly one asset to a recipient; it returns an error
    /// otherwise, so a caller verifying the consignment before signing never verifies only a
    /// subset of a multi-recipient batch. This counts only recipient-directed transfers: other
    /// assets sharing the spent UTXOs may still move as change allocations back to the sender in
    /// the same transaction.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn create_consignments_return_path(&self, psbt: String) -> Result<String, Error> {
        let mut consignment_paths = self.create_consignments_impl(psbt)?;
        if consignment_paths.len() != 1 {
            return Err(Error::Internal {
                details: format!(
                    "expected exactly one asset transfer, found {}",
                    consignment_paths.len()
                ),
            });
        }
        Ok(consignment_paths.remove(0))
    }

    fn create_consignments_impl(&self, psbt: String) -> Result<Vec<String>, Error> {
        info!(self.logger(), "Creating consignments...");

        let psbt = Psbt::from_str(&psbt)?;
        let (txid, transfer_dir, info_contents, fascia) = self.get_transfer_end_data(&psbt)?;
        self.gen_consignments(&fascia, &info_contents.transfers, &transfer_dir)?;

        let consignment_paths = info_contents
            .transfers
            .keys()
            .map(|asset_id| {
                self.get_send_consignment_path(asset_id, &txid)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();

        info!(self.logger(), "Create consignments completed");
        Ok(consignment_paths)
    }

    /// Accept an RGB transfer using a consignment received out-of-band.
    ///
    /// Returns the consignment, the received assignments and the hex-encoded digests of the media
    /// attachments defined in the consignment.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer_consignment(
        &mut self,
        online: Online,
        consignment_path: PathBuf,
        txid: String,
        vout: u32,
        blinding: u64,
    ) -> Result<(RgbTransfer, Vec<Assignment>, HashSet<String>), Error> {
        info!(self.logger(), "Accepting transfer consignment...");
        self.check_online(online)?;
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let consignment =
            RgbTransfer::load_file(&consignment_path).map_err(|_| Error::InvalidFilePath {
                file_path: consignment_path.to_string_lossy().to_string(),
            })?;

        self.accept_transfer_with_consignment(consignment, witness_id, vout, blinding, None)
    }

    /// Accept an RGB transfer using a TXID to retrieve its consignment from the proxy.
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

        let (consignment, assignments, _media_digests) =
            self.accept_transfer_with_consignment(consignment, witness_id, vout, blinding, None)?;
        Ok((consignment, assignments))
    }

    /// Accept an RGB transfer from a pre-fetched consignment.
    ///
    /// **Unchecked:** `txid` and `vout` define the witness anchor used for validation but are
    /// not re-checked against a recipient ID or the blockchain. Prefer
    /// [`Self::fetch_and_accept_transfer_by_recipient_id`]. If composing manually, pin first
    /// (see [`Self::fetch_consignment_by_recipient_id_unchecked`]).
    ///
    /// `expected` must match the consignment contract, schema, and the single assignment revealed
    /// for `(txid, vout, blinding)`; empty or mismatched assignments are rejected before the
    /// transfer is accepted into the stash.
    ///
    /// <div class="warning">This method is meant for special usage on HTLC outpoints</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn accept_transfer_from_consignment_unchecked(
        &mut self,
        consignment: RgbTransfer,
        txid: String,
        vout: u32,
        blinding: u64,
        expected: ExpectedTransfer,
    ) -> Result<(RgbTransfer, Vec<Assignment>), Error> {
        info!(self.logger(), "Accepting transfer...");
        let witness_id = RgbTxid::from_str(&txid).map_err(|_| Error::InvalidTxid)?;
        let (consignment, assignments, _media_digests) = self.accept_transfer_with_consignment(
            consignment,
            witness_id,
            vout,
            blinding,
            Some(expected),
        )?;
        Ok((consignment, assignments))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn accept_transfer_with_consignment(
        &mut self,
        consignment: RgbTransfer,
        witness_id: RgbTxid,
        vout: u32,
        blinding: u64,
        expected: Option<ExpectedTransfer>,
    ) -> Result<(RgbTransfer, Vec<Assignment>, HashSet<String>), Error> {
        let schema_id = consignment.schema_id().to_string();
        let asset_schema: AssetSchema = schema_id.try_into()?;
        self.check_schema_support(&asset_schema)?;
        debug!(
            self.logger(),
            "Got consignment for asset with {} schema", asset_schema
        );

        if let Some(ref expected) = expected {
            Self::validate_expected_transfer_intent(&consignment, &asset_schema, expected)?;
        }

        let mut runtime = self.rgb_runtime()?;

        let graph_seal = GraphSeal::with_blinded_vout(vout, blinding);
        runtime.store_secret_seal(graph_seal)?;

        let resolver = OffchainResolver {
            witness_id,
            consignment: &consignment,
            fallback: self.blockchain_resolver(),
        };

        debug!(self.logger(), "Validating consignment...");
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

        let received_rgb_assignments =
            self.extract_received_assignments(&consignment, witness_id, Some(vout), None);
        let mut received: Vec<Assignment> = received_rgb_assignments.into_values().collect();
        received.sort();

        if let Some(ref expected) = expected {
            Self::validate_expected_transfer_assignments(&received, expected)?;
        }

        let valid_contract = valid_consignment.clone().into_valid_contract();
        let media_digests = self
            .extract_attachments(&valid_contract, asset_schema)
            .iter()
            .map(|a| hex::encode(a.digest))
            .collect::<HashSet<_>>();
        runtime.import_contract(valid_contract, self.blockchain_resolver())?;

        runtime.accept_transfer(valid_consignment, &resolver)?;

        info!(self.logger(), "Accept transfer completed");
        Ok((consignment, received, media_digests))
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn validate_expected_transfer_intent(
        consignment: &RgbTransfer,
        asset_schema: &AssetSchema,
        expected: &ExpectedTransfer,
    ) -> Result<(), Error> {
        if matches!(expected.assignment, Assignment::Any) {
            return Err(Error::InvalidAssignment);
        }
        let contract_id = consignment.contract_id().to_string();
        if contract_id != expected.asset_id {
            return Err(Error::UnexpectedTransfer {
                details: format!(
                    "contract id mismatch: got {contract_id}, expected {}",
                    expected.asset_id
                ),
            });
        }
        if asset_schema != &expected.asset_schema {
            return Err(Error::UnexpectedTransfer {
                details: format!(
                    "schema mismatch: got {asset_schema}, expected {}",
                    expected.asset_schema
                ),
            });
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn validate_expected_transfer_assignments(
        received: &[Assignment],
        expected: &ExpectedTransfer,
    ) -> Result<(), Error> {
        if received.is_empty() {
            return Err(Error::UnexpectedTransfer {
                details: s!("no assignments for the given witness seal"),
            });
        }
        if received != [expected.assignment.clone()] {
            return Err(Error::UnexpectedTransfer {
                details: format!(
                    "assignment mismatch: got {received:?}, expected {:?}",
                    expected.assignment
                ),
            });
        }
        Ok(())
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
    pub fn get_tx_height(&self, online: Online, txid: String) -> Result<Option<u32>, Error> {
        info!(self.logger(), "Getting TX height...");
        self.check_online(online)?;
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
        online: Online,
        after_height: u32,
        force_witnesses: Vec<RgbTxid>,
    ) -> Result<UpdateRes, Error> {
        info!(self.logger(), "Updating witnesses...");
        self.check_online(online)?;
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
    pub fn upsert_witness(
        &self,
        witness_id: RgbTxid,
        witness_ord: WitnessOrd,
    ) -> Result<(), Error> {
        let mut runtime = self.rgb_runtime()?;
        runtime.upsert_witness(witness_id, witness_ord)?;
        Ok(())
    }

    /// Extract the metadata of a new RGB asset and save the asset into the DB.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn save_new_asset(
        &self,
        online: Online,
        consignment: RgbTransfer,
        offchain_txid: String,
    ) -> Result<(), Error> {
        info!(self.logger(), "Saving new asset...");
        self.check_online(online)?;
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
        let valid_transfer = match consignment.clone().validate(&resolver, &validation_config) {
            Ok(consignment) => consignment,
            Err(ValidationError::InvalidConsignment(error)) => {
                error!(self.logger(), "Consignment is invalid: {}", error);
                return Err(Error::InvalidConsignment);
            }
            Err(ValidationError::ResolverError(error)) => {
                return Err(Error::Network {
                    details: error.to_string(),
                });
            }
        };
        let valid_contract = valid_transfer.clone().into_valid_contract();

        let runtime = self.rgb_runtime()?;
        let txn = self.database().begin_transaction()?;
        if txn.get_asset(contract_id.to_string())?.is_some() {
            // Metadata registration is idempotent only when the RGB stock agrees with the database.
            // A missing stock entry means the caller has not completed transfer acceptance.
            runtime.export_contract(contract_id)?;
            drop(txn);
            info!(self.logger(), "Save new asset completed");
            return Ok(());
        }
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

    /// Return whether the RGB asset with the provided ID is known to the wallet.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn is_asset_known(&self, contract_id: ContractId) -> Result<bool, Error> {
        let asset_id = contract_id.to_string();
        info!(
            self.logger(),
            "Checking if asset '{}' is known...", asset_id
        );
        let txn = self.database().begin_transaction()?;
        let known = txn.get_asset(asset_id)?.is_some();
        txn.commit()?;
        info!(self.logger(), "Check if asset is known completed");
        Ok(known)
    }

    /// List the media files for a given RGB asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn list_asset_media(&self, asset_id: String) -> Result<HashSet<Media>, Error> {
        info!(self.logger(), "Listing media for asset '{}'...", asset_id);
        let txn = self.database().begin_transaction()?;
        let asset = txn.check_asset_exists(asset_id)?;
        let token = match asset.schema {
            AssetSchema::Uda => self.get_asset_token(
                asset.idx,
                &txn.iter_media()?,
                &txn.iter_tokens()?,
                &txn.iter_token_medias()?,
            ),
            AssetSchema::Nia | AssetSchema::Cfa | AssetSchema::Ifa => None,
        };
        let medias = self.get_asset_medias(&txn, asset.media_idx, token)?;
        txn.commit()?;
        info!(self.logger(), "List asset media completed");
        Ok(medias)
    }

    /// Return the consignment file path for a send transfer of an asset.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    pub fn get_send_consignment_path(&self, asset_id: &str, transfer_id: &str) -> PathBuf {
        self.send_consignment_path(asset_id, transfer_id)
    }

    /// Complete the donation send operation by updating the DB only. This will also broadcast the
    /// transaction to update the DB with the new UTXOs and BDK.
    ///
    /// <div class="warning">This method is meant for special usage and is normally not needed, use
    /// it only if you know what you're doing</div>
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn send_end_db_update_only(
        &mut self,
        online: Online,
        signed_psbt: String,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending (end) db update only...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;

        // this will also update the DB with the new UTXOs and BDK
        self.broadcast_psbt(&txn, &psbt)?;

        let (txid, _, info_contents, _) = self.get_transfer_end_data(&psbt)?;

        let batch_transfer_idx = self.update_or_save_transfers(
            &txn,
            txid.clone(),
            &info_contents,
            TransferStatus::WaitingConfirmations,
            true,
        )?;

        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();

        info!(self.logger(), "Send (end) db update only completed");
        Ok(OperationResult {
            txid,
            batch_transfer_idx,
            entropy: info_contents.entropy,
        })
    }
}

#[cfg(test)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
mod tests {
    use super::*;

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    #[test]
    fn display_indexer_protocol() {
        assert_eq!(IndexerProtocol::Electrum.to_string(), "Electrum");
        assert_eq!(IndexerProtocol::Esplora.to_string(), "Esplora");
    }
}
