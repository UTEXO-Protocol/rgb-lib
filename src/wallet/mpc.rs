//! RGB MPC wallet module.
//!
//! This module defines the [`MpcWallet`] structure for MPC-based RGB wallets.
//! MPC wallets use an external MPC provider for key generation and signing,
//! with no local key material.

use super::*;

use crate::mpc::{MpcAddressInfo, MpcWalletProvider};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::wallet::mpc_psbt;
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::wallet::online::{UTXO_NUM, UTXO_SIZE};

// Re-use the NUMS constants from multisig (BIP-341 Nothing-Up-My-Sleeve point)
const NUMS_TPUB_TESTNET: &str = "tpubD6NzVbkrYhZ4WLczPJWReQycCJdd6YVWXubbVUFnJ5KgU5MDQrD998ZJLSmaB7GVcCnJSDWprxmrGkJ6SvgQC6QAffVpqSvonXmeizXcrkN";
const NUMS_XPUB_MAINNET: &str = "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6QgnecKFpJFPpdzxKrwoaZoV44qAJewsc4kX9vGaCaBExuvJH57";

/// An RGB wallet backed by an MPC provider for key management and signing.
///
/// Can be obtained with the [`MpcWallet::new`] method.
pub struct MpcWallet {
    pub(crate) internals: WalletInternals,
    pub(crate) provider: Box<dyn MpcWalletProvider>,
    /// Identifier used by the MPC provider (e.g. DFNS Bitcoin wallet ID).
    #[allow(dead_code)]
    pub(crate) wallet_id: String,
}

impl WalletCore for MpcWallet {
    fn internals(&self) -> &WalletInternals {
        &self.internals
    }

    fn internals_mut(&mut self) -> &mut WalletInternals {
        &mut self.internals
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn sync_db_txos(&mut self, _full_scan: bool, _include_spent: bool) -> Result<(), Error> {
        debug!(self.logger(), "MPC: Syncing TXOs from indexer...");

        // Get colored (External) MPC addresses and query indexer for their UTXOs
        let colored_addrs = self.database().get_mpc_addresses_by_keychain(0)?;

        let db_txos = self.database().iter_txos()?;
        let db_outpoints: HashSet<String> = db_txos
            .into_iter()
            .filter(|t| t.exists && !t.spent)
            .map(|u| u.outpoint().to_string())
            .collect();

        let pending_witness_scripts: Vec<String> = self
            .database()
            .iter_pending_witness_scripts()?
            .into_iter()
            .map(|s| s.script)
            .collect();

        for addr in &colored_addrs {
            let script = ScriptBuf::from_hex(&addr.script_pubkey).map_err(|e| Error::Internal {
                details: format!("invalid script_pubkey hex: {e}"),
            })?;
            let utxos = self.indexer().list_unspent_for_script(&script)?;

            for (outpoint, txout) in utxos {
                let op_str = outpoint.to_string();
                if db_outpoints.contains(&op_str) {
                    continue;
                }

                let mut new_db_utxo = DbTxoActMod {
                    idx: ActiveValue::NotSet,
                    txid: ActiveValue::Set(outpoint.txid.to_string()),
                    vout: ActiveValue::Set(outpoint.vout),
                    btc_amount: ActiveValue::Set(txout.value.to_sat().to_string()),
                    spent: ActiveValue::Set(false),
                    exists: ActiveValue::Set(true),
                    pending_witness: ActiveValue::Set(false),
                };

                if !pending_witness_scripts.is_empty() {
                    let script_hex = txout.script_pubkey.to_hex_string();
                    if pending_witness_scripts.contains(&script_hex) {
                        new_db_utxo.pending_witness = ActiveValue::Set(true);
                        self.database().del_pending_witness_script(script_hex)?;
                    }
                }

                self.database().set_txo(new_db_utxo)?;
            }
        }

        debug!(self.logger(), "MPC: Synced TXOs");
        Ok(())
    }
}

impl WalletBackup for MpcWallet {}

impl WalletOffline for MpcWallet {
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn get_new_addresses(
        &mut self,
        keychain: KeychainKind,
        _count: u32,
    ) -> Result<BdkAddress, Error> {
        let keychain_u8 = match keychain {
            KeychainKind::External => 0u8,
            KeychainKind::Internal => 1u8,
        };
        let index = self.database().get_next_mpc_derivation_index(keychain_u8)?;

        let addr_info: MpcAddressInfo =
            self.provider
                .create_address(self.bitcoin_network(), keychain, index)?;

        // Save to DB
        let db_addr = database::entities::mpc_address::ActiveModel {
            address: ActiveValue::Set(addr_info.address.clone()),
            script_pubkey: ActiveValue::Set(addr_info.script_pubkey.to_hex_string()),
            signing_key_id: ActiveValue::Set(addr_info.signing_key_id),
            keychain: ActiveValue::Set(keychain_u8),
            derivation_index: ActiveValue::Set(index),
            ..Default::default()
        };
        self.database().set_mpc_address(db_addr)?;

        let address = parse_address_str(&addr_info.address, self.bitcoin_network())?;
        Ok(address)
    }

    fn internal_unspents(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        // Return empty iterator — MPC vanilla UTXOs are tracked separately
        // This is OK because all callers that need vanilla UTXOs are overridden
        std::iter::empty()
    }

    fn get_uncolorable_btc_sum(&self) -> Result<u64, Error> {
        #[cfg(any(feature = "electrum", feature = "esplora"))]
        {
            if self.online_data().is_none() {
                return Ok(0);
            }
            let utxos = self.query_vanilla_utxos()?;
            Ok(utxos.iter().map(|(_, txout, _)| txout.value.to_sat()).sum())
        }
        #[cfg(not(any(feature = "electrum", feature = "esplora")))]
        {
            Ok(0)
        }
    }

    fn get_btc_balance_impl(
        &mut self,
        online: Option<Online>,
        skip_sync: bool,
    ) -> Result<BtcBalance, Error> {
        self.sync_if_requested(online, skip_sync)?;

        #[cfg(any(feature = "electrum", feature = "esplora"))]
        {
            let vanilla_utxos = self.query_vanilla_utxos()?;
            let vanilla_total: u64 = vanilla_utxos
                .iter()
                .map(|(_, txout, _)| txout.value.to_sat())
                .sum();

            let colored_addrs = self.database().get_mpc_addresses_by_keychain(0)?;
            let mut colored_total: u64 = 0;
            for addr in &colored_addrs {
                let script =
                    ScriptBuf::from_hex(&addr.script_pubkey).map_err(|e| Error::Internal {
                        details: format!("invalid script_pubkey hex: {e}"),
                    })?;
                let utxos = self.indexer().list_unspent_for_script(&script)?;
                colored_total += utxos
                    .iter()
                    .map(|(_, txout)| txout.value.to_sat())
                    .sum::<u64>();
            }

            Ok(BtcBalance {
                vanilla: Balance {
                    settled: vanilla_total,
                    future: vanilla_total,
                    spendable: vanilla_total,
                },
                colored: Balance {
                    settled: colored_total,
                    future: colored_total,
                    spendable: colored_total,
                },
            })
        }
        #[cfg(not(any(feature = "electrum", feature = "esplora")))]
        {
            Err(Error::Offline)
        }
    }
}

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl WalletOnline for MpcWallet {
    fn wallet_specific_consistency_checks(&mut self) -> Result<(), Error> {
        // MPC wallets don't have BDK UTXOs to cross-check
        Ok(())
    }

    fn list_internal_for_broadcast(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        // Return empty — MPC vanilla UTXOs don't exist in BDK
        // broadcast_psbt uses this to skip marking internal inputs as spent
        // For MPC, all inputs are colored (External) and should be marked spent
        std::iter::empty()
    }

    fn broadcast_psbt(
        &mut self,
        signed_psbt: &Psbt,
        skip_sync: bool,
    ) -> Result<BdkTransaction, Error> {
        let tx = self.broadcast_tx(
            signed_psbt
                .clone()
                .extract_tx()
                .map_err(InternalError::from)?,
        )?;

        // Mark spent colored UTXOs in DB (skip vanilla UTXOs not tracked in txo table)
        for input in &tx.input {
            let txid = input.previous_output.txid.to_string();
            let vout = input.previous_output.vout;
            if let Some(db_txo) = self.database().get_txo(&Outpoint {
                txid: txid.clone(),
                vout,
            })? {
                let mut db_txo: DbTxoActMod = db_txo.into();
                db_txo.spent = ActiveValue::Set(true);
                self.database().update_txo(db_txo)?;
            }
            // Vanilla UTXOs not in txo table — skip silently
        }

        if !skip_sync {
            self.sync_db_txos(false, false)?;
        }

        Ok(tx)
    }

    fn prepare_psbt(
        &mut self,
        input_outpoints: HashSet<BdkOutPoint>,
        witness_recipients: &Vec<(ScriptBuf, u64)>,
        fee_rate: FeeRate,
    ) -> Result<(Psbt, Option<BtcChange>), Error> {
        // Get vanilla UTXOs for funding
        let vanilla_utxos = self.query_vanilla_utxos()?;

        // Collect the required colored inputs (already selected by RGB logic)
        let colored_addrs = self.database().get_mpc_addresses_by_keychain(0)?;
        let mut selected_inputs: Vec<(OutPoint, TxOut)> = Vec::new();

        for addr in &colored_addrs {
            let script = ScriptBuf::from_hex(&addr.script_pubkey).map_err(|e| Error::Internal {
                details: format!("invalid script_pubkey hex: {e}"),
            })?;
            let utxos = self.indexer().list_unspent_for_script(&script)?;
            for (outpoint, txout) in utxos {
                if input_outpoints.contains(&outpoint) {
                    selected_inputs.push((outpoint, txout));
                }
            }
        }

        // Build outputs: OP_RETURN (placeholder, will be replaced by RGB layer) + witness recipients
        let mut outputs: Vec<TxOut> = vec![TxOut {
            value: BdkAmount::from_sat(0),
            script_pubkey: ScriptBuf::new_op_return([]),
        }];

        let mut required_output_value: u64 = 0;
        for (script, amount) in witness_recipients {
            outputs.push(TxOut {
                value: BdkAmount::from_sat(*amount),
                script_pubkey: script.clone(),
            });
            required_output_value += amount;
        }

        // Calculate total from colored inputs
        let colored_total: u64 = selected_inputs
            .iter()
            .map(|(_, txout)| txout.value.to_sat())
            .sum();

        // We need vanilla inputs to cover fees + witness recipient amounts
        let num_outputs = outputs.len() + 1; // +1 for change
        let estimated_fee =
            mpc_psbt::calculate_fee(selected_inputs.len() + 1, num_outputs, fee_rate);
        let needed_from_vanilla =
            (required_output_value + estimated_fee).saturating_sub(colored_total);

        if needed_from_vanilla > 0 {
            let available: Vec<(OutPoint, TxOut)> = vanilla_utxos
                .iter()
                .map(|(op, txout, _)| (*op, txout.clone()))
                .collect();
            let (extra_inputs, _) =
                mpc_psbt::select_coins(&available, needed_from_vanilla, fee_rate, num_outputs)?;
            selected_inputs.extend(extra_inputs);
        }

        // Recalculate total and fee
        let total_input: u64 = selected_inputs
            .iter()
            .map(|(_, txout)| txout.value.to_sat())
            .sum();
        let fee = mpc_psbt::calculate_fee(selected_inputs.len(), num_outputs, fee_rate);

        if total_input < required_output_value + fee {
            return Err(Error::InsufficientBitcoins {
                needed: required_output_value + fee,
                available: total_input,
            });
        }

        // Change output
        let change_amount = total_input - required_output_value - fee;
        let change_address = self.get_new_addresses(KeychainKind::Internal, 1)?;
        let change_script = change_address.script_pubkey();

        if change_amount > mpc_psbt::TAPROOT_DUST {
            outputs.push(TxOut {
                value: BdkAmount::from_sat(change_amount),
                script_pubkey: change_script.clone(),
            });
        }

        let psbt = mpc_psbt::build_psbt(selected_inputs, outputs)?;

        let btc_change = if change_amount > mpc_psbt::TAPROOT_DUST {
            Some(BtcChange {
                vout: (psbt.unsigned_tx.output.len() - 1) as u32,
                amount: change_amount,
            })
        } else {
            None
        };

        Ok((psbt, btc_change))
    }

    fn create_utxos_begin_impl(
        &mut self,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        if !skip_sync {
            self.sync_db_txos(false, false)?;
        }

        let unspent_txos = self.database().get_unspent_txos(vec![])?;
        let unspents = self
            .database()
            .get_rgb_allocations(unspent_txos, None, None, None, None)?;

        let mut utxos_to_create = num.unwrap_or(UTXO_NUM);
        if up_to {
            let allocatable = self.get_available_allocations(unspents, &[], None)?.len() as u8;
            if allocatable >= utxos_to_create {
                return Err(Error::AllocationsAlreadyAvailable);
            }
            utxos_to_create -= allocatable;
        }

        let utxo_size = size.unwrap_or(UTXO_SIZE);
        if utxo_size == 0 {
            return Err(Error::InvalidAmountZero);
        }

        // Get vanilla UTXOs for funding
        let vanilla_utxos = self.query_vanilla_utxos()?;
        let available: Vec<(OutPoint, TxOut)> = vanilla_utxos
            .iter()
            .map(|(op, txout, _)| (*op, txout.clone()))
            .collect();

        // Generate colored addresses for the new UTXOs
        let mut colored_outputs: Vec<TxOut> = Vec::new();
        let mut actual_count = utxos_to_create;

        while actual_count > 0 {
            let target = utxo_size as u64 * actual_count as u64;
            let num_outputs = actual_count as usize + 1; // +1 for change
            match mpc_psbt::select_coins(&available, target, fee_rate_checked, num_outputs) {
                Ok(_) => break,
                Err(Error::InsufficientBitcoins { .. }) => {
                    actual_count -= 1;
                    if actual_count == 0 {
                        let total: u64 = available
                            .iter()
                            .map(|(_, txout)| txout.value.to_sat())
                            .sum();
                        return Err(Error::InsufficientBitcoins {
                            needed: target
                                + mpc_psbt::calculate_fee(
                                    available.len(),
                                    num_outputs,
                                    fee_rate_checked,
                                ),
                            available: total,
                        });
                    }
                }
                Err(e) => return Err(e),
            }
        }

        for _ in 0..actual_count {
            let addr = self.get_new_addresses(KeychainKind::External, 1)?;
            colored_outputs.push(TxOut {
                value: BdkAmount::from_sat(utxo_size as u64),
                script_pubkey: addr.script_pubkey(),
            });
        }

        let target: u64 = colored_outputs.iter().map(|o| o.value.to_sat()).sum();
        let num_outputs = colored_outputs.len() + 1; // +1 for change
        let (selected, total) =
            mpc_psbt::select_coins(&available, target, fee_rate_checked, num_outputs)?;

        let fee = mpc_psbt::calculate_fee(selected.len(), num_outputs, fee_rate_checked);
        let change = total - target - fee;

        let mut outputs = colored_outputs;
        if change > mpc_psbt::TAPROOT_DUST {
            let change_addr = self.get_new_addresses(KeychainKind::Internal, 1)?;
            outputs.push(TxOut {
                value: BdkAmount::from_sat(change),
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        mpc_psbt::build_psbt(selected, outputs)
    }

    fn send_btc_begin_impl(
        &mut self,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        if !skip_sync {
            self.sync_db_txos(false, false)?;
        }

        let script_pubkey = self.get_script_pubkey(&address)?;

        // Get vanilla UTXOs, excluding colored ones
        let unspendable = self.get_unspendable_bdk_outpoints()?;
        let unspendable_set: HashSet<OutPoint> = unspendable.into_iter().collect();

        let vanilla_utxos = self.query_vanilla_utxos()?;
        let available: Vec<(OutPoint, TxOut)> = vanilla_utxos
            .into_iter()
            .filter(|(op, _, _)| !unspendable_set.contains(op))
            .map(|(op, txout, _)| (op, txout))
            .collect();

        let (selected, total) = mpc_psbt::select_coins(&available, amount, fee_rate_checked, 2)?;

        let fee = mpc_psbt::calculate_fee(selected.len(), 2, fee_rate_checked);
        let change = total - amount - fee;

        let mut outputs = vec![TxOut {
            value: BdkAmount::from_sat(amount),
            script_pubkey,
        }];

        if change > mpc_psbt::TAPROOT_DUST {
            let change_addr = self.get_new_addresses(KeychainKind::Internal, 1)?;
            outputs.push(TxOut {
                value: BdkAmount::from_sat(change),
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        mpc_psbt::build_psbt(selected, outputs)
    }

    fn drain_to_begin_impl(
        &mut self,
        address: String,
        destroy_assets: bool,
        fee_rate: u64,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        self.sync_db_txos(false, false)?;

        let script_pubkey = self.get_script_pubkey(&address)?;

        // Collect all UTXOs
        let vanilla_utxos = self.query_vanilla_utxos()?;
        let mut all_inputs: Vec<(OutPoint, TxOut)> = vanilla_utxos
            .into_iter()
            .map(|(op, txout, _)| (op, txout))
            .collect();

        if destroy_assets {
            let colored_addrs = self.database().get_mpc_addresses_by_keychain(0)?;
            for addr in &colored_addrs {
                let script =
                    ScriptBuf::from_hex(&addr.script_pubkey).map_err(|e| Error::Internal {
                        details: format!("invalid script_pubkey hex: {e}"),
                    })?;
                let utxos = self.indexer().list_unspent_for_script(&script)?;
                all_inputs.extend(utxos);
            }
        } else {
            // Filter out colored UTXOs
            let unspendable = self.get_unspendable_bdk_outpoints()?;
            let unspendable_set: HashSet<OutPoint> = unspendable.into_iter().collect();
            all_inputs.retain(|(op, _)| !unspendable_set.contains(op));
        }

        if all_inputs.is_empty() {
            return Err(Error::InsufficientBitcoins {
                needed: 1,
                available: 0,
            });
        }

        let total: u64 = all_inputs
            .iter()
            .map(|(_, txout)| txout.value.to_sat())
            .sum();
        let fee = mpc_psbt::calculate_fee(all_inputs.len(), 1, fee_rate_checked);

        if total <= fee {
            return Err(Error::InsufficientBitcoins {
                needed: fee + 1,
                available: total,
            });
        }

        let outputs = vec![TxOut {
            value: BdkAmount::from_sat(total - fee),
            script_pubkey,
        }];

        mpc_psbt::build_psbt(all_inputs, outputs)
    }
}

/// Common offline APIs.
impl RgbWalletOpsOffline for MpcWallet {}

/// Common online APIs.
#[cfg(any(feature = "electrum", feature = "esplora"))]
impl RgbWalletOpsOnline for MpcWallet {}

// ---------------------------------------------------------------------------
// MPC-specific helpers
// ---------------------------------------------------------------------------

impl MpcWallet {
    /// Create a new MPC wallet.
    pub fn new(
        wallet_data: WalletData,
        wallet_id: String,
        provider: Box<dyn MpcWalletProvider>,
    ) -> Result<Self, Error> {
        let bitcoin_network = wallet_data.bitcoin_network;
        let bdk_network = BdkNetwork::from(bitcoin_network);

        // NUMS-point descriptors — watch-only dummy, never used for signing
        let nums_key = match bitcoin_network {
            BitcoinNetwork::Mainnet => NUMS_XPUB_MAINNET,
            _ => NUMS_TPUB_TESTNET,
        };
        let desc_colored = format!("tr({nums_key}/0/*)");
        let desc_vanilla = format!("tr({nums_key}/1/*)");

        let fingerprint = hash_bytes_hex(wallet_id.as_bytes())[..8].to_string();
        let (wallet_dir, logger, _logger_guard) = setup_new_wallet(&wallet_data, &fingerprint)?;

        let (bdk_wallet, bdk_database) = setup_bdk(
            &wallet_data,
            &wallet_dir,
            desc_colored,
            desc_vanilla,
            true, // watch_only
            bdk_network,
        )?;

        setup_rgb(
            &wallet_dir,
            wallet_data.supported_schemas.clone(),
            bitcoin_network,
        )?;

        let database = setup_db(&wallet_dir)?;

        info!(logger, "New MPC wallet completed");
        Ok(Self {
            internals: WalletInternals {
                wallet_data,
                logger,
                _logger_guard,
                database: Arc::new(database),
                wallet_dir,
                bdk_wallet,
                bdk_database,
                #[cfg(any(feature = "electrum", feature = "esplora"))]
                online_data: None,
                #[cfg(feature = "vss")]
                vss_client: None,
                #[cfg(feature = "vss")]
                auto_backup_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            provider,
            wallet_id,
        })
    }

    /// Query vanilla (Internal keychain) UTXOs from the indexer.
    ///
    /// Returns (outpoint, txout, signing_key_id) tuples.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn query_vanilla_utxos(&self) -> Result<Vec<(OutPoint, TxOut, String)>, Error> {
        let addrs = self.database().get_mpc_addresses_by_keychain(1)?;
        let mut all_utxos = Vec::new();
        for addr in &addrs {
            let script = ScriptBuf::from_hex(&addr.script_pubkey).map_err(|e| Error::Internal {
                details: format!("invalid script_pubkey hex: {e}"),
            })?;
            let utxos = self.indexer().list_unspent_for_script(&script)?;
            for (outpoint, txout) in utxos {
                all_utxos.push((outpoint, txout, addr.signing_key_id.clone()));
            }
        }
        Ok(all_utxos)
    }

    /// Look up signing key IDs for each input in a PSBT.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn get_signing_key_ids_for_psbt(&self, psbt: &Psbt) -> Result<Vec<String>, Error> {
        let mut key_ids = Vec::new();
        for input in &psbt.inputs {
            if let Some(witness_utxo) = &input.witness_utxo {
                let script_hex = witness_utxo.script_pubkey.to_hex_string();
                let addr = self.database().get_mpc_address_by_script(&script_hex)?;
                key_ids.push(addr.signing_key_id);
            } else {
                return Err(Error::Internal {
                    details: s!("PSBT input missing witness_utxo"),
                });
            }
        }
        Ok(key_ids)
    }

    /// Sign a PSBT via the MPC provider and finalize it.
    ///
    /// After DFNS signs, we finalize each input by moving `tap_key_sig`
    /// into `final_script_witness` (required for `extract_tx()` to work).
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn mpc_sign_psbt(&self, psbt: Psbt) -> Result<Psbt, Error> {
        let key_ids = self.get_signing_key_ids_for_psbt(&psbt)?;
        let mut signed = self.provider.sign_psbt(psbt, key_ids)?;

        // Finalize Taproot key-path inputs
        for input in &mut signed.inputs {
            if let Some(sig) = input.tap_key_sig.take() {
                let mut witness = bdk_wallet::bitcoin::Witness::new();
                witness.push(sig.to_vec());
                input.final_script_witness = Some(witness);
                // Clear fields per BIP-371 finalization
                input.tap_internal_key = None;
                input.tap_merkle_root = None;
                input.tap_key_sig = None;
            }
        }

        Ok(signed)
    }

    // --- Offline RGB operations (delegate to trait defaults) ---

    fn finalize_offline_issuance<T: IssuedAssetDetails>(
        &self,
        issue_data: &IssueData,
    ) -> Result<T, Error> {
        let mut runtime = self.rgb_runtime()?;
        let asset = self.import_and_save_contract(issue_data, &mut runtime)?;
        T::from_issuance(self, &asset, issue_data)
    }

    /// Issue a new RGB NIA asset.
    pub fn issue_asset_nia(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<AssetNIA, Error> {
        self.issue_asset_nia_with_impl(ticker, name, precision, amounts, |issue_data| {
            self.finalize_offline_issuance(&issue_data)
        })
    }

    /// Create a blind receive.
    pub fn blind_receive(
        &mut self,
        asset_id: Option<String>,
        assignment: Assignment,
        expiration_timestamp: Option<u64>,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, Error> {
        info!(self.logger(), "Receiving via blinded UTXO...");

        let receive_data_internal = self.create_receive_data(
            asset_id,
            assignment,
            expiration_timestamp.map(|t| t as i64),
            transport_endpoints,
            RecipientType::Blind,
        )?;

        let batch_transfer_idx =
            self.store_receive_transfer(&receive_data_internal, min_confirmations)?;

        info!(self.logger(), "Blind receive completed");
        Ok(ReceiveData {
            invoice: receive_data_internal.invoice_string,
            recipient_id: receive_data_internal.recipient_id,
            expiration_timestamp: receive_data_internal.expiration_timestamp.map(|t| t as u64),
            batch_transfer_idx,
        })
    }

    /// List known RGB assets.
    pub fn list_assets(&self, filter_asset_schemas: Vec<AssetSchema>) -> Result<Assets, Error> {
        self.list_assets_impl(filter_asset_schemas)
    }

    /// Get asset balance.
    pub fn get_asset_balance(&self, asset_id: String) -> Result<Balance, Error> {
        self.get_asset_balance_impl(asset_id)
    }

    /// Get BTC balance.
    pub fn get_btc_balance(
        &mut self,
        online: Option<Online>,
        skip_sync: bool,
    ) -> Result<BtcBalance, Error> {
        RgbWalletOpsOffline::get_btc_balance(self, online, skip_sync)
    }
}

// ---------------------------------------------------------------------------
// Public API — online operations
// ---------------------------------------------------------------------------

#[cfg(any(feature = "electrum", feature = "esplora"))]
impl MpcWallet {
    /// Return the existing or freshly generated wallet [`Online`] data.
    pub fn go_online(
        &mut self,
        skip_consistency_check: bool,
        indexer_url: String,
    ) -> Result<Online, Error> {
        info!(self.logger(), "Going online...");
        let online = self.go_online_impl(skip_consistency_check, &indexer_url)?;
        info!(self.logger(), "Go online completed");
        Ok(online)
    }

    /// Sync the wallet.
    pub fn sync(&mut self, online: Online) -> Result<(), Error> {
        info!(self.logger(), "Syncing...");
        self.sync_impl(online)?;
        info!(self.logger(), "Sync completed");
        Ok(())
    }

    /// Return a new Bitcoin address from the vanilla wallet.
    pub fn get_address(&mut self) -> Result<String, Error> {
        info!(self.logger(), "Getting MPC address...");
        let address = self.get_new_addresses(KeychainKind::Internal, 1)?;
        info!(self.logger(), "Get MPC address completed");
        Ok(address.to_string())
    }

    /// Create new colored UTXOs (begin + MPC sign + end).
    pub fn create_utxos(
        &mut self,
        online: Online,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<u8, Error> {
        info!(self.logger(), "Creating UTXOs...");
        self.check_online(online)?;
        let psbt = self.create_utxos_begin_impl(up_to, num, size, fee_rate, skip_sync)?;
        let signed = self.mpc_sign_psbt(psbt)?;
        let res = self.create_utxos_end_impl(&signed, skip_sync)?;
        info!(self.logger(), "Create UTXOs completed");
        Ok(res)
    }

    /// Prepare unsigned PSBT for UTXO creation.
    pub fn create_utxos_begin(
        &mut self,
        online: Online,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Creating UTXOs (begin)...");
        self.check_online(online)?;
        let res = self.create_utxos_begin_impl(up_to, num, size, fee_rate, skip_sync)?;
        info!(self.logger(), "Create UTXOs (begin) completed");
        Ok(res.to_string())
    }

    /// Broadcast signed PSBT to create UTXOs.
    pub fn create_utxos_end(
        &mut self,
        online: Online,
        signed_psbt: String,
        skip_sync: bool,
    ) -> Result<u8, Error> {
        info!(self.logger(), "Creating UTXOs (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let res = self.create_utxos_end_impl(&psbt, skip_sync)?;
        info!(self.logger(), "Create UTXOs (end) completed");
        Ok(res)
    }

    /// Send RGB assets (begin + MPC sign + end).
    pub fn send(
        &mut self,
        online: Online,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
        skip_sync: bool,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending...");
        self.check_online(online)?;
        let mut begin_op_data = self.send_begin_impl(
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            expiration_timestamp.map(|t| t as i64),
            true,
        )?;
        begin_op_data.psbt = self.mpc_sign_psbt(begin_op_data.psbt)?;
        let res = self.send_end_impl(&begin_op_data.psbt, skip_sync)?;
        info!(self.logger(), "Send completed");
        Ok(res)
    }

    /// Prepare unsigned PSBT for RGB send.
    pub fn send_begin(
        &mut self,
        online: Online,
        recipient_map: HashMap<String, Vec<Recipient>>,
        donation: bool,
        fee_rate: u64,
        min_confirmations: u8,
        expiration_timestamp: Option<u64>,
        dry_run: bool,
    ) -> Result<SendBeginResult, Error> {
        info!(self.logger(), "Sending (begin)...");
        self.check_online(online)?;
        let begin_op_data = self.send_begin_impl(
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            expiration_timestamp.map(|t| t as i64),
            dry_run,
        )?;
        info!(self.logger(), "Send (begin) completed");
        Ok(SendBeginResult {
            psbt: begin_op_data.psbt.to_string(),
            batch_transfer_idx: begin_op_data.batch_transfer_idx,
            details: SendDetails {
                fascia_path: begin_op_data
                    .transfer_dir
                    .join(FASCIA_FILE)
                    .to_string_lossy()
                    .to_string(),
                min_confirmations,
                entropy: begin_op_data.info_batch_transfer.entropy,
                is_donation: donation,
            },
        })
    }

    /// Complete RGB send with signed PSBT.
    pub fn send_end(
        &mut self,
        online: Online,
        signed_psbt: String,
        skip_sync: bool,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let res = self.send_end_impl(&psbt, skip_sync)?;
        info!(self.logger(), "Send (end) completed");
        Ok(res)
    }

    /// Send BTC (begin + MPC sign + end).
    pub fn send_btc(
        &mut self,
        online: Online,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC...");
        self.check_online(online)?;
        let psbt = self.send_btc_begin_impl(address, amount, fee_rate, skip_sync)?;
        let signed = self.mpc_sign_psbt(psbt)?;
        let res = self.send_btc_end_impl(&signed, skip_sync)?;
        info!(self.logger(), "Send BTC completed");
        Ok(res)
    }

    /// Prepare unsigned PSBT for BTC send.
    pub fn send_btc_begin(
        &mut self,
        online: Online,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC (begin)...");
        self.check_online(online)?;
        let res = self.send_btc_begin_impl(address, amount, fee_rate, skip_sync)?;
        info!(self.logger(), "Send BTC (begin) completed");
        Ok(res.to_string())
    }

    /// Broadcast signed PSBT for BTC send.
    pub fn send_btc_end(
        &mut self,
        online: Online,
        signed_psbt: String,
        skip_sync: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let res = self.send_btc_end_impl(&psbt, skip_sync)?;
        info!(self.logger(), "Send BTC (end) completed");
        Ok(res)
    }

    /// Drain wallet to address (begin + MPC sign + end).
    pub fn drain_to(
        &mut self,
        online: Online,
        address: String,
        destroy_assets: bool,
        fee_rate: u64,
    ) -> Result<String, Error> {
        info!(self.logger(), "Draining...");
        self.check_online(online)?;
        let psbt = self.drain_to_begin_impl(address, destroy_assets, fee_rate)?;
        let signed = self.mpc_sign_psbt(psbt)?;
        let tx = self.drain_to_end_impl(&signed)?;
        info!(self.logger(), "Drain completed");
        Ok(tx.compute_txid().to_string())
    }

    /// Prepare unsigned PSBT for drain.
    pub fn drain_to_begin(
        &mut self,
        online: Online,
        address: String,
        destroy_assets: bool,
        fee_rate: u64,
    ) -> Result<String, Error> {
        info!(self.logger(), "Draining (begin)...");
        self.check_online(online)?;
        let psbt = self.drain_to_begin_impl(address, destroy_assets, fee_rate)?;
        info!(self.logger(), "Drain (begin) completed");
        Ok(psbt.to_string())
    }

    /// Broadcast signed PSBT for drain.
    pub fn drain_to_end(&mut self, online: Online, signed_psbt: String) -> Result<String, Error> {
        info!(self.logger(), "Draining (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let tx = self.drain_to_end_impl(&psbt)?;
        info!(self.logger(), "Drain (end) completed");
        Ok(tx.compute_txid().to_string())
    }

    /// Sign a PSBT string via MPC provider.
    pub fn sign_psbt(&self, unsigned_psbt: String) -> Result<String, Error> {
        info!(self.logger(), "Signing PSBT via MPC...");
        let psbt = Psbt::from_str(&unsigned_psbt)?;
        let signed = self.mpc_sign_psbt(psbt)?;
        info!(self.logger(), "Sign PSBT completed");
        Ok(signed.to_string())
    }

    /// Refresh RGB transfers.
    pub fn refresh(
        &mut self,
        online: Online,
        asset_id: Option<String>,
        filter: Vec<RefreshFilter>,
        skip_sync: bool,
    ) -> Result<RefreshResult, Error> {
        RgbWalletOpsOnline::refresh(self, online, asset_id, filter, skip_sync)
    }
}
