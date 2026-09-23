//! RGB MPC wallet module.
//!
//! This module defines the [`MpcWallet`] structure for MPC-based RGB wallets.
//! MPC wallets use an external MPC provider for key generation and signing,
//! with no local key material.

use super::*;

use crate::mpc::MpcWalletProvider;
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
    pub(crate) rgb_carrier_sat: u64,
}

impl WalletCore for MpcWallet {
    fn internals(&self) -> &WalletInternals {
        &self.internals
    }

    fn internals_mut(&mut self) -> &mut WalletInternals {
        &mut self.internals
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn sync_bdk_and_db_txos(
        &mut self,
        txn: &DbTxn,
        _options: SyncOptions,
        _include_spent: bool,
    ) -> Result<(), Error> {
        debug!(self.logger(), "MPC: Syncing TXOs from indexer...");

        // Get colored (External) MPC addresses and query indexer for their UTXOs
        let colored_addrs = txn.get_mpc_addresses_by_keychain(0)?;

        for addr in &colored_addrs {
            let script = ScriptBuf::from_hex(&addr.script_pubkey).map_err(|e| Error::Internal {
                details: format!("invalid script_pubkey hex: {e}"),
            })?;
            let utxos = self.indexer().list_unspent_for_script(&script)?;

            self.record_indexed_outputs(txn, &script, utxos)?;
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
        let txn = self.database().begin_transaction()?;
        let address = self.register_address(&txn, keychain)?;
        txn.commit()?;
        Ok(address)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn get_receive_address(&mut self, txn: &DbTxn) -> Result<BdkAddress, Error> {
        self.register_address(txn, KeychainKind::External)
    }

    fn internal_unspents(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        // Return empty iterator — MPC vanilla UTXOs are tracked separately
        // This is OK because all callers that need vanilla UTXOs are overridden
        std::iter::empty()
    }

    fn get_reserved_vanilla_outpoints(&self, txn: &DbTxn) -> Result<Vec<BdkOutPoint>, Error> {
        let mut reserved: Vec<BdkOutPoint> = txn
            .iter_reserved_txos()?
            .into_iter()
            .map(BdkOutPoint::from)
            .collect();
        // One complete transaction is committed with the RGB batch. Older
        // operations are adopted once, only after validating their original PSBT.
        for batch in txn
            .iter_batch_transfers()?
            .into_iter()
            .filter(|batch| !batch.incoming && !batch.status.settled() && !batch.status.failed())
        {
            let txid = batch.txid.ok_or_else(|| Error::InvalidPsbt {
                details: s!("Pending MPC operation has no txid"),
            })?;
            let tx = match txn.mpc_prepared_inputs(&txid)? {
                Some(tx) => tx,
                None => {
                    let path = self.get_transfer_dir(&txid).join(UNSIGNED_PSBT_FILE);
                    let text = fs::read_to_string(path).map_err(|_| Error::InvalidPsbt {
                        details: s!("Pending MPC operation lacks complete reservations and its original PSBT; restore the saved operation") })?;
                    let psbt = Psbt::from_str(&text)?;
                    if psbt.unsigned_tx.compute_txid().to_string() != txid
                        || psbt.unsigned_tx.input.is_empty()
                    {
                        return Err(Error::InvalidPsbt {
                            details: s!("Pending MPC PSBT transaction mismatch"),
                        });
                    }
                    txn.save_mpc_prepared_inputs(&psbt.unsigned_tx)?;
                    psbt.unsigned_tx
                }
            };
            reserved.extend(tx.input.iter().map(|input| input.previous_output));
        }
        Ok(reserved)
    }

    fn get_btc_balance_impl(
        &mut self,
        txn: &DbTxn,
        online: Option<Online>,
        skip_sync: bool,
    ) -> Result<BtcBalance, Error> {
        self.sync_if_requested(txn, online, skip_sync, KeychainKind::External)?;
        self.sync_if_requested(txn, online, skip_sync, KeychainKind::Internal)?;

        #[cfg(any(feature = "electrum", feature = "esplora"))]
        {
            let vanilla_utxos = self.query_vanilla_utxos(txn)?;
            let vanilla_total: u64 = vanilla_utxos
                .iter()
                .map(|(_, txout, _)| txout.value.to_sat())
                .sum();

            let colored_addrs = txn.get_mpc_addresses_by_keychain(0)?;
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
    fn wallet_specific_consistency_checks(&mut self, _txn: &DbTxn) -> Result<(), Error> {
        // MPC wallets don't have BDK UTXOs to cross-check
        Ok(())
    }

    fn broadcast_psbt(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<BdkTransaction, Error> {
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
            if let Some(db_txo) = txn.get_txo(&Outpoint {
                txid: txid.clone(),
                vout,
            })? {
                let mut db_txo: DbTxoActMod = db_txo.into();
                db_txo.spent = ActiveValue::Set(true);
                txn.update_txo(db_txo)?;
            }
            // Vanilla UTXOs not in txo table — skip silently
        }

        // These outputs are known to be ours; do not classify them as a new
        // witness payment just because the provider reuses the receive script.
        let scripts: HashSet<_> = txn
            .get_mpc_addresses_by_keychain(0)?
            .into_iter()
            .map(|address| address.script_pubkey)
            .collect();
        for (vout, output) in tx.output.iter().enumerate() {
            if scripts.contains(&output.script_pubkey.to_hex_string()) {
                txn.set_txo(DbTxoActMod {
                    txid: ActiveValue::Set(tx.compute_txid().to_string()),
                    vout: ActiveValue::Set(vout as u32),
                    btc_amount: ActiveValue::Set(output.value.to_sat().to_string()),
                    exists: ActiveValue::Set(true),
                    spent: ActiveValue::Set(false),
                    pending_witness: ActiveValue::Set(false),
                    ..Default::default()
                })?;
            }
        }
        self.release_reserved_txos(txn, &tx.compute_txid().to_string())?;

        Ok(tx)
    }

    fn reserve_rgb_inputs(&self, txn: &DbTxn, psbt: &Psbt) -> Result<(), Error> {
        txn.save_mpc_prepared_inputs(&psbt.unsigned_tx)
    }

    fn split_rgb_change(&self) -> bool {
        true
    }

    fn prepare_psbt(
        &mut self,
        txn: &DbTxn,
        input_outpoints: HashSet<BdkOutPoint>,
        witness_recipients: &Vec<(ScriptBuf, u64)>,
        fee_rate: FeeRate,
        // MPC PSBTs are built manually with a final (zero) locktime, so they are
        // always valid as LN funding txs; the caller-pinned locktime is not needed.
        _lock_time: Option<u32>,
        needs_rgb_change: bool,
    ) -> Result<(Psbt, Option<BtcChange>), Error> {
        // Get vanilla UTXOs for funding
        let vanilla_utxos = self.spendable_vanilla_utxos(txn)?;

        // Collect the required colored inputs (already selected by RGB logic)
        let colored_addrs = txn.get_mpc_addresses_by_keychain(0)?;
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
            required_output_value =
                required_output_value.checked_add(*amount).ok_or_else(|| {
                    Error::InvalidRecipientData {
                        details: s!("total recipient amount exceeds u64::MAX"),
                    }
                })?;
        }

        if selected_inputs.len() != input_outpoints.len() {
            return Err(Error::InvalidPsbt {
                details: s!("Required RGB input is absent from indexer"),
            });
        }
        let colored = self
            .register_address(txn, KeychainKind::External)?
            .script_pubkey();
        let vanilla = self
            .register_address(txn, KeychainKind::Internal)?
            .script_pubkey();
        let available = vanilla_utxos
            .into_iter()
            .map(|(op, txout, _)| (op, txout))
            .collect();
        mpc_psbt::split_change(
            selected_inputs,
            available,
            outputs,
            colored,
            vanilla,
            needs_rgb_change.then_some(self.rgb_carrier_sat),
            fee_rate,
        )
    }

    fn create_utxos_begin_impl(
        &mut self,
        txn: &DbTxn,
        up_to: bool,
        num: Option<u8>,
        size: Option<u32>,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        if !skip_sync {
            self.sync_bdk_and_db_txos(
                txn,
                SyncOptions {
                    keychain: SyncKeychain::Colored,
                    strategy: SyncStrategy::FastSync,
                },
                false,
            )?;
        }

        let unspent_txos = txn.get_unspent_txos(vec![])?;
        let unspents = txn.get_rgb_allocations(unspent_txos, None, None, None, None)?;

        let mut utxos_to_create = num.unwrap_or(UTXO_NUM);
        if up_to {
            let allocatable = self.get_available_allocations(unspents, &[], None)?.len();
            // compare in usize since the count of allocatable UTXOs can exceed u8::MAX
            if allocatable >= utxos_to_create as usize {
                return Err(Error::AllocationsAlreadyAvailable);
            }
            // allocatable < utxos_to_create <= u8::MAX, so the conversion cannot fail
            utxos_to_create -=
                u8::try_from(allocatable).expect("allocatable count cannot exceed u8::MAX");
        }

        let utxo_size = size.unwrap_or(UTXO_SIZE);
        if utxo_size == 0 {
            return Err(Error::InvalidAmountZero);
        }

        // Get vanilla UTXOs for funding
        let vanilla_utxos = self.spendable_vanilla_utxos(txn)?;
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
                        let fee = mpc_psbt::calculate_fee(
                            available.len(),
                            num_outputs,
                            fee_rate_checked,
                        )?;
                        return Err(Error::InsufficientBitcoins {
                            needed: target.saturating_add(fee),
                            available: total,
                        });
                    }
                }
                Err(e) => return Err(e),
            }
        }

        for _ in 0..actual_count {
            let addr = self.register_address(txn, KeychainKind::External)?;
            colored_outputs.push(TxOut {
                value: BdkAmount::from_sat(utxo_size as u64),
                script_pubkey: addr.script_pubkey(),
            });
        }

        let target: u64 = colored_outputs.iter().map(|o| o.value.to_sat()).sum();
        let num_outputs = colored_outputs.len() + 1; // +1 for change
        let (selected, total) =
            mpc_psbt::select_coins(&available, target, fee_rate_checked, num_outputs)?;

        let fee = mpc_psbt::calculate_fee(selected.len(), num_outputs, fee_rate_checked)?;
        let change = total - target - fee;

        let mut outputs = colored_outputs;
        if change > mpc_psbt::TAPROOT_DUST {
            let change_addr = self.register_address(txn, KeychainKind::Internal)?;
            outputs.push(TxOut {
                value: BdkAmount::from_sat(change),
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        let psbt = mpc_psbt::build_psbt(selected, outputs)?;
        if !dry_run {
            self.reserve_vanilla_txos(txn, &psbt, WalletTransactionType::CreateUtxos)?;
        }
        Ok(psbt)
    }

    fn create_utxos_end_impl(&mut self, txn: &DbTxn, signed_psbt: &Psbt) -> Result<u8, Error> {
        self.finalize_vanilla_wallet_transaction(
            txn,
            signed_psbt,
            WalletTransactionType::CreateUtxos,
        )?;
        let scripts: HashSet<_> = txn
            .get_mpc_addresses_by_keychain(0)?
            .into_iter()
            .map(|address| address.script_pubkey)
            .collect();
        let count = signed_psbt
            .unsigned_tx
            .output
            .iter()
            .filter(|output| scripts.contains(&output.script_pubkey.to_hex_string()))
            .count();
        let count = u8::try_from(count).map_err(|_| Error::InvalidPsbt {
            details: s!("Too many MPC colored outputs"),
        })?;
        self.broadcast_psbt(txn, signed_psbt)?;
        Ok(count)
    }

    fn send_btc_begin_impl(
        &mut self,
        txn: &DbTxn,
        address: String,
        amount: u64,
        fee_rate: u64,
        skip_sync: bool,
        dry_run: bool,
        // MPC PSBTs are built manually with a final (zero) locktime, so they are
        // always valid as LN funding txs; the caller-pinned locktime is not needed.
        _lock_time: Option<u32>,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        if !skip_sync {
            self.sync_bdk_and_db_txos(
                txn,
                SyncOptions {
                    keychain: SyncKeychain::Colored,
                    strategy: SyncStrategy::FastSync,
                },
                false,
            )?;
        }

        let script_pubkey = self.get_script_pubkey(&address)?;

        // Get vanilla UTXOs, excluding colored ones
        let unspendable = self.get_unspendable_bdk_outpoints(txn)?;
        let unspendable_set: HashSet<OutPoint> = unspendable.into_iter().collect();

        let vanilla_utxos = self.query_vanilla_utxos(txn)?;
        let available: Vec<(OutPoint, TxOut)> = vanilla_utxos
            .into_iter()
            .filter(|(op, _, _)| !unspendable_set.contains(op))
            .map(|(op, txout, _)| (op, txout))
            .collect();

        let (selected, total) = mpc_psbt::select_coins(&available, amount, fee_rate_checked, 2)?;

        let fee = mpc_psbt::calculate_fee(selected.len(), 2, fee_rate_checked)?;
        let change = total - amount - fee;

        let mut outputs = vec![TxOut {
            value: BdkAmount::from_sat(amount),
            script_pubkey,
        }];

        if change > mpc_psbt::TAPROOT_DUST {
            let change_addr = self.register_address(txn, KeychainKind::Internal)?;
            outputs.push(TxOut {
                value: BdkAmount::from_sat(change),
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        let psbt = mpc_psbt::build_psbt(selected, outputs)?;
        if !dry_run {
            self.reserve_vanilla_txos(txn, &psbt, WalletTransactionType::SendBtc)?;
        }
        Ok(psbt)
    }

    fn drain_to_begin_impl(
        &mut self,
        txn: &DbTxn,
        address: String,
        fee_rate: u64,
        dry_run: bool,
    ) -> Result<Psbt, Error> {
        let fee_rate_checked = self.check_fee_rate(fee_rate)?;

        self.sync_bdk_and_db_txos(
            txn,
            SyncOptions {
                keychain: SyncKeychain::Colored,
                strategy: SyncStrategy::FastSync,
            },
            false,
        )?;

        let script_pubkey = self.get_script_pubkey(&address)?;

        // Collect all UTXOs (vanilla only; never drain colored)
        let vanilla_utxos = self.query_vanilla_utxos(txn)?;
        let mut all_inputs: Vec<(OutPoint, TxOut)> = vanilla_utxos
            .into_iter()
            .map(|(op, txout, _)| (op, txout))
            .collect();

        // Filter out colored UTXOs
        let unspendable = self.get_unspendable_bdk_outpoints(txn)?;
        let unspendable_set: HashSet<OutPoint> = unspendable.into_iter().collect();
        all_inputs.retain(|(op, _)| !unspendable_set.contains(op));

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
        let fee = mpc_psbt::calculate_fee(all_inputs.len(), 1, fee_rate_checked)?;

        if total <= fee {
            return Err(Error::InsufficientBitcoins {
                needed: fee.saturating_add(1),
                available: total,
            });
        }

        let outputs = vec![TxOut {
            value: BdkAmount::from_sat(total - fee),
            script_pubkey,
        }];

        let psbt = mpc_psbt::build_psbt(all_inputs, outputs)?;
        if !dry_run {
            self.reserve_vanilla_txos(txn, &psbt, WalletTransactionType::Drain)?;
        }
        Ok(psbt)
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
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn record_indexed_outputs(
        &self,
        txn: &DbTxn,
        script: &ScriptBuf,
        outputs: Vec<(OutPoint, TxOut)>,
    ) -> Result<(), Error> {
        let script_hex = script.to_hex_string();
        let awaiting_receive = txn.count_in_flight_witness_transfers_for_script(&script_hex)? > 0;
        let mut own_txids: HashSet<String> = txn
            .iter_wallet_transactions()?
            .into_iter()
            .map(|tx| tx.txid)
            .collect();
        own_txids.extend(
            txn.iter_batch_transfers()?
                .into_iter()
                .filter(|batch| !batch.incoming)
                .filter_map(|batch| batch.txid),
        );
        for (outpoint, output) in outputs {
            let known = txn.get_txo(&outpoint.into())?;
            // Upsert promotes exists/amount while preserving an existing row's
            // pending_witness/spent flags. Own change must not consume a receive.
            txn.set_txo(DbTxoActMod {
                txid: ActiveValue::Set(outpoint.txid.to_string()),
                vout: ActiveValue::Set(outpoint.vout),
                btc_amount: ActiveValue::Set(output.value.to_sat().to_string()),
                spent: ActiveValue::Set(false),
                exists: ActiveValue::Set(true),
                pending_witness: ActiveValue::Set(
                    known.is_none()
                        && awaiting_receive
                        && !own_txids.contains(&outpoint.txid.to_string()),
                ),
                ..Default::default()
            })?;
        }
        // Address reuse cannot identify which invoice an arbitrary UTXO pays.
        // Retain the marker until every receive at this script is terminal.
        if !awaiting_receive {
            txn.del_pending_witness_script(script_hex)?;
        }
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn register_address(&self, txn: &DbTxn, keychain: KeychainKind) -> Result<BdkAddress, Error> {
        let keychain_u8 = match keychain {
            KeychainKind::External => 0u8,
            KeychainKind::Internal => 1u8,
        };
        if self.wallet_data().reuse_addresses
            && let Some(last) = txn.get_last_mpc_address(keychain_u8)?
        {
            return parse_address_str(&last.address, self.bitcoin_network());
        }
        self.create_registered_address(txn, keychain, keychain_u8)
    }

    fn create_registered_address(
        &self,
        txn: &DbTxn,
        keychain: KeychainKind,
        keychain_u8: u8,
    ) -> Result<BdkAddress, Error> {
        let index = txn.get_next_mpc_derivation_index(keychain_u8)?;
        let info = self
            .provider
            .create_address(self.bitcoin_network(), keychain, index)?;
        let address = parse_address_str(&info.address, self.bitcoin_network())?;
        if address.script_pubkey() != info.script_pubkey
            || info.derivation_index != index
            || info.signing_key_id.is_empty()
        {
            return Err(Error::MpcProvider {
                details: s!("provider returned inconsistent address metadata"),
            });
        }
        txn.set_mpc_address(database::entities::mpc_address::ActiveModel {
            address: ActiveValue::Set(info.address),
            script_pubkey: ActiveValue::Set(info.script_pubkey.to_hex_string()),
            signing_key_id: ActiveValue::Set(info.signing_key_id),
            keychain: ActiveValue::Set(keychain_u8),
            derivation_index: ActiveValue::Set(index),
            ..Default::default()
        })?;
        Ok(address)
    }

    /// Create a new MPC wallet.
    ///
    /// **Note:** For MPC wallets, `wallet_data.reuse_addresses` is recommended to be `true`
    /// to avoid unnecessary provider API calls for address generation.
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
            &logger,
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
                reuse_address_index: HashMap::new(),
                #[cfg(any(feature = "electrum", feature = "esplora"))]
                online_data: None,
                #[cfg(feature = "vss")]
                vss_client: None,
                #[cfg(feature = "vss")]
                auto_backup_in_progress: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
            provider,
            wallet_id,
            rgb_carrier_sat: 1_000,
        })
    }

    /// Fetch node-indexed prevouts for the fixed MPC roles on the checked network.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn list_mpc_unspents(&self, online: Online) -> Result<Vec<(OutPoint, TxOut)>, Error> {
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut outputs = Vec::new();
        for role in [0, 1] {
            for address in txn.get_mpc_addresses_by_keychain(role)? {
                let script = ScriptBuf::from_hex(&address.script_pubkey).map_err(|_| {
                    Error::InvalidPsbt {
                        details: s!("Invalid MPC script"),
                    }
                })?;
                outputs.extend(self.indexer().list_unspent_for_script(&script)?);
            }
        }
        txn.commit()?;
        Ok(outputs)
    }

    /// Set the fixed carrier amount used only when RGB allocations need change.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn set_rgb_carrier_amount(&mut self, amount: u64) -> Result<(), Error> {
        if !(mpc_psbt::TAPROOT_DUST..=100_000).contains(&amount) {
            return Err(Error::InvalidPsbt {
                details: s!("RGB carrier outside policy"),
            });
        }
        self.rgb_carrier_sat = amount;
        Ok(())
    }

    /// Query vanilla (Internal keychain) UTXOs from the indexer.
    ///
    /// Returns (outpoint, txout, signing_key_id) tuples.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn query_vanilla_utxos(&self, txn: &DbTxn) -> Result<Vec<(OutPoint, TxOut, String)>, Error> {
        let addrs = txn.get_mpc_addresses_by_keychain(1)?;
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

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn spendable_vanilla_utxos(
        &self,
        txn: &DbTxn,
    ) -> Result<Vec<(OutPoint, TxOut, String)>, Error> {
        self.filter_spendable_vanilla_utxos(txn, self.query_vanilla_utxos(txn)?)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn filter_spendable_vanilla_utxos(
        &self,
        txn: &DbTxn,
        utxos: Vec<(OutPoint, TxOut, String)>,
    ) -> Result<Vec<(OutPoint, TxOut, String)>, Error> {
        let excluded: HashSet<_> = self
            .get_unspendable_bdk_outpoints(txn)?
            .into_iter()
            .collect();
        Ok(utxos
            .into_iter()
            .filter(|(outpoint, _, _)| !excluded.contains(outpoint))
            .collect())
    }

    /// Look up signing key IDs for each input in a PSBT.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    fn get_signing_key_ids_for_psbt(&self, txn: &DbTxn, psbt: &Psbt) -> Result<Vec<String>, Error> {
        let mut key_ids = Vec::new();
        for input in &psbt.inputs {
            if let Some(witness_utxo) = &input.witness_utxo {
                let script_hex = witness_utxo.script_pubkey.to_hex_string();
                let addr = txn.get_mpc_address_by_script(&script_hex)?;
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
    fn mpc_sign_psbt(&self, txn: &DbTxn, psbt: Psbt) -> Result<Psbt, Error> {
        let key_ids = self.get_signing_key_ids_for_psbt(txn, &psbt)?;
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
        txn: &DbTxn,
        issue_data: &IssueData,
    ) -> Result<T, Error> {
        let mut runtime = self.rgb_runtime()?;
        let asset = self.import_and_save_contract(txn, issue_data, &mut runtime)?;
        T::from_issuance(txn, self, &asset, issue_data)
    }

    /// Issue a new RGB NIA asset.
    pub fn issue_asset_nia(
        &self,
        ticker: String,
        name: String,
        precision: u8,
        amounts: Vec<u64>,
    ) -> Result<AssetNIA, Error> {
        info!(self.logger(), "Issuing NIA...");
        let txn = self.database().begin_transaction()?;
        let issue_data = self.create_nia_contract(&txn, ticker, name, precision, amounts)?;
        let res = self.finalize_offline_issuance(&txn, &issue_data)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Issue asset NIA completed");
        Ok(res)
    }

    /// Create a blind receive.
    pub fn blind_receive(
        &mut self,
        asset_id: Option<String>,
        assignment: Assignment,
        expiration_timestamp: u64,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, Error> {
        info!(self.logger(), "Receiving via blinded UTXO...");

        let txn = self.database().begin_transaction()?;
        let receive_data_internal = self.create_receive_data(
            &txn,
            asset_id,
            assignment,
            i64::try_from(expiration_timestamp).map_err(|_| Error::InvalidExpiration)?,
            transport_endpoints,
            RecipientType::Blind,
        )?;

        let batch_transfer_idx =
            self.store_receive_transfer(&txn, &receive_data_internal, min_confirmations)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();

        info!(self.logger(), "Blind receive completed");
        Ok(ReceiveData {
            invoice: receive_data_internal.invoice_string,
            recipient_id: receive_data_internal.recipient_id,
            expiration_timestamp: receive_data_internal.expiration_timestamp as u64,
            batch_transfer_idx,
        })
    }

    /// Create a witness invoice using a provider-controlled Bitcoin address.
    ///
    /// No Bitcoin funds or signatures are required by the recipient. Address
    /// registration and receive state are committed in the same transaction.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub fn witness_receive(
        &mut self,
        asset_id: Option<String>,
        assignment: Assignment,
        expiration_timestamp: u64,
        transport_endpoints: Vec<String>,
        min_confirmations: u8,
    ) -> Result<ReceiveData, Error> {
        if expiration_timestamp > i64::MAX as u64 {
            return Err(Error::InvalidExpiration);
        }
        let txn = self.database().begin_transaction()?;
        let receive = self.create_receive_data(
            &txn,
            asset_id,
            assignment,
            i64::try_from(expiration_timestamp).map_err(|_| Error::InvalidExpiration)?,
            transport_endpoints,
            RecipientType::Witness,
        )?;
        let batch_transfer_idx = self.store_receive_transfer(&txn, &receive, min_confirmations)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        Ok(ReceiveData {
            invoice: receive.invoice_string,
            recipient_id: receive.recipient_id,
            expiration_timestamp: receive.expiration_timestamp as u64,
            batch_transfer_idx,
        })
    }

    /// List known RGB assets.
    pub fn list_assets(&self, filter_asset_schemas: Vec<AssetSchema>) -> Result<Assets, Error> {
        RgbWalletOpsOffline::list_assets(self, filter_asset_schemas)
    }

    /// Get asset balance.
    pub fn get_asset_balance(&self, asset_id: String) -> Result<Balance, Error> {
        RgbWalletOpsOffline::get_asset_balance(self, asset_id)
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
    pub fn go_online(&mut self, online_options: OnlineOptions) -> Result<Online, Error> {
        info!(self.logger(), "Going online...");
        let online = self.go_online_impl(&online_options)?;
        info!(self.logger(), "Go online completed");
        Ok(online)
    }

    /// Sync the wallet.
    pub fn sync(&mut self, online: Online, options: SyncOptions) -> Result<(), Error> {
        info!(self.logger(), "Syncing...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        self.sync_impl(&txn, options)?;
        txn.commit()?;
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

    /// Rotate the pinned address for the given keychain.
    ///
    /// Creates a new address via the MPC provider. Future reuse will return this new address.
    /// Only meaningful when `reuse_addresses` is `true`.
    pub fn rotate_address(&mut self, keychain: KeychainKind) -> Result<String, Error> {
        if !self.wallet_data().reuse_addresses {
            return Err(Error::AddressReuseDisabled);
        }
        let keychain_u8 = match keychain {
            KeychainKind::External => 0u8,
            KeychainKind::Internal => 1u8,
        };
        let txn = self.database().begin_transaction()?;
        let address = self.create_registered_address(&txn, keychain, keychain_u8)?;
        txn.commit()?;
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
        let txn = self.database().begin_transaction()?;
        let psbt =
            self.create_utxos_begin_impl(&txn, up_to, num, size, fee_rate, skip_sync, true)?;
        let signed = self.mpc_sign_psbt(&txn, psbt)?;
        let res = self.create_utxos_end_impl(&txn, &signed)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
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
        dry_run: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Creating UTXOs (begin)...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let res =
            self.create_utxos_begin_impl(&txn, up_to, num, size, fee_rate, skip_sync, dry_run)?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        info!(self.logger(), "Create UTXOs (begin) completed");
        Ok(res.to_string())
    }

    /// Broadcast signed PSBT to create UTXOs.
    pub fn create_utxos_end(&mut self, online: Online, signed_psbt: String) -> Result<u8, Error> {
        info!(self.logger(), "Creating UTXOs (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.create_utxos_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
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
        expiration_timestamp: u64,
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let mut begin_op_data = self.send_begin_impl(
            &txn,
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            Some(i64::try_from(expiration_timestamp).map_err(|_| Error::InvalidExpiration)?),
            true,
            None,
        )?;
        begin_op_data.psbt = self.mpc_sign_psbt(&txn, begin_op_data.psbt)?;
        let res = self.send_end_impl(&txn, &begin_op_data.psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
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
        expiration_timestamp: u64,
        dry_run: bool,
    ) -> Result<SendBeginResult, Error> {
        info!(self.logger(), "Sending (begin)...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let begin_op_data = self.send_begin_impl(
            &txn,
            recipient_map,
            donation,
            fee_rate,
            min_confirmations,
            Some(i64::try_from(expiration_timestamp).map_err(|_| Error::InvalidExpiration)?),
            dry_run,
            None,
        )?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        if !dry_run {
            self.trigger_auto_backup();
        }
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
    ) -> Result<OperationResult, Error> {
        info!(self.logger(), "Sending (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.send_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
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
        let txn = self.database().begin_transaction()?;
        let psbt =
            self.send_btc_begin_impl(&txn, address, amount, fee_rate, skip_sync, true, None)?;
        let signed = self.mpc_sign_psbt(&txn, psbt)?;
        let res = self.send_btc_end_impl(&txn, &signed)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
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
        dry_run: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC (begin)...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let res =
            self.send_btc_begin_impl(&txn, address, amount, fee_rate, skip_sync, dry_run, None)?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        info!(self.logger(), "Send BTC (begin) completed");
        Ok(res.to_string())
    }

    /// Broadcast signed PSBT for BTC send.
    pub fn send_btc_end(&mut self, online: Online, signed_psbt: String) -> Result<String, Error> {
        info!(self.logger(), "Sending BTC (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let res = self.send_btc_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        info!(self.logger(), "Send BTC (end) completed");
        Ok(res)
    }

    /// Drain wallet to address (begin + MPC sign + end).
    pub fn drain_to(
        &mut self,
        online: Online,
        address: String,
        fee_rate: u64,
    ) -> Result<String, Error> {
        info!(self.logger(), "Draining...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let psbt = self.drain_to_begin_impl(&txn, address, fee_rate, true)?;
        let signed = self.mpc_sign_psbt(&txn, psbt)?;
        let tx = self.drain_to_end_impl(&txn, &signed)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Drain completed");
        Ok(tx.compute_txid().to_string())
    }

    /// Prepare unsigned PSBT for drain.
    pub fn drain_to_begin(
        &mut self,
        online: Online,
        address: String,
        fee_rate: u64,
        dry_run: bool,
    ) -> Result<String, Error> {
        info!(self.logger(), "Draining (begin)...");
        self.check_online(online)?;
        let txn = self.database().begin_transaction()?;
        let psbt = self.drain_to_begin_impl(&txn, address, fee_rate, dry_run)?;
        if !dry_run {
            self.update_backup_info(&txn, false)?;
        }
        txn.commit()?;
        info!(self.logger(), "Drain (begin) completed");
        Ok(psbt.to_string())
    }

    /// Broadcast signed PSBT for drain.
    pub fn drain_to_end(&mut self, online: Online, signed_psbt: String) -> Result<String, Error> {
        info!(self.logger(), "Draining (end)...");
        self.check_online(online)?;
        let psbt = Psbt::from_str(&signed_psbt)?;
        let txn = self.database().begin_transaction()?;
        let tx = self.drain_to_end_impl(&txn, &psbt)?;
        self.update_backup_info(&txn, false)?;
        txn.commit()?;
        self.trigger_auto_backup();
        info!(self.logger(), "Drain (end) completed");
        Ok(tx.compute_txid().to_string())
    }

    /// Sign a PSBT string via MPC provider.
    pub fn sign_psbt(&self, unsigned_psbt: String) -> Result<String, Error> {
        info!(self.logger(), "Signing PSBT via MPC...");
        let psbt = Psbt::from_str(&unsigned_psbt)?;
        let txn = self.database().begin_transaction()?;
        let signed = self.mpc_sign_psbt(&txn, psbt)?;
        txn.commit()?;
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

#[cfg(feature = "vss")]
impl MpcWallet {
    /// Configure VSS backup for this wallet.
    ///
    /// MPC wallets keep no local key material, but the wallet directory
    /// (BDK database, rgb-lib SQLite, consignments) still holds restorable
    /// state. The caller is responsible for supplying the `SecretKey` used
    /// inside `config` for sigs-auth + HKDF; for MPC contexts this key
    /// typically lives outside the rgb-lib boundary (operator KMS, user
    /// passphrase, or a deterministic message signed by the MPC provider).
    pub fn configure_vss_backup(
        &mut self,
        config: super::vss::VssBackupConfig,
    ) -> Result<(), Error> {
        WalletBackup::configure_vss_backup(self, config)
    }

    /// Disable VSS auto-backup.
    pub fn disable_vss_auto_backup(&mut self) {
        WalletBackup::disable_vss_auto_backup(self)
    }

    /// Perform a VSS backup.
    pub async fn vss_backup(&self, client: &super::vss::VssBackupClient) -> Result<i64, Error> {
        WalletBackup::vss_backup(self, client).await
    }

    /// Get VSS backup info.
    pub async fn vss_backup_info(
        &self,
        client: &super::vss::VssBackupClient,
    ) -> Result<super::vss::VssBackupInfo, Error> {
        WalletBackup::vss_backup_info(self, client).await
    }

    /// Returns the configured VSS backup client, if any.
    ///
    /// This is the client constructed by [`configure_vss_backup`](Self::configure_vss_backup);
    /// callers can reuse it for manual backup operations instead of building a
    /// second client with the same configuration.
    pub fn vss_client(&self) -> Option<Arc<super::vss::VssBackupClient>> {
        WalletCore::vss_client(self).clone()
    }
}

#[cfg(all(test, any(feature = "electrum", feature = "esplora")))]
#[path = "mpc_tests.rs"]
mod tests;
