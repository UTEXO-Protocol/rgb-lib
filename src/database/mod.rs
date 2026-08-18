pub(crate) mod entities;

use super::*;

#[cfg(feature = "mpc")]
use crate::database::entities::mpc_address;
use crate::database::entities::{
    asset, coloring, media, prelude::*, reuse_address_index, transfer_transport_endpoint,
    transport_endpoint, txo, wallet_transaction,
};
use bdk_wallet::KeychainKind;

fn keychain_to_u8(keychain: KeychainKind) -> u8 {
    match keychain {
        KeychainKind::External => 0,
        KeychainKind::Internal => 1,
    }
}

fn keychain_from_u8(value: u8) -> Option<KeychainKind> {
    match value {
        0 => Some(KeychainKind::External),
        1 => Some(KeychainKind::Internal),
        _ => None,
    }
}
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::database::entities::{pending_witness_script, reserved_txo};

#[derive(Debug, Clone)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) struct DbAssetTransferData {
    pub(crate) asset_transfer: DbAssetTransfer,
    pub(crate) transfers: Vec<DbTransfer>,
}

impl DbBatchTransfer {
    pub(crate) fn get_asset_transfers(
        &self,
        asset_transfers: &[DbAssetTransfer],
    ) -> Vec<DbAssetTransfer> {
        asset_transfers
            .iter()
            .filter(|&t| t.batch_transfer_idx == self.idx)
            .cloned()
            .collect()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn get_transfers(
        &self,
        asset_transfers: &[DbAssetTransfer],
        transfers: &[DbTransfer],
    ) -> Result<DbBatchTransferData, Error> {
        let asset_transfers = self.get_asset_transfers(asset_transfers);
        let mut asset_transfers_data = vec![];
        for asset_transfer in asset_transfers {
            let transfers: Vec<DbTransfer> = transfers
                .iter()
                .filter(|&t| asset_transfer.idx == t.asset_transfer_idx)
                .cloned()
                .collect();
            asset_transfers_data.push(DbAssetTransferData {
                asset_transfer,
                transfers,
            })
        }
        Ok(DbBatchTransferData {
            asset_transfers_data,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn get_incoming_transfer(
        &self,
        asset_transfers: &[DbAssetTransfer],
        transfers: &[DbTransfer],
    ) -> Result<(DbAssetTransfer, DbTransfer), Error> {
        let batch_transfer_data = self.get_transfers(asset_transfers, transfers)?;
        let asset_transfer_data = batch_transfer_data
            .asset_transfers_data
            .first() // incoming batch transfer has only one asset transfer
            .expect("asset transfer should be connected to a batch transfer");
        let transfer = asset_transfer_data
            .transfers
            .first() // incoming asset transfer has only one transfer
            .expect("transfer should be connected to an asset transfer");
        Ok((asset_transfer_data.asset_transfer.clone(), transfer.clone()))
    }

    pub(crate) fn failed(&self) -> bool {
        self.status.failed()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn waiting(&self) -> bool {
        self.status.waiting()
    }

    pub(crate) fn waiting_confirmations(&self) -> bool {
        self.status.waiting_confirmations()
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn is_fallible(&self) -> bool {
        self.status.is_fallible()
    }
}

#[derive(Debug, Clone)]
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) struct DbBatchTransferData {
    pub(crate) asset_transfers_data: Vec<DbAssetTransferData>,
}

impl DbColoring {
    pub(crate) fn incoming(&self) -> bool {
        [
            ColoringType::Receive,
            ColoringType::Change,
            ColoringType::Issue,
        ]
        .contains(&self.r#type)
    }
}

pub struct DbData {
    pub(crate) batch_transfers: Vec<DbBatchTransfer>,
    pub(crate) asset_transfers: Vec<DbAssetTransfer>,
    pub(crate) transfers: Vec<DbTransfer>,
    pub(crate) colorings: Vec<DbColoring>,
    pub(crate) txos: Vec<DbTxo>,
}

impl DbTransfer {
    pub(crate) fn related_transfers(
        &self,
        asset_transfers: &[DbAssetTransfer],
        batch_transfers: &[DbBatchTransfer],
    ) -> (DbAssetTransfer, DbBatchTransfer) {
        let asset_transfer = asset_transfers
            .iter()
            .find(|t| t.idx == self.asset_transfer_idx)
            .expect("transfer should be connected to an asset transfer");
        let batch_transfer = batch_transfers
            .iter()
            .find(|t| t.idx == asset_transfer.batch_transfer_idx)
            .expect("asset transfer should be connected to a batch transfer");

        (asset_transfer.clone(), batch_transfer.clone())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn uses_out_of_band_exchange(&self) -> bool {
        self.invoice_string
            .as_deref()
            .and_then(|s| RgbInvoice::from_str(s).ok())
            .map(|invoice| invoice.transports == vec![])
            .unwrap_or(false)
    }
}

impl DbTxo {
    pub(crate) fn outpoint(&self) -> Outpoint {
        Outpoint {
            txid: self.txid.to_string(),
            vout: self.vout,
        }
    }

    fn get_utxo_allocations(
        &self,
        colorings: &[DbColoring],
        asset_transfers: &[DbAssetTransfer],
        batch_transfers: &[DbBatchTransfer],
    ) -> Result<Vec<LocalRgbAllocation>, Error> {
        let utxo_colorings: Vec<&DbColoring> =
            colorings.iter().filter(|c| c.txo_idx == self.idx).collect();

        let mut allocations: Vec<LocalRgbAllocation> = vec![];
        utxo_colorings.iter().for_each(|c| {
            let asset_transfer: &DbAssetTransfer = asset_transfers
                .iter()
                .find(|t| t.idx == c.asset_transfer_idx)
                .expect("coloring should be connected to an asset transfer");
            let batch_transfer: &DbBatchTransfer = batch_transfers
                .iter()
                .find(|t| asset_transfer.batch_transfer_idx == t.idx)
                .expect("asset transfer should be connected to a batch transfer");

            allocations.push(LocalRgbAllocation {
                asset_id: asset_transfer.asset_id.clone(),
                assignment: c.assignment.clone(),
                status: batch_transfer.status,
                incoming: c.incoming(),
                txo_spent: self.spent,
            });
        });

        Ok(allocations)
    }
}

impl From<DbReservedTxo> for BdkOutPoint {
    fn from(r: DbReservedTxo) -> BdkOutPoint {
        BdkOutPoint::from_str(&format!("{}:{}", r.txid, r.vout))
            .expect("DB should contain a valid outpoint")
    }
}

impl From<DbTxo> for BdkOutPoint {
    fn from(x: DbTxo) -> BdkOutPoint {
        BdkOutPoint::from_str(&x.outpoint().to_string())
            .expect("DB should contain a valid outpoint")
    }
}

impl From<LocalOutput> for DbTxoActMod {
    fn from(x: LocalOutput) -> DbTxoActMod {
        DbTxoActMod {
            idx: ActiveValue::NotSet,
            txid: ActiveValue::Set(x.outpoint.txid.to_string()),
            vout: ActiveValue::Set(x.outpoint.vout),
            btc_amount: ActiveValue::Set(x.txout.value.to_sat().to_string()),
            spent: ActiveValue::Set(x.is_spent),
            exists: ActiveValue::Set(true),
            pending_witness: ActiveValue::Set(false),
        }
    }
}

pub struct RgbLibDatabase {
    connection: DatabaseConnection,
}

impl RgbLibDatabase {
    pub(crate) fn new(connection: DatabaseConnection) -> Self {
        Self { connection }
    }

    pub(crate) fn begin_transaction(&self) -> Result<DbTxn, Error> {
        Ok(DbTxn {
            txn: Some(block_on(self.connection.begin())?),
        })
    }
}

pub struct DbTxn {
    txn: Option<DatabaseTransaction>,
}

impl Drop for DbTxn {
    fn drop(&mut self) {
        if let Some(txn) = self.txn.take() {
            // run the rollback inside our runtime so the async
            // release has a tokio context (panics otherwise)
            let _ = block_on(txn.rollback());
        }
    }
}

impl DbTxn {
    fn inner(&self) -> &DatabaseTransaction {
        self.txn.as_ref().expect("txn already consumed")
    }

    pub(crate) fn commit(mut self) -> Result<(), Error> {
        let txn = self.txn.take().expect("txn already consumed");
        Ok(block_on(txn.commit())?)
    }

    pub(crate) fn set_asset(&self, asset: DbAssetActMod) -> Result<i32, Error> {
        let res = block_on(Asset::insert(asset).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_asset_transfer(
        &self,
        asset_transfer: DbAssetTransferActMod,
    ) -> Result<i32, Error> {
        let res = block_on(AssetTransfer::insert(asset_transfer).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_backup_info(&self, backup_info: DbBackupInfoActMod) -> Result<i32, Error> {
        let res = block_on(BackupInfo::insert(backup_info).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_batch_transfer(
        &self,
        mut batch_transfer: DbBatchTransferActMod,
    ) -> Result<i32, Error> {
        batch_transfer.updated_at = batch_transfer.created_at.clone();
        let res = block_on(BatchTransfer::insert(batch_transfer).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_coloring(&self, coloring: DbColoringActMod) -> Result<i32, Error> {
        let res = block_on(Coloring::insert(coloring).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_media(&self, media: DbMediaActMod) -> Result<i32, Error> {
        let res = block_on(Media::insert(media).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_pending_witness_script(
        &self,
        pending_witness_script: DbPendingWitnessScriptActMod,
    ) -> Result<i32, Error> {
        let script = pending_witness_script
            .script
            .clone()
            .take()
            .expect("script must be set on the active model");
        let on_conflict = sea_query::OnConflict::column(
            crate::database::entities::pending_witness_script::Column::Script,
        )
        .do_nothing()
        .to_owned();
        let conn = self.inner();
        let res = block_on(
            PendingWitnessScript::insert(pending_witness_script)
                .on_conflict(on_conflict)
                .exec(conn),
        );
        match res {
            Ok(insert_result) => Ok(insert_result.last_insert_id),
            Err(DbErr::RecordNotInserted) => {
                let existing = block_on(
                    PendingWitnessScript::find()
                        .filter(
                            crate::database::entities::pending_witness_script::Column::Script
                                .eq(script),
                        )
                        .one(conn),
                )?;
                match existing {
                    Some(row) => Ok(row.idx),
                    None => unreachable!("RecordNotInserted means the row exists"),
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn set_reserved_txos(
        &self,
        reserved_txos: Vec<DbReservedTxoActMod>,
    ) -> Result<(), Error> {
        block_on(ReservedTxo::insert_many(reserved_txos).exec(self.inner()))?;
        Ok(())
    }

    pub(crate) fn set_token(&self, token: DbTokenActMod) -> Result<i32, Error> {
        let res = block_on(Token::insert(token).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_token_media(&self, token_media: DbTokenMediaActMod) -> Result<i32, Error> {
        let res = block_on(TokenMedia::insert(token_media).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_transport_endpoint(
        &self,
        transport_endpoint: DbTransportEndpointActMod,
    ) -> Result<i32, Error> {
        let res = block_on(TransportEndpoint::insert(transport_endpoint).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_transfer(&self, transfer: DbTransferActMod) -> Result<i32, Error> {
        let res = block_on(Transfer::insert(transfer).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    pub(crate) fn set_transfer_transport_endpoint(
        &self,
        transfer_transport_endpoint: DbTransferTransportEndpointActMod,
    ) -> Result<i32, Error> {
        let res = block_on(
            TransferTransportEndpoint::insert(transfer_transport_endpoint).exec(self.inner()),
        )?;
        Ok(res.last_insert_id)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn set_txo(&self, txo: DbTxoActMod) -> Result<i32, Error> {
        let mut on_conflict =
            sea_query::OnConflict::columns([txo::Column::Txid, txo::Column::Vout]);
        let mut update = false;
        if txo.exists.clone().unwrap() {
            update = true;
            // update exists only if updated value is true
            on_conflict.update_column(txo::Column::Exists);
        }
        if txo.btc_amount.clone().unwrap() != "0" {
            update = true;
            // update btc_amount only if updated value is positive
            on_conflict.update_column(txo::Column::BtcAmount);
        }
        if !update {
            on_conflict.do_nothing();
        }
        // this returns RecordNotInserted if the TXO already exists and on_conflict is do_nothing
        let conn = self.inner();
        let res = block_on(
            Txo::insert(txo.clone())
                .on_conflict(on_conflict.to_owned())
                .exec(conn),
        );
        let idx = match res {
            Ok(insert_result) => insert_result.last_insert_id,
            Err(DbErr::RecordNotInserted) => {
                // insert skipped due to ON CONFLICT DO NOTHING -> fetch existing record's idx
                let existing = self.get_txo(&Outpoint {
                    txid: txo.txid.unwrap(),
                    vout: txo.vout.unwrap(),
                })?;
                match existing {
                    Some(record) => record.idx,
                    None => unreachable!("RecordNotInserted means it already exists"),
                }
            }
            Err(err) => {
                return Err(err.into());
            }
        };
        Ok(idx)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn set_wallet_transaction(
        &self,
        wallet_transaction: DbWalletTransactionActMod,
    ) -> Result<i32, Error> {
        let res = block_on(WalletTransaction::insert(wallet_transaction).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn update_transfer(
        &self,
        transfer: &mut DbTransferActMod,
    ) -> Result<DbTransfer, Error> {
        Ok(block_on(
            Transfer::update(transfer.clone()).exec(self.inner()),
        )?)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn update_asset(&self, asset: &mut DbAssetActMod) -> Result<DbAsset, Error> {
        Ok(block_on(Asset::update(asset.clone()).exec(self.inner()))?)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn update_asset_transfer(
        &self,
        asset_transfer: &mut DbAssetTransferActMod,
    ) -> Result<DbAssetTransfer, Error> {
        Ok(block_on(
            AssetTransfer::update(asset_transfer.clone()).exec(self.inner()),
        )?)
    }

    pub(crate) fn update_backup_info(
        &self,
        backup_info: &mut DbBackupInfoActMod,
    ) -> Result<DbBackupInfo, Error> {
        Ok(block_on(
            BackupInfo::update(backup_info.clone()).exec(self.inner()),
        )?)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn update_batch_transfer(
        &self,
        batch_transfer: &mut DbBatchTransferActMod,
    ) -> Result<DbBatchTransfer, Error> {
        let now = now().unix_timestamp();
        batch_transfer.updated_at = ActiveValue::Set(now);
        Ok(block_on(
            BatchTransfer::update(batch_transfer.clone()).exec(self.inner()),
        )?)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn update_transfer_transport_endpoint(
        &self,
        transfer_transport_endpoint: &mut DbTransferTransportEndpointActMod,
    ) -> Result<DbTransferTransportEndpoint, Error> {
        Ok(block_on(
            TransferTransportEndpoint::update(transfer_transport_endpoint.clone())
                .exec(self.inner()),
        )?)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn update_txo(&self, txo: DbTxoActMod) -> Result<(), Error> {
        block_on(Txo::update(txo).exec(self.inner()))?;
        Ok(())
    }

    pub(crate) fn del_backup_info(&self) -> Result<(), Error> {
        block_on(BackupInfo::delete_many().exec(self.inner()))?;
        Ok(())
    }

    pub(crate) fn del_batch_transfer(&self, batch_transfer: &DbBatchTransfer) -> Result<(), Error> {
        block_on(BatchTransfer::delete_by_id(batch_transfer.idx).exec(self.inner()))?;
        Ok(())
    }

    pub(crate) fn del_coloring(&self, asset_transfer_idx: i32) -> Result<(), Error> {
        block_on(
            Coloring::delete_many()
                .filter(coloring::Column::AssetTransferIdx.eq(asset_transfer_idx))
                .exec(self.inner()),
        )?;
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn del_pending_witness_script(&self, script: String) -> Result<(), Error> {
        block_on(
            PendingWitnessScript::delete_many()
                .filter(pending_witness_script::Column::Script.eq(script))
                .exec(self.inner()),
        )?;
        Ok(())
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn del_reserved_txos(&self, reserved_txos: &[DbReservedTxo]) -> Result<(), Error> {
        let idxs = reserved_txos.iter().map(|r| r.idx).collect::<Vec<_>>();
        block_on(
            ReservedTxo::delete_many()
                .filter(reserved_txo::Column::Idx.is_in(idxs))
                .exec(self.inner()),
        )?;
        Ok(())
    }

    pub(crate) fn del_txo(&self, idx: i32) -> Result<(), Error> {
        block_on(Txo::delete_by_id(idx).exec(self.inner()))?;
        Ok(())
    }

    pub(crate) fn del_wallet_transaction(&self, idx: i32) -> Result<(), Error> {
        block_on(WalletTransaction::delete_by_id(idx).exec(self.inner()))?;
        Ok(())
    }

    pub(crate) fn get_asset(&self, asset_id: String) -> Result<Option<DbAsset>, Error> {
        Ok(block_on(
            Asset::find()
                .filter(asset::Column::Id.eq(asset_id))
                .one(self.inner()),
        )?)
    }

    pub(crate) fn get_backup_info(&self) -> Result<Option<DbBackupInfo>, Error> {
        Ok(block_on(BackupInfo::find().one(self.inner()))?)
    }

    pub(crate) fn set_reuse_address_index(
        &self,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<(), Error> {
        let model = reuse_address_index::ActiveModel {
            keychain: ActiveValue::Set(keychain_to_u8(keychain)),
            derivation_index: ActiveValue::Set(index),
        };
        let on_conflict = sea_query::OnConflict::column(reuse_address_index::Column::Keychain)
            .update_column(reuse_address_index::Column::DerivationIndex)
            .to_owned();
        block_on(
            ReuseAddressIndex::insert(model)
                .on_conflict(on_conflict)
                .exec(self.inner()),
        )?;
        Ok(())
    }

    pub(crate) fn get_reuse_address_index(&self) -> Result<HashMap<KeychainKind, u32>, Error> {
        let rows = block_on(ReuseAddressIndex::find().all(self.inner()))?;
        Ok(rows
            .into_iter()
            .filter_map(|row| keychain_from_u8(row.keychain).map(|k| (k, row.derivation_index)))
            .collect())
    }

    pub(crate) fn get_batch_transfer_by_txid(
        &self,
        txid: &str,
    ) -> Result<Option<DbBatchTransfer>, Error> {
        Ok(block_on(
            BatchTransfer::find()
                .filter(crate::database::entities::batch_transfer::Column::Txid.eq(txid))
                .one(self.inner()),
        )?)
    }

    pub(crate) fn get_media(&self, media_idx: i32) -> Result<Option<DbMedia>, Error> {
        Ok(block_on(Media::find_by_id(media_idx).one(self.inner()))?)
    }

    pub(crate) fn get_media_by_digest(&self, digest: String) -> Result<Option<DbMedia>, Error> {
        Ok(block_on(
            Media::find()
                .filter(media::Column::Digest.eq(digest))
                .one(self.inner()),
        )?)
    }

    pub(crate) fn get_transport_endpoint(
        &self,
        endpoint: String,
    ) -> Result<Option<DbTransportEndpoint>, Error> {
        Ok(block_on(
            TransportEndpoint::find()
                .filter(transport_endpoint::Column::Endpoint.eq(endpoint))
                .one(self.inner()),
        )?)
    }

    pub(crate) fn get_txo(&self, outpoint: &Outpoint) -> Result<Option<DbTxo>, Error> {
        Ok(block_on(
            Txo::find()
                .filter(txo::Column::Txid.eq(outpoint.txid.clone()))
                .filter(txo::Column::Vout.eq(outpoint.vout))
                .one(self.inner()),
        )?)
    }

    pub(crate) fn get_wallet_transactions_by_idxs(
        &self,
        idxs: &[i32],
    ) -> Result<Vec<DbWalletTransaction>, Error> {
        Ok(block_on(
            WalletTransaction::find()
                .filter(wallet_transaction::Column::Idx.is_in(idxs.to_vec()))
                .all(self.inner()),
        )?)
    }

    pub(crate) fn get_wallet_transaction_with_reserved_txos_by_txid(
        &self,
        txid: &str,
    ) -> Result<Option<(DbWalletTransaction, Vec<DbReservedTxo>)>, Error> {
        Ok(block_on(
            WalletTransaction::find()
                .filter(wallet_transaction::Column::Txid.eq(txid))
                .find_with_related(ReservedTxo)
                .all(self.inner()),
        )?
        .into_iter()
        .next())
    }

    pub(crate) fn iter_assets(&self) -> Result<Vec<DbAsset>, Error> {
        Ok(block_on(Asset::find().all(self.inner()))?)
    }

    pub(crate) fn iter_asset_transfers(&self) -> Result<Vec<DbAssetTransfer>, Error> {
        Ok(block_on(AssetTransfer::find().all(self.inner()))?)
    }

    pub(crate) fn iter_batch_transfers(&self) -> Result<Vec<DbBatchTransfer>, Error> {
        Ok(block_on(BatchTransfer::find().all(self.inner()))?)
    }

    pub(crate) fn iter_colorings(&self) -> Result<Vec<DbColoring>, Error> {
        Ok(block_on(Coloring::find().all(self.inner()))?)
    }

    pub(crate) fn iter_media(&self) -> Result<Vec<DbMedia>, Error> {
        Ok(block_on(Media::find().all(self.inner()))?)
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn iter_pending_witness_scripts(
        &self,
    ) -> Result<Vec<DbPendingWitnessScript>, Error> {
        Ok(block_on(PendingWitnessScript::find().all(self.inner()))?)
    }

    /// Count in-flight (non-Settled, non-Failed) witness `batch_transfer`s
    /// whose associated `transfer.recipient_id` derives back to `script_hex`.
    ///
    /// Used by sync paths to decide whether deleting a `pending_witness_script`
    /// row is safe: the row must stay alive while ≥ 2 in-flight invoices target
    /// the same pinned script, so later-arriving UTXOs at that script keep
    /// getting `pending_witness=true` and are excluded from coin selection.
    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn count_in_flight_witness_transfers_for_script(
        &self,
        script_hex: &str,
    ) -> Result<u32, Error> {
        let batch_transfers = self.iter_batch_transfers()?;
        let asset_transfers = self.iter_asset_transfers()?;
        let transfers = self.iter_transfers()?;

        let in_flight_batch_idx: std::collections::HashSet<i32> = batch_transfers
            .iter()
            .filter(|bt| !bt.status.settled() && !bt.status.failed())
            .map(|bt| bt.idx)
            .collect();
        let in_flight_asset_transfer_idx: std::collections::HashSet<i32> = asset_transfers
            .iter()
            .filter(|at| in_flight_batch_idx.contains(&at.batch_transfer_idx))
            .map(|at| at.idx)
            .collect();

        let mut count: u32 = 0;
        for t in &transfers {
            if !in_flight_asset_transfer_idx.contains(&t.asset_transfer_idx) {
                continue;
            }
            if !matches!(t.recipient_type, Some(RecipientTypeFull::Witness { .. })) {
                continue;
            }
            let Some(ref recipient_id) = t.recipient_id else {
                continue;
            };
            match crate::utils::script_buf_from_recipient_id(recipient_id.clone()) {
                Ok(Some(script)) => {
                    if script.to_hex_string() == script_hex {
                        count = count.saturating_add(1);
                    }
                }
                _ => continue,
            }
        }
        Ok(count)
    }

    pub(crate) fn iter_reserved_txos(&self) -> Result<Vec<DbReservedTxo>, Error> {
        Ok(block_on(ReservedTxo::find().all(self.inner()))?)
    }

    pub(crate) fn iter_token_medias(&self) -> Result<Vec<DbTokenMedia>, Error> {
        Ok(block_on(TokenMedia::find().all(self.inner()))?)
    }

    pub(crate) fn iter_tokens(&self) -> Result<Vec<DbToken>, Error> {
        Ok(block_on(Token::find().all(self.inner()))?)
    }

    pub(crate) fn iter_transfers(&self) -> Result<Vec<DbTransfer>, Error> {
        Ok(block_on(Transfer::find().all(self.inner()))?)
    }

    pub(crate) fn iter_txos(&self) -> Result<Vec<DbTxo>, Error> {
        Ok(block_on(Txo::find().all(self.inner()))?)
    }

    pub(crate) fn iter_wallet_transactions(&self) -> Result<Vec<DbWalletTransaction>, Error> {
        Ok(block_on(WalletTransaction::find().all(self.inner()))?)
    }

    pub(crate) fn get_transfer_transport_endpoints_data(
        &self,
        transfer_idx: i32,
    ) -> Result<Vec<(DbTransferTransportEndpoint, DbTransportEndpoint)>, Error> {
        Ok(block_on(
            TransferTransportEndpoint::find()
                .filter(transfer_transport_endpoint::Column::TransferIdx.eq(transfer_idx))
                .find_also_related(TransportEndpoint)
                .order_by_asc(transfer_transport_endpoint::Column::Idx)
                .all(self.inner()),
        )?
        .into_iter()
        .map(|(tte, ce)| (tte, ce.expect("should be connected")))
        .collect())
    }

    pub(crate) fn get_db_data(&self, empty_transfers: bool) -> Result<DbData, Error> {
        let batch_transfers = self.iter_batch_transfers()?;
        let asset_transfers = self.iter_asset_transfers()?;
        let colorings = self.iter_colorings()?;
        let transfers = if empty_transfers {
            vec![]
        } else {
            self.iter_transfers()?
        };
        let txos = self.iter_txos()?;
        Ok(DbData {
            batch_transfers,
            asset_transfers,
            transfers,
            colorings,
            txos,
        })
    }

    pub(crate) fn get_unspent_txos(&self, txos: Vec<DbTxo>) -> Result<Vec<DbTxo>, Error> {
        let txos = if txos.is_empty() {
            self.iter_txos()?
        } else {
            txos
        };
        Ok(txos.into_iter().filter(|t| !t.spent).collect())
    }

    pub(crate) fn get_issuance_link_right_outpoint(
        &self,
        asset_id: &str,
        asset_transfers: Option<Vec<DbAssetTransfer>>,
        colorings: Option<Vec<DbColoring>>,
        txos: Option<Vec<DbTxo>>,
    ) -> Result<Option<Outpoint>, Error> {
        let asset_transfers = asset_transfers
            .map(Ok)
            .unwrap_or_else(|| self.iter_asset_transfers())?;
        let colorings = colorings.map(Ok).unwrap_or_else(|| self.iter_colorings())?;
        let txos = txos.map(Ok).unwrap_or_else(|| self.iter_txos())?;
        let issuance_link_right_coloring = colorings.iter().find(|coloring| {
            coloring.r#type == ColoringType::Issue
                && coloring.assignment == Assignment::LinkRight
                && asset_transfers.iter().any(|asset_transfer| {
                    asset_transfer.idx == coloring.asset_transfer_idx
                        && asset_transfer.asset_id.as_deref() == Some(asset_id)
                })
        });
        Ok(issuance_link_right_coloring
            .and_then(|coloring| txos.iter().find(|txo| txo.idx == coloring.txo_idx))
            .map(|txo| txo.outpoint()))
    }

    pub(crate) fn get_unspent_link_right_outpoint(
        &self,
        asset_id: &str,
    ) -> Result<Option<Outpoint>, Error> {
        let unspent_txos = self.get_unspent_txos(vec![])?;
        let unspents = self.get_rgb_allocations(unspent_txos, None, None, None, None)?;
        Ok(unspents
            .iter()
            .find(|unspent| {
                unspent.rgb_allocations.iter().any(|allocation| {
                    allocation.asset_id.as_deref() == Some(asset_id)
                        && allocation.assignment == Assignment::LinkRight
                        && allocation.settled()
                })
            })
            .map(|unspent| unspent.utxo.outpoint()))
    }

    pub(crate) fn get_asset_balance(
        &self,
        asset_id: String,
        transfers: Option<Vec<DbTransfer>>,
        asset_transfers: Option<Vec<DbAssetTransfer>>,
        batch_transfers: Option<Vec<DbBatchTransfer>>,
        colorings: Option<Vec<DbColoring>>,
        txos: Option<Vec<DbTxo>>,
    ) -> Result<Balance, Error> {
        let batch_transfers = batch_transfers
            .map(Ok)
            .unwrap_or_else(|| self.iter_batch_transfers())?;
        let asset_transfers = asset_transfers
            .map(Ok)
            .unwrap_or_else(|| self.iter_asset_transfers())?;
        let transfers = transfers.map(Ok).unwrap_or_else(|| self.iter_transfers())?;
        let colorings = colorings.map(Ok).unwrap_or_else(|| self.iter_colorings())?;
        let txos = txos.map(Ok).unwrap_or_else(|| self.iter_txos())?;

        let txos_allocations = self.get_rgb_allocations(
            txos,
            Some(colorings),
            Some(batch_transfers.clone()),
            Some(asset_transfers.clone()),
            Some(transfers.clone()),
        )?;

        let mut allocations: Vec<LocalRgbAllocation> = vec![];
        txos_allocations
            .iter()
            .for_each(|u| allocations.extend(u.rgb_allocations.clone()));
        let ass_allocations: Vec<LocalRgbAllocation> = allocations
            .into_iter()
            .filter(|a| a.asset_id == Some(asset_id.clone()))
            .collect();

        let settled: u64 = ass_allocations
            .iter()
            .filter(|a| a.settled())
            .map(|a| a.assignment.main_amount())
            .sum();

        let allocations_pending_incoming: u64 = ass_allocations
            .iter()
            .filter(|a| !a.txo_spent && a.incoming && a.status.pending())
            .map(|a| a.assignment.main_amount())
            .sum();
        let witness_pending: u64 = transfers
            .iter()
            .filter(|t| matches!(t.recipient_type, Some(RecipientTypeFull::Witness { .. })))
            .filter_map(|t| {
                let (at, bt) = t.related_transfers(&asset_transfers, &batch_transfers);
                if bt.incoming && bt.status.waiting_confirmations() {
                    // filter for asset ID (always present in WaitingConfirmations status)
                    if at.asset_id.unwrap() != asset_id {
                        return None;
                    }
                    Some(
                        t.requested_assignment
                            .as_ref()
                            .map(|a| a.main_amount())
                            .unwrap_or(0),
                    )
                } else {
                    None
                }
            })
            .sum();
        let ass_pending_incoming = allocations_pending_incoming
            .checked_add(witness_pending)
            .expect("total pending incoming amount cannot exceed u64::MAX");
        let ass_pending_outgoing: u64 = ass_allocations
            .iter()
            .filter(|a| !a.incoming && a.status.pending())
            .map(|a| a.assignment.main_amount())
            .sum();
        let ass_pending: i128 = ass_pending_incoming as i128 - ass_pending_outgoing as i128;

        let future = settled as i128 + ass_pending;

        let unspendable: u64 = txos_allocations
            .into_iter()
            .filter(|u| {
                // unspent
                (!u.utxo.spent
                    // and with transfers either outgoing and not failed or incoming and pending
                    && (u.rgb_allocations.iter().any(|a| {
                        (!a.incoming && !a.status.failed()) || (a.incoming && a.status.pending())
                    })
                    // or with pending blinded incoming transfers
                    || u.pending_blinded > 0
                    ))
                    // spent
                    || (u.utxo.spent
                    // and with transfers outgoing and in WaitingConfirmations
                        && u.rgb_allocations
                            .iter()
                            .any(|a| !a.incoming && a.status.waiting_confirmations()))
            })
            .collect::<Vec<LocalUnspent>>()
            .iter()
            .map(|u| {
                u.rgb_allocations
                    .iter()
                    .filter(|a| a.asset_id == Some(asset_id.clone()) && a.settled())
                    .map(|a| a.assignment.main_amount())
                    .sum::<u64>()
            })
            .sum();

        let spendable = settled
            .checked_sub(unspendable)
            .expect("unspendable allocations are a subset of settled ones");

        Ok(Balance {
            settled,
            future: u64::try_from(future)
                .expect("pending outgoing cannot exceed available balance"),
            spendable,
        })
    }

    #[cfg(any(feature = "electrum", feature = "esplora"))]
    pub(crate) fn get_asset_ids(&self) -> Result<Vec<String>, Error> {
        Ok(self.iter_assets()?.into_iter().map(|a| a.id).collect())
    }

    pub(crate) fn check_asset_exists(&self, asset_id: String) -> Result<DbAsset, Error> {
        match self.get_asset(asset_id.clone())? {
            Some(a) => Ok(a),
            None => Err(Error::AssetNotFound { asset_id }),
        }
    }

    pub(crate) fn get_batch_transfer_or_fail(
        &self,
        idx: i32,
        batch_transfers: &[DbBatchTransfer],
    ) -> Result<DbBatchTransfer, Error> {
        if let Some(batch_transfer) = batch_transfers.iter().find(|t| t.idx == idx) {
            Ok(batch_transfer.clone())
        } else {
            Err(Error::BatchTransferNotFound { idx })
        }
    }

    pub(crate) fn get_or_insert_media(&self, digest: String, mime: String) -> Result<i32, Error> {
        Ok(match self.get_media_by_digest(digest.clone())? {
            Some(media) => media.idx,
            None => self.set_media(DbMediaActMod {
                digest: ActiveValue::Set(digest),
                mime: ActiveValue::Set(mime),
                ..Default::default()
            })?,
        })
    }

    pub(crate) fn get_rgb_allocations(
        &self,
        utxos: Vec<DbTxo>,
        colorings: Option<Vec<DbColoring>>,
        batch_transfers: Option<Vec<DbBatchTransfer>>,
        asset_transfers: Option<Vec<DbAssetTransfer>>,
        transfers: Option<Vec<DbTransfer>>,
    ) -> Result<Vec<LocalUnspent>, Error> {
        let batch_transfers = batch_transfers
            .map(Ok)
            .unwrap_or_else(|| self.iter_batch_transfers())?;
        let asset_transfers = asset_transfers
            .map(Ok)
            .unwrap_or_else(|| self.iter_asset_transfers())?;
        let colorings = colorings.map(Ok).unwrap_or_else(|| self.iter_colorings())?;
        let transfers = transfers.map(Ok).unwrap_or_else(|| self.iter_transfers())?;

        let pending_blinded_utxos = transfers
            .iter()
            .filter_map(|t| match &t.recipient_type {
                Some(RecipientTypeFull::Blind { unblinded_utxo }) => {
                    let (_, bt) = t.related_transfers(&asset_transfers, &batch_transfers);
                    (bt.incoming && bt.status.waiting_counterparty()).then_some(unblinded_utxo)
                }
                _ => None,
            })
            .fold(HashMap::new(), |mut acc, utxo| {
                *acc.entry(utxo).or_insert(0) += 1;
                acc
            });

        utxos
            .iter()
            .map(|t| {
                Ok(LocalUnspent {
                    utxo: t.clone(),
                    rgb_allocations: t.get_utxo_allocations(
                        &colorings,
                        &asset_transfers,
                        &batch_transfers,
                    )?,
                    pending_blinded: *pending_blinded_utxos.get(&t.outpoint()).unwrap_or(&0),
                })
            })
            .collect()
    }

    #[cfg(feature = "mpc")]
    pub(crate) fn set_mpc_address(&self, addr: mpc_address::ActiveModel) -> Result<i32, Error> {
        let res = block_on(MpcAddress::insert(addr).exec(self.inner()))?;
        Ok(res.last_insert_id)
    }

    #[cfg(feature = "mpc")]
    pub(crate) fn get_mpc_addresses_by_keychain(
        &self,
        keychain: u8,
    ) -> Result<Vec<mpc_address::Model>, Error> {
        Ok(block_on(
            mpc_address::Entity::find()
                .filter(mpc_address::Column::Keychain.eq(keychain))
                .all(self.inner()),
        )?)
    }

    #[cfg(feature = "mpc")]
    pub(crate) fn get_mpc_address_by_script(
        &self,
        script_hex: &str,
    ) -> Result<mpc_address::Model, Error> {
        block_on(
            mpc_address::Entity::find()
                .filter(mpc_address::Column::ScriptPubkey.eq(script_hex))
                .one(self.inner()),
        )?
        .ok_or(Error::Internal {
            details: format!("MPC address not found for script {script_hex}"),
        })
    }

    #[cfg(feature = "mpc")]
    pub(crate) fn get_last_mpc_address(
        &self,
        keychain: u8,
    ) -> Result<Option<mpc_address::Model>, Error> {
        Ok(block_on(
            mpc_address::Entity::find()
                .filter(mpc_address::Column::Keychain.eq(keychain))
                .order_by_desc(mpc_address::Column::DerivationIndex)
                .one(self.inner()),
        )?)
    }

    #[cfg(feature = "mpc")]
    pub(crate) fn get_next_mpc_derivation_index(&self, keychain: u8) -> Result<u32, Error> {
        let max_idx = block_on(
            mpc_address::Entity::find()
                .filter(mpc_address::Column::Keychain.eq(keychain))
                .order_by_desc(mpc_address::Column::DerivationIndex)
                .one(self.inner()),
        )?;
        Ok(max_idx.map(|a| a.derivation_index + 1).unwrap_or(0))
    }
}

pub(crate) mod enums;
