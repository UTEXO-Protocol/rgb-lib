//! Wallet functionality.
//!
//! This module defines the [`Wallet`] and [`MultisigWallet`] structures and related functionality.

pub(crate) mod backup;
pub(crate) mod core;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) mod indexer;
#[cfg(feature = "mpc")]
pub(crate) mod mpc;
#[cfg(feature = "mpc")]
pub(crate) mod mpc_psbt;
pub(crate) mod multisig;
pub(crate) mod objects;
pub(crate) mod offline;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) mod online;
pub mod rust_only;
pub(crate) mod singlesig;
#[cfg(feature = "vss")]
pub mod vss;

#[cfg(test)]
pub(crate) mod test;

pub use backup::restore_backup;
#[cfg(feature = "mpc")]
pub use mpc::MpcWallet;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub use multisig::{
    BridgeInitResult, HubInfo, InitOperationResult, MultisigOnlineOptions, MultisigVotingStatus,
    Operation, OperationInfo, RespondToOperation, UserRole,
};
pub use multisig::{Cosigner, MultisigKeys, MultisigWallet};
pub use objects::{
    Address, AssetBFA, AssetCFA, AssetIFA, AssetNIA, AssetUDA, Assets, AssignmentsCollection,
    Balance, BlockTime, BtcBalance, DatabaseType, EmbeddedMedia, Invoice, InvoiceData, Media,
    Metadata, Online, Outpoint, PendingVanillaTx, ProofOfReserves, PsbtInputInfo, PsbtInspection,
    PsbtOutputInfo, ReceiveData, Recipient, RecipientInfo, RecipientType, RgbAllocation,
    RgbInputInfo, RgbInspection, RgbOperationInfo, RgbOutputInfo, RgbTransitionInfo, Token,
    TokenLight, Transaction, TransactionType, Transfer, TransferKind, TransferTransportEndpoint,
    TransportEndpoint, TypeOfTransition, Unspent, Utxo, WalletData, WalletDescriptors, WitnessData,
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub use objects::{
    BridgeBeginResult, BridgeDetails, BurnBeginResult, BurnDetails, InflateBeginResult,
    InflateDetails, OnlineOptions, OperationResult, RefreshFilter, RefreshResult,
    RefreshTransferStatus, RefreshedTransfer, SendBeginResult, SendDetails,
};
pub use offline::RgbWalletOpsOffline;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub use online::RgbWalletOpsOnline;
pub use singlesig::{SinglesigKeys, Wallet};

pub(crate) use backup::WalletBackup;
pub(crate) use core::{
    ASSETS_DIR, MEDIA_DIR, NUM_KNOWN_SCHEMAS, WalletCore, WalletInternals, setup_bdk, setup_db,
    setup_new_wallet, setup_rgb,
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub use core::{SyncKeychain, SyncOptions, SyncStrategy};
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) use indexer::Indexer;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) use objects::{
    AssetInfo, AssetSpend, BeginOperationData, BtcChange, FailTransfersOutcome, LocalRecipient,
    LocalRecipientData, LocalWitnessData, OnlineData, PrepareRgbPsbtResult,
    PrepareTransferPsbtResult, ReceivedConsignmentMeta, RefreshResultTrait,
    TryFailBatchTransferOutcome,
};
pub(crate) use objects::{
    InfoAssetTransfer, InfoBatchTransfer, IssueData, IssuedAssetDetails, LocalAssetData,
    LocalRgbAllocation, LocalTransportEndpoint, LocalUnspent, ReceiveDataInternal, TransferData,
    TransferEndData,
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) use offline::TRANSFER_DATA_FILE;
pub(crate) use offline::WalletOffline;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) use online::WalletOnline;

use super::*;

pub(crate) const CONSIGNMENT_FILE: &str = "consignment_out";
pub(crate) const FASCIA_FILE: &str = "fascia";
pub(crate) const UNSIGNED_PSBT_FILE: &str = "unsigned.psbt";

pub(crate) const SCHEMA_ID_NIA: &str =
    "rgb:sch:RWhwUfTMpuP2Zfx1~j4nswCANGeJrYOqDcKelaMV4zU#remote-digital-pegasus";
pub(crate) const SCHEMA_ID_UDA: &str =
    "rgb:sch:~6rjymf3GTE840lb5JoXm2aFwE8eWCk3mCjOf_mUztE#spider-montana-fantasy";
pub(crate) const SCHEMA_ID_CFA: &str =
    "rgb:sch:JgqK5hJX9YBT4osCV7VcW_iLTcA5csUCnLzvaKTTrNY#mars-house-friend";
pub(crate) const SCHEMA_ID_IFA: &str =
    "rgb:sch:IpjJhFLz3oywYKQxO3KmFgR0Aa415nlTNrNyEFqMZCE#shoe-colombo-mango";
pub(crate) const SCHEMA_ID_BFA: &str =
    "rgb:sch:mXfH3DI28cPIC8kkamtpgRC5Yct2WS6Cd6XPTGtst~A#first-bernard-paul";

pub(crate) const RGB_STATE_ASSET_OWNER: &str = "assetOwner";
pub(crate) const RGB_STATE_INFLATION_ALLOWANCE: &str = "inflationAllowance";
pub(crate) const RGB_STATE_BRIDGE_RIGHT: &str = "bridgeRight";
pub(crate) const RGB_GLOBAL_ISSUED_SUPPLY: &str = "issuedSupply";
pub(crate) const RGB_GLOBAL_BRIDGED_SUPPLY: &str = "bridgedSupply";
pub(crate) const RGB_GLOBAL_BRIDGE_LOCATION: &str = "bridgeLocation";
pub(crate) const RGB_GLOBAL_REJECT_LIST_URL: &str = "rejectListUrl";
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const RGB_METADATA_ALLOWED_INFLATION: &str = "allowedInflation";
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const RGB_METADATA_BURNED_ASSET: &str = "burnedAsset";
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) const RGB_METADATA_BURNED_INFLATION: &str = "burnedInflation";
/// Where a BFA burn's proceeds are owed; declared only by the BFA schema.
pub(crate) const RGB_METADATA_BURN_RECIPIENT: &str = "burnRecipient";
