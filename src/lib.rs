#![allow(clippy::too_many_arguments)]
#![cfg_attr(target_arch = "wasm32", allow(dead_code, unused_imports))]
#![warn(missing_docs)]

//! A library to manage wallets for RGB assets.
//!
//! ## Wallet
//! The main component of the library is the [`Wallet`].
//!
//! It allows to create and operate an RGB wallet that can issue, send and receive NIA, CFA, IFA and
//! UDA assets. The library also manages UTXOs and asset allocations.
//!
//! ## Backend
//! The library uses BDK for walleting operations and several components from the RGB ecosystem for
//! RGB asset operations.
//!
//! ## Database
//! A SQLite database is used to persist data to disk.
//!
//! Database support is designed in order to support multiple database backends. At the moment only
//! SQLite is supported but adding more should be relatively easy.
//!
//! ## Api
//! RGB asset transfers require the exchange of off-chain data in the form of consignment or media
//! files.
//!
//! The library currently implements the API for a proxy server to support these data exchanges
//! between sender and receiver.
//!
//! ## Errors
//! Errors are handled with the crate `thiserror`.
//!
//! ## FFI
//! Library functionality is exposed for other languages via FFI bindings.
//!
//! ## Examples
//! ### Create an RGB wallet
//! ```
//! use rgb_lib::wallet::{DatabaseType, Wallet, WalletData};
//! use rgb_lib::{generate_keys, AssetSchema, BitcoinNetwork};
//!
//! fn main() -> Result<(), rgb_lib::Error> {
//!     let data_dir = tempfile::tempdir()?;
//!     let keys = generate_keys(BitcoinNetwork::Regtest);
//!     let wallet_data = WalletData {
//!         data_dir: data_dir.path().to_str().unwrap().to_string(),
//!         bitcoin_network: BitcoinNetwork::Regtest,
//!         database_type: DatabaseType::Sqlite,
//!         max_allocations_per_utxo: 5,
//!         account_xpub_vanilla: keys.account_xpub_vanilla,
//!         account_xpub_colored: keys.account_xpub_colored,
//!         mnemonic: Some(keys.mnemonic),
//!         master_fingerprint: keys.master_fingerprint,
//!         vanilla_keychain: None,
//!         supported_schemas: vec![AssetSchema::Nia],
//!     };
//!     let wallet = Wallet::new(wallet_data)?;
//!
//!     Ok(())
//! }
//! ```

#[cfg(all(target_arch = "wasm32", feature = "electrum"))]
compile_error!("feature `electrum` is not supported on wasm32; use `esplora`.");

pub(crate) mod api;
pub(crate) mod database;
pub(crate) mod error;
pub mod keys;
pub mod utils;
pub mod wallet;

pub use bdk_wallet;
pub use bdk_wallet::bitcoin;
pub use rgbinvoice::RgbTransport;
pub use rgbstd::{
    ChainNet, ContractId, Txid as RgbTxid,
    containers::{ConsignmentExt, Fascia, FileContent, PubWitness, Transfer as RgbTransfer},
    indexers::AnyResolver,
    persistence::UpdateRes,
    schema::SchemaId,
    validation::{ValidationConfig, ValidationError},
    vm::WitnessOrd,
};

#[cfg(not(target_arch = "wasm32"))]
pub use crate::wallet::backup::restore_backup;
pub use crate::{
    database::enums::{AssetSchema, Assignment, TransferStatus, TransportType},
    error::Error,
    keys::{generate_keys, restore_keys},
    utils::BitcoinNetwork,
    wallet::{RecipientType, TransactionType, TransferKind, Wallet},
};

#[cfg(any(feature = "electrum", feature = "esplora"))]
use std::{
    cmp::{Ordering, max, min},
    collections::hash_map::DefaultHasher,
    hash::Hasher,
    num::NonZeroU32,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt, fs,
    hash::Hash,
    io::{self, ErrorKind, Read, Write},
    panic,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

#[cfg(target_arch = "wasm32")]
use crate::database::memory_db::ActiveValue;
use amplify::{Wrapper, bmap, confinement::Confined, s};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use base64::{Engine as _, engine::general_purpose};
#[cfg(feature = "electrum")]
use bdk_electrum::{
    BdkElectrumClient,
    electrum_client::{Client as ElectrumClient, ElectrumApi, Error as ElectrumError, Param},
};
#[cfg(feature = "esplora")]
use bdk_esplora::esplora_client::Error as EsploraError;
#[cfg(all(not(target_arch = "wasm32"), feature = "esplora"))]
use bdk_esplora::{
    EsploraExt,
    esplora_client::{BlockingClient as EsploraClient, Builder as EsploraBuilder},
};
#[cfg(feature = "esplora")]
use bdk_wallet::bitcoin::Txid;
#[cfg(not(target_arch = "wasm32"))]
use bdk_wallet::file_store::Store;
use bdk_wallet::{
    ChangeSet, KeychainKind, LocalOutput, PersistedWallet, SignOptions, Wallet as BdkWallet,
    bitcoin::{
        Address as BdkAddress, Amount as BdkAmount, BlockHash, Network as BdkNetwork, NetworkKind,
        OutPoint, OutPoint as BdkOutPoint, ScriptBuf, TxOut,
        bip32::{ChildNumber, DerivationPath, Fingerprint, KeySource, Xpriv, Xpub},
        constants::ChainHash,
        hashes::{Hash as Sha256Hash, sha256},
        psbt::{ExtractTxError, Psbt},
        secp256k1::Secp256k1,
    },
    chain::{CanonicalizationParams, ChainPosition},
    descriptor::Segwitv0,
    keys::{
        DerivableKey, DescriptorKey,
        DescriptorKey::{Public, Secret},
        ExtendedKey, GeneratableKey,
        bip39::{Language, Mnemonic, WordCount},
    },
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use bdk_wallet::{
    Update,
    bitcoin::{Transaction as BdkTransaction, blockdata::fee_rate::FeeRate},
    chain::{
        DescriptorExt,
        spk_client::{FullScanRequest, FullScanResponse, SyncRequest, SyncResponse},
    },
    coin_selection::InsufficientFunds,
};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305,
    aead::{generic_array::GenericArray, stream},
};
#[cfg(not(target_arch = "wasm32"))]
use file_format::FileFormat;
#[cfg(not(target_arch = "wasm32"))]
use futures::executor::block_on;
use psrgbt::{RgbOutExt, RgbPsbtExt};
use rand::{Rng, distr::Alphanumeric};
#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(feature = "electrum", feature = "esplora"))]
use reqwest::{
    blocking::{Client as RestClient, multipart},
    header::CONTENT_TYPE,
};
#[cfg(not(target_arch = "wasm32"))]
use rgb_lib_migration::{
    ArrayType, ColumnType, Migrator, MigratorTrait, Nullable, Value, ValueType, ValueTypeErr,
};
use rgbinvoice::{AddressPayload, Beneficiary, RgbInvoice, RgbInvoiceBuilder, XChainNet};
#[cfg(feature = "electrum")]
use rgbstd::indexers::electrum_blocking::electrum_client::ConfigBuilder;
use rgbstd::{
    Allocation, Amount, Genesis, GraphSeal, Identity, Layer1, Operation, Opout, OutputSeal,
    OwnedFraction, Precision, Schema, SecretSeal, TokenIndex, Transition, TransitionType,
    TypeSystem,
    containers::{BuilderSeal, Kit, ValidContract, ValidKit, ValidTransfer},
    contract::{AllocatedState, ContractBuilder, IssuerWrapper, TransitionBuilder},
    info::{ContractInfo, SchemaInfo},
    invoice::{InvoiceState, Pay2Vout},
    persistence::{MemContract, MemContractState, StashReadProvider, Stock, fs::FsBinStore},
    rgbcore::commit_verify::Conceal,
    stl::{
        AssetSpec, Attachment, ContractTerms, Details, EmbeddedMedia as RgbEmbeddedMedia,
        MediaType, Name, ProofOfReserves as RgbProofOfReserves, RejectListUrl, RicardianContract,
        Ticker, TokenData,
    },
    txout::{BlindSeal, CloseMethod, ExplicitSeal},
    validation::{
        ResolveWitness, Scripts, Status, WitnessOrdProvider, WitnessResolverError, WitnessStatus,
    },
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use rgbstd::{
    Assign, KnownTransition,
    containers::Consignment,
    contract::SchemaWrapper,
    daggy::Walker,
    txout::TxPtr,
    validation::{OpoutsDagData, Validity, Warning},
};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use schemata::{
    CfaWrapper, IfaWrapper, NiaWrapper, OS_ASSET, OS_INFLATION, OS_REPLACE, UdaWrapper,
};
use schemata::{
    CollectibleFungibleAsset, InflatableFungibleAsset, NonInflatableAsset, UniqueDigitalAsset,
};
use scrypt::{
    Params, Scrypt,
    password_hash::{PasswordHasher, Salt, SaltString, rand_core::OsRng},
};
#[cfg(not(target_arch = "wasm32"))]
use sea_orm::{
    ActiveValue, ColumnTrait, ConnectOptions, Database, DatabaseConnection, DbErr,
    DeriveActiveEnum, EntityTrait, EnumIter, IntoActiveValue, JsonValue, QueryFilter, QueryOrder,
    QueryResult, TryGetError, TryGetable, TryIntoModel,
};
use serde::de::{self, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use slog::{Drain, Logger, debug, error, info, o, warn};
#[cfg(not(target_arch = "wasm32"))]
use slog_async::AsyncGuard;
#[cfg(not(target_arch = "wasm32"))]
use slog_term::{FullFormat, PlainDecorator};
use strict_encoding::{DecodeError, DeserializeError, FieldName};
#[cfg(not(target_arch = "wasm32"))]
use tempfile::TempDir;
use time::OffsetDateTime;
use typenum::consts::U32;
#[cfg(not(target_arch = "wasm32"))]
use walkdir::WalkDir;
#[cfg(not(target_arch = "wasm32"))]
use zip::write::SimpleFileOptions;

#[cfg(not(target_arch = "wasm32"))]
use crate::database::RgbLibDatabase;
use crate::database::{
    DbAsset, DbAssetActMod, DbAssetTransfer, DbAssetTransferActMod, DbBackupInfo,
    DbBackupInfoActMod, DbBatchTransfer, DbBatchTransferActMod, DbColoring, DbColoringActMod,
    DbMedia, DbMediaActMod, DbPendingWitnessScriptActMod, DbToken, DbTokenActMod, DbTokenMedia,
    DbTokenMediaActMod, DbTransfer, DbTransferActMod, DbTransferTransportEndpoint,
    DbTransferTransportEndpointActMod, DbTransportEndpoint, DbTransportEndpointActMod, DbTxo,
    DbTxoActMod, DbWalletTransactionActMod,
};
#[cfg(feature = "electrum")]
use crate::utils::INDEXER_BATCH_SIZE;
#[cfg(feature = "esplora")]
use crate::utils::INDEXER_PARALLEL_REQUESTS;
#[cfg(test)]
use crate::wallet::test::{mock_asset_terms, mock_contract_details, mock_token_data};
#[cfg(test)]
use crate::wallet::test::{mock_chain_net, skip_build_dag, skip_check_fee_rate};
#[cfg(any(feature = "electrum", feature = "esplora"))]
#[cfg(test)]
use crate::wallet::test::{mock_input_unspents, mock_vout};
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::{
    api::proxy::GetConsignmentResponse,
    database::{DbData, LocalRecipient, LocalRecipientData, LocalWitnessData},
    error::IndexerError,
    utils::{INDEXER_STOP_GAP, OffchainResolver, script_buf_from_recipient_id},
    wallet::{AssignmentsCollection, Indexer},
};
#[cfg(not(target_arch = "wasm32"))]
#[cfg(any(feature = "electrum", feature = "esplora"))]
use crate::{
    api::proxy::Proxy,
    api::reject_list::RejectList,
    utils::{check_proxy, get_indexer_and_resolver, get_rest_client},
};
use crate::{
    database::{
        LocalRgbAllocation, LocalTransportEndpoint, LocalUnspent, TransferData,
        enums::{ColoringType, RecipientTypeFull, WalletTransactionType},
    },
    error::InternalError,
    utils::{
        DumbResolver, LOG_FILE, RgbRuntime, adjust_canonicalization, beneficiary_from_script_buf,
        from_str_or_number_mandatory, from_str_or_number_optional, get_account_xpubs,
        get_descriptors, get_descriptors_from_xpubs, load_rgb_runtime, now, parse_address_str,
        setup_logger, str_to_xpub,
    },
    wallet::{
        Balance, NUM_KNOWN_SCHEMAS, Outpoint, SCHEMA_ID_CFA, SCHEMA_ID_IFA, SCHEMA_ID_NIA,
        SCHEMA_ID_UDA,
    },
};
