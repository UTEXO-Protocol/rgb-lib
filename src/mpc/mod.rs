//! MPC wallet provider trait and types.

use bdk_wallet::{
    KeychainKind,
    bitcoin::{Psbt, ScriptBuf},
};

use crate::error::Error;
use crate::utils::BitcoinNetwork;

/// Address information returned by an MPC wallet provider.
#[derive(Debug, Clone)]
pub struct MpcAddressInfo {
    /// The Bitcoin address string.
    pub address: String,
    /// The script pubkey for this address.
    pub script_pubkey: ScriptBuf,
    /// The MPC signing key identifier.
    pub signing_key_id: String,
    /// The BIP32 derivation index used.
    pub derivation_index: u32,
}

/// Trait for MPC wallet providers.
pub trait MpcWalletProvider: Send + Sync {
    /// Resolve an address via the MPC provider. Repeated calls for the same
    /// wallet/network/keychain/index MUST return the same address and key ID,
    /// including after a local transaction rollback or a dry run. Providers
    /// with non-idempotent creation APIs must persist/reconcile provisioning
    /// in their adapter before returning a binding here.
    fn create_address(
        &self,
        bitcoin_network: BitcoinNetwork,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<MpcAddressInfo, Error>;

    /// Sign a PSBT using the MPC provider, preserving its transaction and RGB
    /// metadata. P2WPKH adapters must return finalized witnesses; the library
    /// finalizes Taproot key-path signatures. A Taproot output key must never
    /// be treated as an internal key and tweaked a second time.
    fn sign_psbt(&self, psbt: Psbt, signing_key_ids: Vec<String>) -> Result<Psbt, Error>;
}

#[cfg(feature = "dfns")]
pub mod dfns;
