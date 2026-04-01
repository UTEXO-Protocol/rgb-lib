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
    /// Create a new address via the MPC provider.
    fn create_address(
        &self,
        bitcoin_network: BitcoinNetwork,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<MpcAddressInfo, Error>;

    /// Sign a PSBT using the MPC provider.
    fn sign_psbt(&self, psbt: Psbt, signing_key_ids: Vec<String>) -> Result<Psbt, Error>;
}

#[cfg(feature = "dfns")]
pub mod dfns;
