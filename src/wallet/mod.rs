//! RGB wallet
//!
//! This module defines the [`Wallet`] related modules.

#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod backup;
#[cfg(target_arch = "wasm32")]
pub mod idb_store;
#[cfg(target_arch = "wasm32")]
pub(crate) mod memory_store;
pub(crate) mod offline;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub(crate) mod online;
pub mod rust_only;
#[cfg(feature = "vss")]
pub mod vss;

#[cfg(test)]
pub(crate) mod test;

pub use offline::*;
#[cfg(any(feature = "electrum", feature = "esplora"))]
pub use online::*;

use super::*;
