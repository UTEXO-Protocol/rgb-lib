//! In-memory BDK store for WASM (browser has no real filesystem).
//! Used when `data_dir == ":memory:"` and `target_arch = "wasm32"`.

use super::*;
use bdk_core::Merge;
use bdk_wallet::WalletPersister;
use serde::{Deserialize, Serialize};

/// In-memory store for BDK ChangeSet. Implements WalletPersister without file I/O.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(bound = "C: Serialize + for<'a> Deserialize<'a>")]
pub(crate) struct MemoryStore<C> {
    data: Option<C>,
}

impl<C> MemoryStore<C>
where
    C: Default + Merge + Clone,
{
    pub(crate) fn new() -> Self {
        Self { data: None }
    }
}

impl<C> MemoryStore<C> {
    pub(crate) fn get_data(&self) -> &Option<C> {
        &self.data
    }

    pub(crate) fn set_data(&mut self, data: Option<C>) {
        self.data = data;
    }
}

impl WalletPersister for MemoryStore<ChangeSet> {
    type Error = std::convert::Infallible;

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        Ok(persister.data.take().unwrap_or_default())
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        let mut current = persister.data.take().unwrap_or_default();
        current.merge(changeset.clone());
        persister.data = Some(current);
        Ok(())
    }
}
