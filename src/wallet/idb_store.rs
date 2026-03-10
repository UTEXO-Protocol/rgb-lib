//! IndexedDB persistence for WASM wallet snapshots.

use bdk_wallet::ChangeSet;
use rexie::{ObjectStore, Rexie, TransactionMode};
use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use crate::database::memory_db::InMemoryDb;

const DB_NAME: &str = "rgb_lib_wallet";
const DB_VERSION: u32 = 1;
const STORE_NAME: &str = "snapshots";

/// A serializable snapshot of wallet state for IndexedDB persistence.
#[derive(Serialize, Deserialize)]
pub struct WalletSnapshot {
    /// The in-memory RGB-lib database.
    pub db: InMemoryDb,
    /// The BDK wallet changeset.
    pub bdk_changeset: Option<ChangeSet>,
}

async fn open_db() -> Result<Rexie, String> {
    let rexie = Rexie::builder(DB_NAME)
        .version(DB_VERSION)
        .add_object_store(ObjectStore::new(STORE_NAME))
        .build()
        .await
        .map_err(|e| format!("IndexedDB open error: {e:?}"))?;
    Ok(rexie)
}

/// Save a wallet snapshot to IndexedDB under the given key.
pub async fn save_snapshot(key: &str, snapshot: &WalletSnapshot) -> Result<(), String> {
    let db = open_db().await?;
    let tx = db
        .transaction(&[STORE_NAME], TransactionMode::ReadWrite)
        .map_err(|e| format!("IndexedDB transaction error: {e:?}"))?;
    let store = tx
        .store(STORE_NAME)
        .map_err(|e| format!("IndexedDB store error: {e:?}"))?;

    let json_str = serde_json::to_string(snapshot).map_err(|e| format!("Serialize error: {e}"))?;
    let js_key = JsValue::from_str(key);
    let js_val = JsValue::from_str(&json_str);

    store
        .put(&js_val, Some(&js_key))
        .await
        .map_err(|e| format!("IndexedDB put error: {e:?}"))?;
    tx.done()
        .await
        .map_err(|e| format!("IndexedDB commit error: {e:?}"))?;
    Ok(())
}

/// Load a wallet snapshot from IndexedDB for the given key.
pub async fn load_snapshot(key: &str) -> Result<Option<WalletSnapshot>, String> {
    let db = open_db().await?;
    let tx = db
        .transaction(&[STORE_NAME], TransactionMode::ReadOnly)
        .map_err(|e| format!("IndexedDB transaction error: {e:?}"))?;
    let store = tx
        .store(STORE_NAME)
        .map_err(|e| format!("IndexedDB store error: {e:?}"))?;

    let js_key = JsValue::from_str(key);
    let result = store
        .get(js_key)
        .await
        .map_err(|e| format!("IndexedDB get error: {e:?}"))?;

    match result {
        Some(js_val) => {
            let json_str = js_val
                .as_string()
                .ok_or_else(|| "IndexedDB value is not a string".to_string())?;
            let snapshot: WalletSnapshot =
                serde_json::from_str(&json_str).map_err(|e| format!("Deserialize error: {e}"))?;
            Ok(Some(snapshot))
        }
        None => Ok(None),
    }
}
