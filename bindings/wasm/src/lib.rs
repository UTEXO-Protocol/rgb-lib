use std::backtrace::Backtrace;
use std::cell::RefCell;
use std::panic;
use wasm_bindgen::prelude::*;

use rgb_lib::Wallet;
use rgb_lib::wallet::WalletData;

#[wasm_bindgen(js_namespace = console)]
extern "C" {
    #[wasm_bindgen(js_name = error)]
    fn console_error(s: &str);
}

#[wasm_bindgen(start)]
pub fn init() {
    let _ = instant::Instant::now();
    panic::set_hook(Box::new(move |info| {
        let msg = format!("[rgb-lib WASM panic] {}", info);
        console_error(&msg);
        let bt = Backtrace::force_capture();
        let bt_str = bt.to_string();
        if !bt_str.is_empty() && bt_str != "disabled backtrace\n" {
            console_error("Backtrace:");
            for line in bt_str.lines() {
                console_error(line);
            }
        }
    }));
}

#[wasm_bindgen]
pub fn generate_keys(network: &str) -> Result<JsValue, JsValue> {
    let bitcoin_network = network
        .parse::<rgb_lib::BitcoinNetwork>()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let keys = rgb_lib::generate_keys(bitcoin_network);
    serde_wasm_bindgen::to_value(&keys).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub fn restore_keys(network: &str, mnemonic: &str) -> Result<JsValue, JsValue> {
    let bitcoin_network = network
        .parse::<rgb_lib::BitcoinNetwork>()
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let keys = rgb_lib::restore_keys(bitcoin_network, mnemonic.to_string())
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    serde_wasm_bindgen::to_value(&keys).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub struct WasmWallet {
    inner: RefCell<Wallet>,
}

#[wasm_bindgen]
impl WasmWallet {
    /// Create a new RGB wallet from a JSON-encoded WalletData.
    #[wasm_bindgen(constructor)]
    pub fn new(wallet_data_json: &str) -> Result<WasmWallet, JsValue> {
        let wd: WalletData = serde_json::from_str(wallet_data_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid WalletData JSON: {e}")))?;
        let wallet = Wallet::new(wd).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmWallet {
            inner: RefCell::new(wallet),
        })
    }

    /// Return the WalletData as a JS object.
    pub fn get_wallet_data(&self) -> Result<JsValue, JsValue> {
        let wd = self.inner.borrow().get_wallet_data();
        serde_wasm_bindgen::to_value(&wd).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Issue a new NIA (Non-Inflatable Asset).
    ///
    /// `amounts_js` is a JS array of u64 values.
    pub fn issue_asset_nia(
        &self,
        ticker: &str,
        name: &str,
        precision: u8,
        amounts_js: JsValue,
    ) -> Result<JsValue, JsValue> {
        let amounts: Vec<u64> = serde_wasm_bindgen::from_value(amounts_js)
            .map_err(|e| JsValue::from_str(&format!("Invalid amounts array: {e}")))?;
        let asset = self
            .inner
            .borrow()
            .issue_asset_nia(ticker.to_string(), name.to_string(), precision, amounts)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&asset).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Return the BTC balance. Always skips sync on wasm32.
    pub fn get_btc_balance(&self) -> Result<JsValue, JsValue> {
        let balance = self
            .inner
            .borrow_mut()
            .get_btc_balance(None, true)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&balance).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Return the balance for a specific asset.
    pub fn get_asset_balance(&self, asset_id: &str) -> Result<JsValue, JsValue> {
        let balance = self
            .inner
            .borrow()
            .get_asset_balance(asset_id.to_string())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&balance).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// List known RGB assets. Pass a JS array of schema strings to filter, or empty for all.
    pub fn list_assets(&self, filter_asset_schemas_js: JsValue) -> Result<JsValue, JsValue> {
        let schemas: Vec<rgb_lib::AssetSchema> =
            serde_wasm_bindgen::from_value(filter_asset_schemas_js)
                .map_err(|e| JsValue::from_str(&format!("Invalid schemas: {e}")))?;
        let assets = self
            .inner
            .borrow()
            .list_assets(schemas)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&assets).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// List RGB transfers, optionally filtered by asset ID.
    pub fn list_transfers(&self, asset_id: Option<String>) -> Result<JsValue, JsValue> {
        let transfers = self
            .inner
            .borrow()
            .list_transfers(asset_id)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&transfers).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// List unspent outputs. Always skips sync on wasm32.
    pub fn list_unspents(&self, settled_only: bool) -> Result<JsValue, JsValue> {
        let unspents = self
            .inner
            .borrow_mut()
            .list_unspents(None, settled_only, true)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&unspents).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// List Bitcoin transactions. Always skips sync on wasm32.
    pub fn list_transactions(&self) -> Result<JsValue, JsValue> {
        let txs = self
            .inner
            .borrow_mut()
            .list_transactions(None, true)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&txs).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Sign a PSBT (base64-encoded). Returns the signed PSBT string.
    pub fn sign_psbt(&self, unsigned_psbt: &str) -> Result<String, JsValue> {
        self.inner
            .borrow()
            .sign_psbt(unsigned_psbt.to_string(), None)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Finalize a signed PSBT (base64-encoded). Returns the finalized PSBT string.
    pub fn finalize_psbt(&self, signed_psbt: &str) -> Result<String, JsValue> {
        self.inner
            .borrow()
            .finalize_psbt(signed_psbt.to_string(), None)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Blind an UTXO to receive RGB assets. Returns ReceiveData as a JS object.
    ///
    /// `assignment_js` is a JS object like `{ "Fungible": 100 }` or `"NonFungible"` or `"Any"`.
    /// `transport_endpoints_js` is a JS array of endpoint strings.
    pub fn blind_receive(
        &self,
        asset_id: Option<String>,
        assignment_js: JsValue,
        duration_seconds: Option<u32>,
        transport_endpoints_js: JsValue,
        min_confirmations: u8,
    ) -> Result<JsValue, JsValue> {
        let assignment: rgb_lib::Assignment = serde_wasm_bindgen::from_value(assignment_js)
            .map_err(|e| JsValue::from_str(&format!("Invalid assignment: {e}")))?;
        let transport_endpoints: Vec<String> =
            serde_wasm_bindgen::from_value(transport_endpoints_js)
                .map_err(|e| JsValue::from_str(&format!("Invalid transport endpoints: {e}")))?;
        let data = self
            .inner
            .borrow()
            .blind_receive(
                asset_id,
                assignment,
                duration_seconds,
                transport_endpoints,
                min_confirmations,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&data).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Create an address to receive RGB assets via witness TX. Returns ReceiveData as a JS object.
    pub fn witness_receive(
        &self,
        asset_id: Option<String>,
        assignment_js: JsValue,
        duration_seconds: Option<u32>,
        transport_endpoints_js: JsValue,
        min_confirmations: u8,
    ) -> Result<JsValue, JsValue> {
        let assignment: rgb_lib::Assignment = serde_wasm_bindgen::from_value(assignment_js)
            .map_err(|e| JsValue::from_str(&format!("Invalid assignment: {e}")))?;
        let transport_endpoints: Vec<String> =
            serde_wasm_bindgen::from_value(transport_endpoints_js)
                .map_err(|e| JsValue::from_str(&format!("Invalid transport endpoints: {e}")))?;
        let data = self
            .inner
            .borrow_mut()
            .witness_receive(
                asset_id,
                assignment,
                duration_seconds,
                transport_endpoints,
                min_confirmations,
            )
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&data).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Return a new Bitcoin address from the vanilla wallet.
    pub fn get_address(&self) -> Result<String, JsValue> {
        self.inner
            .borrow_mut()
            .get_address()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Delete failed transfers. Returns true if any were deleted.
    pub fn delete_transfers(
        &self,
        batch_transfer_idx: Option<i32>,
        no_asset_only: bool,
    ) -> Result<bool, JsValue> {
        self.inner
            .borrow()
            .delete_transfers(batch_transfer_idx, no_asset_only)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
