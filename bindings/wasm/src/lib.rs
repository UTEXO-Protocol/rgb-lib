use std::backtrace::Backtrace;
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

// ---------------------------------------------------------------------------
// WasmWallet: wraps rgb_lib::Wallet for browser use
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct WasmWallet {
    inner: Wallet,
}

#[wasm_bindgen]
impl WasmWallet {
    /// Create a new RGB wallet from a JSON-encoded WalletData.
    #[wasm_bindgen(constructor)]
    pub fn new(wallet_data_json: &str) -> Result<WasmWallet, JsValue> {
        let wd: WalletData = serde_json::from_str(wallet_data_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid WalletData JSON: {e}")))?;
        let wallet = Wallet::new(wd).map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(WasmWallet { inner: wallet })
    }

    /// Return the WalletData as a JS object.
    pub fn get_wallet_data(&self) -> Result<JsValue, JsValue> {
        let wd = self.inner.get_wallet_data();
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
            .issue_asset_nia(ticker.to_string(), name.to_string(), precision, amounts)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        serde_wasm_bindgen::to_value(&asset).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
