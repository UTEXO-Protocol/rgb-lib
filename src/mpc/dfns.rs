//! DFNS MPC wallet provider implementation.
//!
//! This module implements the [`MpcWalletProvider`] trait using the DFNS API
//! for address creation and PSBT signing.
//!
//! DFNS requires a 3-step User Action Signing flow for all mutating requests
//! (POST/PUT/DELETE):
//! 1. Initiate a challenge via `/auth/action/init`
//! 2. Sign the challenge with the service account's P-256 private key
//! 3. Execute the actual request with the `X-DFNS-USERACTION` header

use std::collections::HashSet;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bdk_wallet::{
    KeychainKind,
    bitcoin::{Address as BdkAddress, Psbt},
};
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::utils::BitcoinNetwork;

use super::{MpcAddressInfo, MpcWalletProvider};

/// Configuration for the DFNS MPC wallet provider.
#[derive(Clone)]
pub struct DfnsConfig {
    /// DFNS API base URL (e.g., "https://api.dfns.io").
    pub api_url: String,
    /// Bearer authentication token (service account token).
    pub auth_token: String,
    /// Credential ID for signing user action challenges.
    pub cred_id: String,
    /// Private key in PEM format (P-256/secp256r1 ECDSA).
    pub private_key: String,
    /// The signing key ID for HD derivation (get this from a wallet's signingKey.id).
    pub master_key_id: String,
    /// Base derivation path prefix (e.g., "m/86").
    pub base_path: String,
}

impl std::fmt::Debug for DfnsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DfnsConfig")
            .field("api_url", &self.api_url)
            .field("auth_token", &"[REDACTED]")
            .field("cred_id", &self.cred_id)
            .field("private_key", &"[REDACTED]")
            .field("master_key_id", &self.master_key_id)
            .field("base_path", &self.base_path)
            .finish()
    }
}

/// Internal signer that supports P-256 and Ed25519 keys.
enum DfnsSigner {
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl DfnsSigner {
    /// Sign data with the appropriate algorithm.
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            DfnsSigner::P256(key) => {
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = key.sign(data);
                sig.to_der().as_bytes().to_vec()
            }
            DfnsSigner::Ed25519(key) => {
                use ed25519_dalek::Signer;
                key.sign(data).to_bytes().to_vec()
            }
        }
    }
}

/// DFNS MPC wallet provider.
///
/// Communicates with the DFNS API for address creation and PSBT signing.
/// All mutating requests go through the User Action Signing flow.
/// Supports both P-256 and Ed25519 service account keys.
pub struct DfnsProvider {
    config: DfnsConfig,
    http: reqwest::blocking::Client,
    signer: DfnsSigner,
}

// --- DFNS API request/response types ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsCreateWalletRequest {
    network: String,
    name: String,
    signing_key: DfnsSigningKeyRequest,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsSigningKeyRequest {
    scheme: String,
    curve: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    derive_from: Option<DfnsDeriveFrom>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsDeriveFrom {
    key_id: String,
    path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsCreateKeyRequest {
    name: String,
    scheme: String,
    curve: String,
    #[serde(rename = "masterKey")]
    master_key: bool,
}

/// Response from the DFNS key creation endpoint.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DfnsKeyResponse {
    /// The key ID.
    pub id: String,
    /// The public key.
    pub public_key: String,
    /// The signing scheme.
    pub scheme: String,
    /// The elliptic curve.
    pub curve: String,
}

/// Response from the DFNS wallet creation or get wallet endpoint.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DfnsWalletResponse {
    /// The wallet ID.
    pub id: String,
    /// The wallet's Bitcoin address.
    pub address: String,
    /// The signing key associated with this wallet.
    pub signing_key: DfnsSigningKeyResponse,
}

/// Signing key information from a DFNS wallet.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DfnsSigningKeyResponse {
    /// The key ID used for signing operations.
    pub id: String,
    /// The signing scheme (e.g., "Schnorr").
    #[allow(dead_code)]
    pub scheme: String,
    /// The elliptic curve (e.g., "secp256k1").
    #[allow(dead_code)]
    pub curve: String,
    /// The public key in hex format.
    #[allow(dead_code)]
    pub public_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsSignRequest {
    kind: String,
    psbt: String,
}

// --- User Action Signing types ---

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsActionInitRequest {
    user_action_payload: String,
    user_action_http_method: String,
    user_action_http_path: String,
    user_action_server_kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DfnsActionInitResponse {
    challenge: String,
    challenge_identifier: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsActionRequest {
    challenge_identifier: String,
    first_factor: DfnsFirstFactor,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsFirstFactor {
    kind: String,
    credential_assertion: DfnsCredentialAssertion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DfnsCredentialAssertion {
    cred_id: String,
    client_data: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DfnsActionResponse {
    user_action: String,
}

impl DfnsProvider {
    /// Create a new DFNS provider with the given configuration.
    ///
    /// The private key must be a P-256 (secp256r1) ECDSA key in PEM format.
    pub fn new(config: DfnsConfig) -> Result<Self, Error> {
        let http = reqwest::blocking::Client::builder()
            .user_agent("rgb-lib-dfns/0.1")
            .connect_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| Error::MpcProvider {
                details: format!("failed to create HTTP client: {e}"),
            })?;

        let signer = Self::parse_private_key(&config.private_key)?;

        Ok(Self {
            config,
            http,
            signer,
        })
    }

    /// Parse a PEM private key, auto-detecting P-256 vs Ed25519.
    fn parse_private_key(pem: &str) -> Result<DfnsSigner, Error> {
        // Try Ed25519 first (most common for DFNS service accounts)
        if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
            return Ok(DfnsSigner::Ed25519(key));
        }
        // Try P-256
        use p256::pkcs8::DecodePrivateKey;
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_pem(pem) {
            return Ok(DfnsSigner::P256(key));
        }
        Err(Error::MpcProvider {
            details: "failed to parse private key: not a valid P-256 or Ed25519 PEM key"
                .to_string(),
        })
    }

    /// Get wallet information from DFNS (GET — no user action signing needed).
    pub fn get_wallet(&self, wallet_id: &str) -> Result<DfnsWalletResponse, Error> {
        let url = format!("{}/wallets/{}", self.config.api_url, wallet_id);
        let response = self
            .http
            .get(&url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.auth_token),
            )
            .send()
            .map_err(|e| Error::MpcProvider {
                details: format!("DFNS API request failed: {e}"),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            return Err(Error::MpcProvider {
                details: format!("DFNS API returned {status}: {body}"),
            });
        }

        response.json().map_err(|e| Error::MpcProvider {
            details: format!("failed to parse response: {e}"),
        })
    }

    /// Create a master key on DFNS for HD derivation.
    pub fn create_master_key(&self, name: &str) -> Result<DfnsKeyResponse, Error> {
        let request = DfnsCreateKeyRequest {
            name: name.to_string(),
            scheme: "Schnorr".to_string(),
            curve: "secp256k1".to_string(),
            master_key: true,
        };

        let url = format!("{}/keys", self.config.api_url);
        self.post(&url, "/keys", &request)
    }

    /// Map a [`BitcoinNetwork`] to the DFNS network string.
    fn dfns_network(network: BitcoinNetwork) -> Result<&'static str, Error> {
        match network {
            BitcoinNetwork::Mainnet => Ok("Bitcoin"),
            BitcoinNetwork::Testnet => Ok("BitcoinTestnet3"),
            BitcoinNetwork::Signet | BitcoinNetwork::SignetCustom => Ok("BitcoinSignet"),
            _ => Err(Error::MpcProvider {
                details: format!(
                    "DFNS does not support network '{:?}'. Supported: Mainnet, Testnet, Signet",
                    network
                ),
            }),
        }
    }

    /// Build the derivation path for a given keychain and index.
    fn derivation_path(&self, keychain: KeychainKind, index: u32) -> String {
        let keychain_index = match keychain {
            KeychainKind::External => 0u8,
            KeychainKind::Internal => 1u8,
        };
        format!("{}/{}/{}", self.config.base_path, keychain_index, index)
    }

    /// Perform the DFNS User Action Signing flow and execute a POST request.
    ///
    /// 1. Initiate challenge (`/auth/action/init`)
    /// 2. Sign the challenge with P-256 (`/auth/action`)
    /// 3. Execute the actual request with the `X-DFNS-USERACTION` header
    fn post<T: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        path: &str,
        body: &T,
    ) -> Result<R, Error> {
        let body_json = serde_json::to_string(body).map_err(|e| Error::MpcProvider {
            details: format!("failed to serialize request body: {e}"),
        })?;

        // Step 1: Initiate user action challenge
        let init_request = DfnsActionInitRequest {
            user_action_payload: body_json.clone(),
            user_action_http_method: "POST".to_string(),
            user_action_http_path: path.to_string(),
            user_action_server_kind: "Api".to_string(),
        };

        let init_url = format!("{}/auth/action/init", self.config.api_url);
        let init_response = self
            .http
            .post(&init_url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.auth_token),
            )
            .header("Content-Type", "application/json")
            .json(&init_request)
            .send()
            .map_err(|e| Error::MpcProvider {
                details: format!("DFNS action init request failed: {e}"),
            })?;

        if !init_response.status().is_success() {
            let status = init_response.status();
            let body_text = init_response.text().unwrap_or_default();
            return Err(Error::MpcProvider {
                details: format!("DFNS action init returned {status}: {body_text}"),
            });
        }

        let init_data: DfnsActionInitResponse =
            init_response.json().map_err(|e| Error::MpcProvider {
                details: format!("failed to parse DFNS action init response: {e}"),
            })?;

        // Step 2: Sign the challenge with P-256
        let client_data = serde_json::json!({
            "type": "key.get",
            "challenge": init_data.challenge,
        })
        .to_string();

        let signature_bytes = self.signer.sign(client_data.as_bytes());

        let client_data_b64 = URL_SAFE_NO_PAD.encode(client_data.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature_bytes);

        let action_request = DfnsActionRequest {
            challenge_identifier: init_data.challenge_identifier,
            first_factor: DfnsFirstFactor {
                kind: "Key".to_string(),
                credential_assertion: DfnsCredentialAssertion {
                    cred_id: self.config.cred_id.clone(),
                    client_data: client_data_b64,
                    signature: signature_b64,
                },
            },
        };

        let action_url = format!("{}/auth/action", self.config.api_url);
        let action_response = self
            .http
            .post(&action_url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.auth_token),
            )
            .header("Content-Type", "application/json")
            .json(&action_request)
            .send()
            .map_err(|e| Error::MpcProvider {
                details: format!("DFNS action sign request failed: {e}"),
            })?;

        if !action_response.status().is_success() {
            let status = action_response.status();
            let body_text = action_response.text().unwrap_or_default();
            return Err(Error::MpcProvider {
                details: format!("DFNS action sign returned {status}: {body_text}"),
            });
        }

        let action_data: DfnsActionResponse =
            action_response.json().map_err(|e| Error::MpcProvider {
                details: format!("failed to parse DFNS action sign response: {e}"),
            })?;

        // Step 3: Execute the actual request with the user action token
        let response = self
            .http
            .post(url)
            .header(
                "Authorization",
                format!("Bearer {}", self.config.auth_token),
            )
            .header("Content-Type", "application/json")
            .header("X-DFNS-USERACTION", &action_data.user_action)
            .body(body_json)
            .send()
            .map_err(|e| Error::MpcProvider {
                details: format!("DFNS API request failed: {e}"),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body_text = response.text().unwrap_or_default();
            return Err(Error::MpcProvider {
                details: format!("DFNS API returned {status}: {body_text}"),
            });
        }

        let body_text = response.text().map_err(|e| Error::MpcProvider {
            details: format!("failed to read DFNS API response body: {e}"),
        })?;

        serde_json::from_str::<R>(&body_text).map_err(|e| Error::MpcProvider {
            details: format!(
                "failed to parse DFNS API response: {e}\nBody: {}",
                &body_text[..body_text.len().min(500)]
            ),
        })
    }
}

impl MpcWalletProvider for DfnsProvider {
    fn create_address(
        &self,
        bitcoin_network: BitcoinNetwork,
        keychain: KeychainKind,
        index: u32,
    ) -> Result<MpcAddressInfo, Error> {
        let network = Self::dfns_network(bitcoin_network)?.to_string();
        let path = self.derivation_path(keychain, index);

        let request = DfnsCreateWalletRequest {
            network,
            name: format!("rgb-lib-{}-{}", path, index),
            signing_key: DfnsSigningKeyRequest {
                scheme: "Schnorr".to_string(),
                curve: "secp256k1".to_string(),
                derive_from: Some(DfnsDeriveFrom {
                    key_id: self.config.master_key_id.clone(),
                    path: path.clone(),
                }),
            },
        };

        let url = format!("{}/wallets", self.config.api_url);
        let response: DfnsWalletResponse = self.post(&url, "/wallets", &request)?;

        let bdk_address =
            BdkAddress::from_str(&response.address).map_err(|e| Error::MpcProvider {
                details: format!("invalid address from DFNS: {e}"),
            })?;
        let bdk_address = bdk_address
            .require_network(bitcoin_network.into())
            .map_err(|e| Error::MpcProvider {
                details: format!("address network mismatch: {e}"),
            })?;
        let script_pubkey = bdk_address.script_pubkey();

        Ok(MpcAddressInfo {
            address: response.address,
            script_pubkey,
            // Store the wallet ID — PSBT signing uses /wallets/{walletId}/signatures
            signing_key_id: response.id,
            derivation_index: index,
        })
    }

    fn sign_psbt(&self, psbt: Psbt, signing_key_ids: Vec<String>) -> Result<Psbt, Error> {
        // Deduplicate IDs while preserving deterministic order
        let mut seen = HashSet::new();
        let unique_ids: Vec<&String> = signing_key_ids
            .iter()
            .filter(|id| seen.insert(id.as_str()))
            .collect();

        let mut current_psbt = psbt;

        for wallet_id in unique_ids {
            let psbt_bytes = current_psbt.serialize();
            let psbt_hex = format!("0x{}", hex::encode(&psbt_bytes));

            let request = DfnsSignRequest {
                kind: "Psbt".to_string(),
                psbt: psbt_hex,
            };

            let http_path = format!("/wallets/{}/signatures", wallet_id);
            let url = format!("{}{}", self.config.api_url, http_path);
            let response: serde_json::Value = self.post(&url, &http_path, &request)?;

            let status = response
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if status != "Signed" && status != "Executed" {
                return Err(Error::MpcProvider {
                    details: format!(
                        "DFNS signature failed (status: {status}, wallet: {wallet_id})"
                    ),
                });
            }

            let signed_data = response
                .get("signedData")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::MpcProvider {
                    details: format!(
                        "DFNS signature response has no signedData (status: {status})"
                    ),
                })?;

            let signed_hex = signed_data.strip_prefix("0x").unwrap_or(signed_data);

            let signed_bytes = hex::decode(signed_hex).map_err(|e| Error::MpcProvider {
                details: format!("invalid hex in DFNS signed_data: {e}"),
            })?;

            current_psbt = Psbt::deserialize(&signed_bytes).map_err(|e| Error::MpcProvider {
                details: format!("failed to deserialize signed PSBT from DFNS: {e}"),
            })?;
        }

        Ok(current_psbt)
    }
}
