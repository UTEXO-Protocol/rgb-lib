use super::*;

/// keccak256("FundsIn(address,uint256,uint256)")
const FUNDS_IN_TOPIC: &str = "0xcf4f3270b7400c5ca42954767c516b7c595dcd8038cdd121945a474c616208f8";

pub(crate) struct EthClient {
    client: RestClient,
    rpc_url: String,
}

// TODO: drop allow(dead_code) when we decided which fields we need
/// A single log entry returned by `eth_getLogs`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EthLog {
    /// Contract address that emitted the event.
    #[allow(dead_code)]
    pub address: String,
    /// Indexed topic hashes (topic[0] = event signature hash).
    pub topics: Vec<String>,
    /// ABI-encoded non-indexed parameters.
    pub data: String,
    /// Block number (hex).
    #[allow(dead_code)]
    pub block_number: Option<String>,
    /// Transaction hash.
    #[allow(dead_code)]
    pub transaction_hash: Option<String>,
    /// Log index within the block (hex).
    #[allow(dead_code)]
    pub log_index: Option<String>,
}

/// Decoded FundsIn event from the Bridge contract.
#[derive(Debug)]
pub(crate) struct FundsInEvent {
    /// Locked amount.
    pub amount: u64,
    /// RGB operation ID (32 bytes).
    pub operation_id: [u8; 32],
}

#[derive(Debug, Serialize)]
struct NullRequest;

/// Decode a hex-encoded ABI word (32 bytes) at the given word index from `data`.
/// `data` must start with "0x".
fn abi_word(data: &str, index: usize) -> Result<[u8; 32], Error> {
    let hex = data.strip_prefix("0x").unwrap_or(data);
    let start = index * 64;
    let end = start + 64;
    if hex.len() < end {
        return Err(Error::Network {
            details: format!("ABI data too short: expected at least {end} hex chars"),
        });
    }
    let mut buf = [0u8; 32];
    hex::decode_to_slice(&hex[start..end], &mut buf).map_err(|e| Error::Network {
        details: format!("ABI hex decode error: {e}"),
    })?;
    Ok(buf)
}

impl EthLog {
    /// Try to parse this log as a FundsIn event.
    /// Returns `None` if the log topic doesn't match.
    pub fn as_funds_in(&self) -> Result<Option<FundsInEvent>, Error> {
        let Some(topic0) = self.topics.first() else {
            return Ok(None);
        };

        if !topic0.eq_ignore_ascii_case(FUNDS_IN_TOPIC) {
            return Ok(None);
        }

        let data_hex = self.data.strip_prefix("0x").unwrap_or(&self.data);
        let words = data_hex.len() / 64;

        // Legacy format:
        // event FundsIn(address token, uint256 amount, uint256 operationId)
        // data = abi.encode(token, amount, operationId)
        if words >= 3 {
            let amount_word = abi_word(&self.data, 1)?;
            let amount = u64::from_be_bytes(amount_word[24..32].try_into().unwrap());
            let operation_id = abi_word(&self.data, 2)?;
            return Ok(Some(FundsInEvent {
                amount,
                operation_id,
            }));
        }

        // Current format:
        // event FundsIn(address indexed sender, uint256 operationId, uint256 amount)
        // data = abi.encode(operationId, amount)
        if words >= 2 {
            let operation_id = abi_word(&self.data, 0)?;
            let amount_word = abi_word(&self.data, 1)?;
            let amount = u64::from_be_bytes(amount_word[24..32].try_into().unwrap());
            return Ok(Some(FundsInEvent {
                amount,
                operation_id,
            }));
        }

        Err(Error::Network {
            details: format!(
                "unexpected FundsIn ABI payload size: {} bytes",
                data_hex.len() / 2
            ),
        })
    }
}

/// JSON-RPC envelope used for both request and response.
#[derive(Debug, Serialize)]
struct RpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    params: P,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<R> {
    result: Option<R>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

/// Filter object for `eth_getLogs`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogFilter {
    /// Contract address to filter on.
    address: String,
    /// Start block (hex or tag).
    from_block: String,
    /// End block (hex or tag).
    to_block: String,
    /// Optional topic filters.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    topics: Vec<Option<String>>,
}

impl EthClient {
    pub(crate) fn new(rpc_url: &str) -> Result<Self, Error> {
        let client = RestClient::builder()
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT))
            .timeout(Duration::from_secs(READ_WRITE_TIMEOUT))
            .build()?;
        Ok(Self {
            client,
            rpc_url: rpc_url.to_string(),
        })
    }

    fn req_err(e: impl std::fmt::Display) -> Error {
        Error::Network {
            details: format!("Ethereum RPC: {e}"),
        }
    }

    /// Fetch logs emitted by `contract` between `from_block` and `to_block`.
    ///
    /// `topics` can be used to filter by event signature and/or indexed params.
    /// Pass an empty slice to get all events from the contract.
    ///
    /// Block parameters accept hex strings (`"0x0"`) or tags (`"earliest"`,
    /// `"latest"`).
    pub(crate) fn get_logs(
        &self,
        contract: &str,
        from_block: &str,
        to_block: &str,
    ) -> Result<Vec<EthLog>, Error> {
        let body = RpcRequest {
            jsonrpc: "2.0",
            method: "eth_getLogs",
            params: [LogFilter {
                address: contract.to_string(),
                from_block: from_block.to_string(),
                to_block: to_block.to_string(),
                topics: vec![Some(FUNDS_IN_TOPIC.to_string())],
            }],
            id: 1,
        };

        let resp: RpcResponse<Vec<EthLog>> = self
            .client
            .post(&self.rpc_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json()
            .map_err(Self::req_err)?;

        if let Some(err) = resp.error {
            return Err(Error::Network {
                details: format!("eth_getLogs error {}: {}", err.code, err.message),
            });
        }

        resp.result.ok_or_else(|| Error::Network {
            details: s!("eth_getLogs returned null result"),
        })
    }

    pub(crate) fn client_version(&self) -> Result<String, Error> {
        let body: RpcRequest<NullRequest> = RpcRequest {
            jsonrpc: "2.0",
            method: "web3_clientVersion",
            params: NullRequest,
            id: 1,
        };
        let resp: RpcResponse<String> = self
            .client
            .post(&self.rpc_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json()
            .map_err(Self::req_err)?;

        if let Some(err) = resp.error {
            return Err(Error::Network {
                details: format!("web3_clientVersion error {}: {}", err.code, err.message),
            });
        }

        resp.result.ok_or_else(|| Error::Network {
            details: s!("web3_clientVersion returned null result"),
        })
    }
}
