use super::*;

/// keccak256("FundsIn(address,uint256,uint64)")
const FUNDS_IN_TOPIC: &str = "0xf1a18caea297591892fc07ea412a5e617d8e51e1155912d8871793e1d4e70f87";

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
    pub address: String,
    /// Indexed topic hashes (topic[0] = event signature hash).
    pub topics: Vec<String>,
    /// ABI-encoded non-indexed parameters.
    pub data: String,
    /// Block number (hex), absent while the log is pending.
    pub block_number: Option<String>,
    /// Transaction hash.
    #[allow(dead_code)]
    pub transaction_hash: Option<String>,
    /// Log index within the block (hex).
    #[allow(dead_code)]
    pub log_index: Option<String>,
    /// Set on a log whose block was reorganized out of the chain.
    #[serde(default)]
    pub removed: bool,
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

/// Parse a JSON-RPC hex quantity.
fn quantity(hex: &str) -> Result<u64, Error> {
    u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16).map_err(|e| Error::Network {
        details: format!("invalid Ethereum RPC quantity {hex:?}: {e}"),
    })
}

/// Whether two hex addresses name the same account, whatever their case or `0x` prefix.
fn same_address(a: &str, b: &str) -> bool {
    let bare = |s: &str| s.strip_prefix("0x").unwrap_or(s).to_ascii_lowercase();
    bare(a) == bare(b)
}

/// Read an ABI uint256 as u64, refusing values that don't fit.
/// Truncating would silently disagree with the amount the mint commits to.
fn word_as_u64(word: [u8; 32]) -> Result<u64, Error> {
    if word[..24].iter().any(|&b| b != 0) {
        return Err(Error::Network {
            details: s!("FundsIn amount exceeds u64 range"),
        });
    }
    Ok(u64::from_be_bytes(word[24..32].try_into().unwrap()))
}

impl EthLog {
    /// Number of the block the log was mined in, `None` while it is pending.
    pub fn block_number(&self) -> Result<Option<u64>, Error> {
        self.block_number.as_deref().map(quantity).transpose()
    }

    /// Try to parse this log as a FundsIn event.
    /// Returns `None` if the log topic doesn't match.
    pub fn as_funds_in(&self) -> Result<Option<FundsInEvent>, Error> {
        let Some(topic0) = self.topics.first() else {
            return Ok(None);
        };

        if !topic0.eq_ignore_ascii_case(FUNDS_IN_TOPIC) {
            return Ok(None);
        }
        if self.topics.len() != 2 || self.data.strip_prefix("0x").unwrap_or(&self.data).len() != 128
        {
            return Err(Error::Network {
                details: s!("unexpected FundsIn ABI layout"),
            });
        }
        Ok(Some(FundsInEvent {
            operation_id: abi_word(&self.data, 0)?,
            amount: word_as_u64(abi_word(&self.data, 1)?)?,
        }))
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
    /// Event signature filter.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    topics: Vec<String>,
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

    /// Send one JSON-RPC request and return its result, `None` if the node returned null.
    fn call<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<Option<R>, Error> {
        let body = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: 1,
        };
        let resp: RpcResponse<R> = self
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
                details: format!("{method} error {}: {}", err.code, err.message),
            });
        }
        Ok(resp.result)
    }

    /// Fetch the FundsIn logs `contract` emitted between `from_block` and `to_block`.
    ///
    /// Block parameters accept hex strings (`"0x0"`) or tags (`"earliest"`,
    /// `"latest"`).
    ///
    /// Only the contract's own logs are returned, and none from a block the chain reorganized
    /// away. A log of any other address fails the call: any contract can emit a FundsIn naming
    /// any OpId and amount, so an RPC that ignores the address filter cannot be trusted with
    /// deciding whether a mint is backed.
    pub(crate) fn get_logs(
        &self,
        contract: &str,
        from_block: &str,
        to_block: &str,
    ) -> Result<Vec<EthLog>, Error> {
        let filter = [LogFilter {
            address: contract.to_string(),
            from_block: from_block.to_string(),
            to_block: to_block.to_string(),
            topics: vec![FUNDS_IN_TOPIC.to_string()],
        }];
        let logs: Vec<EthLog> =
            self.call("eth_getLogs", filter)?
                .ok_or_else(|| Error::Network {
                    details: s!("eth_getLogs returned null result"),
                })?;

        if let Some(foreign) = logs.iter().find(|l| !same_address(&l.address, contract)) {
            return Err(Error::Network {
                details: format!(
                    "eth_getLogs for {contract} returned a log of {}",
                    foreign.address
                ),
            });
        }
        Ok(logs.into_iter().filter(|l| !l.removed).collect())
    }

    pub(crate) fn client_version(&self) -> Result<String, Error> {
        self.call("web3_clientVersion", NullRequest)?
            .ok_or_else(|| Error::Network {
                details: s!("web3_clientVersion returned null result"),
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn word(hex_tail: &str) -> String {
        format!("{:0>64}", hex_tail)
    }

    fn log(topics: &[&str], data_words: &[&str]) -> EthLog {
        EthLog {
            address: s!("0x0000000000000000000000000000000000000001"),
            topics: topics.iter().map(|t| t.to_string()).collect(),
            data: format!(
                "0x{}",
                data_words.iter().map(|w| word(w)).collect::<String>()
            ),
            block_number: None,
            transaction_hash: None,
            log_index: None,
            removed: false,
        }
    }

    const BRIDGE: &str = "0x00000000000000000000000000000000000000b1";

    /// Serve `result` as the answer to any JSON-RPC call.
    fn rpc_server(result: serde_json::Value) -> (mockito::ServerGuard, mockito::Mock) {
        let mut server = mockito::Server::new();
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result});
        let mock = server
            .mock("POST", "/")
            .with_status(200)
            .with_body(body.to_string())
            .create();
        (server, mock)
    }

    fn rpc_log(address: &str, block: &str, removed: bool) -> serde_json::Value {
        serde_json::json!({
            "address": address,
            "topics": [FUNDS_IN_TOPIC, format!("0x{}", word("dead"))],
            "data": format!("0x{}{}", word("ab"), word("64")),
            "blockNumber": block,
            "transactionHash": format!("0x{}", word("1")),
            "logIndex": "0x0",
            "removed": removed,
        })
    }

    const OPID: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

    #[test]
    fn decodes_bridge_event() {
        let log = log(&[FUNDS_IN_TOPIC, &word("dead")], &["ab", "64"]);
        let event = log.as_funds_in().unwrap().unwrap();
        assert_eq!(event.amount, 100);
        assert_eq!(hex::encode(event.operation_id), OPID);
    }

    #[test]
    fn rejects_old_bridge_event() {
        let old_topic = "0xcf4f3270b7400c5ca42954767c516b7c595dcd8038cdd121945a474c616208f8";
        let log = log(&[old_topic, &word("dead"), &format!("0x{OPID}")], &["64"]);
        assert!(log.as_funds_in().unwrap().is_none());
    }

    #[test]
    fn rejects_malformed_bridge_event() {
        let short = log(&[FUNDS_IN_TOPIC, &word("dead")], &["ab"]);
        assert!(short.as_funds_in().is_err());

        let extra_topic = log(&[FUNDS_IN_TOPIC, &word("dead"), &word("ab")], &["ab", "64"]);
        assert!(extra_topic.as_funds_in().is_err());
    }

    #[test]
    fn decodes_maximum_amount_and_rejects_overflow() {
        let max = log(
            &[FUNDS_IN_TOPIC, &word("dead")],
            &["ab", "ffffffffffffffff"],
        );
        assert_eq!(max.as_funds_in().unwrap().unwrap().amount, u64::MAX);

        let overflow = log(
            &[FUNDS_IN_TOPIC, &word("dead")],
            &["ab", "10000000000000000"],
        );
        assert!(overflow.as_funds_in().is_err());
    }

    #[test]
    fn queries_bridge_event_signature() {
        let mut server = mockito::Server::new();
        let address = "0x0000000000000000000000000000000000000001";
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "eth_getLogs",
            "params": [{
                "address": address,
                "fromBlock": "0x0",
                "toBlock": "latest",
                "topics": [FUNDS_IN_TOPIC],
            }],
            "id": 1,
        });
        let mock = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::Json(request))
            .with_status(200)
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":[]}"#)
            .create();

        let logs = EthClient::new(&server.url())
            .unwrap()
            .get_logs(address, "0x0", "latest")
            .unwrap();
        assert!(logs.is_empty());
        mock.assert();
    }

    /// Any contract can emit a FundsIn naming any OpId and amount, so a log the bridge did not
    /// emit must never reach the validator - even from an RPC that ignored the address filter.
    #[test]
    fn rejects_a_log_of_another_contract() {
        let stranger = "0x00000000000000000000000000000000000000c2";
        let (server, mock) = rpc_server(serde_json::json!([
            rpc_log(BRIDGE, "0x10", false),
            rpc_log(stranger, "0x11", false),
        ]));
        let result = EthClient::new(&server.url())
            .unwrap()
            .get_logs(BRIDGE, "0x0", "latest");
        assert!(
            matches!(&result, Err(Error::Network { details }) if details.contains(stranger)),
            "{result:?}"
        );
        mock.assert();
    }

    #[test]
    fn matches_the_contract_address_in_any_case() {
        let checksummed = "0x00000000000000000000000000000000000000B1";
        let (server, _mock) = rpc_server(serde_json::json!([rpc_log(BRIDGE, "0x10", false)]));
        let logs = EthClient::new(&server.url())
            .unwrap()
            .get_logs(checksummed, "0x0", "latest")
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].block_number().unwrap(), Some(0x10));
    }

    /// A removed log belongs to a block the chain reorganized away: its lock never happened.
    #[test]
    fn drops_removed_logs() {
        let (server, _mock) = rpc_server(serde_json::json!([
            rpc_log(BRIDGE, "0x10", true),
            rpc_log(BRIDGE, "0x11", false),
        ]));
        let logs = EthClient::new(&server.url())
            .unwrap()
            .get_logs(BRIDGE, "0x0", "latest")
            .unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].block_number().unwrap(), Some(0x11));
    }

    #[test]
    fn ignores_other_events() {
        let log = log(&[&word("1234")], &["64"]);
        assert!(log.as_funds_in().unwrap().is_none());
    }
}
