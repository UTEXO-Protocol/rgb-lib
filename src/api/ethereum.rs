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
                topics: vec![FUNDS_IN_TOPIC.to_string()],
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
        }
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

    #[test]
    fn ignores_other_events() {
        let log = log(&[&word("1234")], &["64"]);
        assert!(log.as_funds_in().unwrap().is_none());
    }
}
