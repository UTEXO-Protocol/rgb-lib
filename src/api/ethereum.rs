use super::*;

/// keccak256("FundsIn(address,uint256,uint64)"); sender and rgbOpId are indexed.
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
        if self.topics.len() != 3 || self.data.strip_prefix("0x").unwrap_or(&self.data).len() != 64
        {
            return Err(Error::Network {
                details: s!("unexpected FundsIn ABI layout"),
            });
        }
        Ok(Some(FundsInEvent {
            // topic2 is the OpId bytes read as a big-endian uint256.
            operation_id: abi_word(&self.topics[2], 0)?,
            amount: word_as_u64(abi_word(&self.data, 0)?)?,
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
    /// Start block (hex).
    from_block: String,
    /// End block (hex).
    to_block: String,
    /// Event signature filter.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    topics: Vec<String>,
}

/// Widest block range one `eth_getLogs` asks for: public Arbitrum RPCs refuse more than 10M.
const LOG_SCAN_CHUNK: u64 = 10_000_000;
/// Narrowest range retried after an RPC refuses a wider one.
const MIN_LOG_SCAN_CHUNK: u64 = 1_000;
/// Clock slack before the asset genesis: no FundsIn of its mints can be older.
const GENESIS_SLACK_SECS: u64 = 86_400;

#[derive(Debug, Deserialize)]
struct BlockHeader {
    timestamp: String,
}

fn parse_hex_u64(method: &str, value: &str) -> Result<u64, Error> {
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16).map_err(|e| Error::Network {
        details: format!("{method} returned invalid quantity {value:?}: {e}"),
    })
}

fn rpc_refused(method: &str, err: RpcError) -> Error {
    Error::Network {
        details: format!("{method} error {}: {}", err.code, err.message),
    }
}

/// First block in `0..=head` with a timestamp at or after `ts`, or `head + 1` if none.
/// Block timestamps never decrease, so a binary search finds it.
fn first_block_at(
    ts: u64,
    head: u64,
    mut block_ts: impl FnMut(u64) -> Result<u64, Error>,
) -> Result<u64, Error> {
    let (mut lo, mut hi) = (0, head.saturating_add(1));
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if block_ts(mid)? < ts {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Fetches `from..=to` in ranges of at most `chunk` blocks. RPCs cap the range
/// differently, so a refused range is halved and retried; transport errors are not.
fn scan_in_chunks<T>(
    from: u64,
    to: u64,
    mut chunk: u64,
    mut fetch: impl FnMut(u64, u64) -> Result<Result<Vec<T>, RpcError>, Error>,
) -> Result<Vec<T>, Error> {
    let mut found = vec![];
    let mut start = from;
    while start <= to {
        let end = to.min(start.saturating_add(chunk - 1));
        let width = end - start + 1;
        match fetch(start, end)? {
            Ok(mut items) => found.append(&mut items),
            Err(_) if width > MIN_LOG_SCAN_CHUNK => {
                chunk = (width / 2).max(MIN_LOG_SCAN_CHUNK);
                continue;
            }
            Err(err) => return Err(rpc_refused("eth_getLogs", err)),
        }
        match end.checked_add(1) {
            Some(next) => start = next,
            None => break,
        }
    }
    Ok(found)
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

    /// Sends one JSON-RPC call. The outer error is transport, the inner one is
    /// the node refusing the call.
    fn call<P: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<Result<R, RpcError>, Error> {
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
            return Ok(Err(err));
        }
        resp.result.map(Ok).ok_or_else(|| Error::Network {
            details: format!("{method} returned null result"),
        })
    }

    /// FundsIn logs emitted by `contract` in `from_block..=to_block`.
    fn get_logs(
        &self,
        contract: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Result<Vec<EthLog>, RpcError>, Error> {
        self.call(
            "eth_getLogs",
            [LogFilter {
                address: contract.to_string(),
                from_block: format!("{from_block:#x}"),
                to_block: format!("{to_block:#x}"),
                topics: vec![FUNDS_IN_TOPIC.to_string()],
            }],
        )
    }

    /// FundsIn logs of `contract` from a day before `genesis_ts` (asset genesis,
    /// unix seconds) to the chain head, so the range stays within RPC limits.
    pub(crate) fn funds_in_logs_since(
        &self,
        contract: &str,
        genesis_ts: i64,
    ) -> Result<Vec<EthLog>, Error> {
        let head = self.block_number()?;
        let since = u64::try_from(genesis_ts)
            .unwrap_or(0)
            .saturating_sub(GENESIS_SLACK_SECS);
        let from = first_block_at(since, head, |n| self.block_timestamp(n))?;
        scan_in_chunks(from, head, LOG_SCAN_CHUNK, |a, b| {
            self.get_logs(contract, a, b)
        })
    }

    fn block_number(&self) -> Result<u64, Error> {
        let head: String = self
            .call("eth_blockNumber", NullRequest)?
            .map_err(|e| rpc_refused("eth_blockNumber", e))?;
        parse_hex_u64("eth_blockNumber", &head)
    }

    fn block_timestamp(&self, number: u64) -> Result<u64, Error> {
        let block: BlockHeader = self
            .call("eth_getBlockByNumber", (format!("{number:#x}"), false))?
            .map_err(|e| rpc_refused("eth_getBlockByNumber", e))?;
        parse_hex_u64("eth_getBlockByNumber", &block.timestamp)
    }

    pub(crate) fn client_version(&self) -> Result<String, Error> {
        self.call("web3_clientVersion", NullRequest)?
            .map_err(|e| rpc_refused("web3_clientVersion", e))
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
        let log = log(
            &[FUNDS_IN_TOPIC, &word("dead"), &format!("0x{OPID}")],
            &["64"],
        );
        let event = log.as_funds_in().unwrap().unwrap();
        assert_eq!(event.amount, 100);
        assert_eq!(hex::encode(event.operation_id), OPID);
    }

    #[test]
    fn reads_the_operation_id_big_endian() {
        let opid = "ab00000000000000000000000000000000000000000000000000000000000002";
        let log = log(
            &[FUNDS_IN_TOPIC, &word("dead"), &format!("0x{opid}")],
            &["64"],
        );
        let event = log.as_funds_in().unwrap().unwrap();
        assert_eq!(event.operation_id[0], 0xab);
        assert_eq!(event.operation_id[31], 0x02);
    }

    #[test]
    fn rejects_old_bridge_event() {
        let old_topic = "0xcf4f3270b7400c5ca42954767c516b7c595dcd8038cdd121945a474c616208f8";
        let log = log(&[old_topic, &word("dead"), &format!("0x{OPID}")], &["64"]);
        assert!(log.as_funds_in().unwrap().is_none());
    }

    #[test]
    fn rejects_malformed_bridge_event() {
        let no_amount = log(&[FUNDS_IN_TOPIC, &word("dead"), &word("ab")], &[]);
        assert!(no_amount.as_funds_in().is_err());

        // The old layout: the OpId in data, not indexed.
        let old_layout = log(&[FUNDS_IN_TOPIC, &word("dead")], &["ab", "64"]);
        assert!(old_layout.as_funds_in().is_err());

        let extra_topic = log(
            &[FUNDS_IN_TOPIC, &word("dead"), &word("ab"), &word("cd")],
            &["64"],
        );
        assert!(extra_topic.as_funds_in().is_err());
    }

    #[test]
    fn decodes_maximum_amount_and_rejects_overflow() {
        let max = log(
            &[FUNDS_IN_TOPIC, &word("dead"), &word("ab")],
            &["ffffffffffffffff"],
        );
        assert_eq!(max.as_funds_in().unwrap().unwrap().amount, u64::MAX);

        let overflow = log(
            &[FUNDS_IN_TOPIC, &word("dead"), &word("ab")],
            &["10000000000000000"],
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
                "toBlock": "0xf",
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
            .get_logs(address, 0, 15)
            .unwrap()
            .unwrap();
        assert!(logs.is_empty());
        mock.assert();
    }

    fn refusal() -> RpcError {
        RpcError {
            code: -32602,
            message: s!("query spans too many blocks, only 10000000 are allowed"),
        }
    }

    #[test]
    fn finds_the_first_block_at_a_timestamp() {
        let block_ts = [100, 110, 110, 120, 130];
        let at = |ts| first_block_at(ts, 4, |n| Ok(block_ts[n as usize])).unwrap();
        assert_eq!(at(0), 0);
        assert_eq!(at(100), 0);
        assert_eq!(at(105), 1);
        assert_eq!(at(110), 1, "the first of equal timestamps");
        assert_eq!(at(130), 4);
        assert_eq!(at(131), 5, "nothing that late: past the head");
    }

    #[test]
    fn scans_the_whole_range_in_chunks() {
        let mut ranges = vec![];
        let found = scan_in_chunks(5, 2_504, 1_000, |a, b| {
            ranges.push((a, b));
            Ok(Ok(vec![a]))
        })
        .unwrap();
        assert_eq!(ranges, [(5, 1_004), (1_005, 2_004), (2_005, 2_504)]);
        assert_eq!(found, [5, 1_005, 2_005]);
    }

    #[test]
    fn scans_nothing_when_the_start_is_past_the_head() {
        let found = scan_in_chunks(6, 5, 1_000, |_, _| -> Result<Result<Vec<u64>, _>, _> {
            panic!("no range to fetch")
        })
        .unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn halves_a_range_the_rpc_refuses() {
        let mut ranges = vec![];
        scan_in_chunks(0, 9_999, 8_000, |a, b| {
            ranges.push((a, b));
            Ok(if b - a + 1 > 2_000 {
                Err(refusal())
            } else {
                Ok(vec![()])
            })
        })
        .unwrap();
        assert_eq!(
            ranges,
            [
                (0, 7_999),
                (0, 3_999),
                (0, 1_999),
                (2_000, 3_999),
                (4_000, 5_999),
                (6_000, 7_999),
                (8_000, 9_999),
            ]
        );
    }

    #[test]
    fn halves_the_range_actually_sent() {
        let mut ranges = vec![];
        scan_in_chunks(0, 2_999, LOG_SCAN_CHUNK, |a, b| {
            ranges.push((a, b));
            Ok(if b - a + 1 > 2_000 {
                Err(refusal())
            } else {
                Ok(vec![()])
            })
        })
        .unwrap();
        assert_eq!(ranges, [(0, 2_999), (0, 1_499), (1_500, 2_999)]);
    }

    #[test]
    fn gives_up_when_even_the_narrowest_range_is_refused() {
        let mut calls = 0;
        let err = scan_in_chunks(0, 9_999, 4_000, |_, _| -> Result<Result<Vec<()>, _>, _> {
            calls += 1;
            Ok(Err(refusal()))
        })
        .unwrap_err();
        assert!(err.to_string().contains("only 10000000 are allowed"));
        assert_eq!(calls, 3, "4000, 2000, then the 1000 floor");
    }

    #[test]
    fn does_not_retry_a_transport_error() {
        let mut calls = 0;
        let err = scan_in_chunks(0, 9_999, 4_000, |_, _| -> Result<Result<Vec<()>, _>, _> {
            calls += 1;
            Err(Error::Network {
                details: s!("connection refused"),
            })
        });
        assert!(err.is_err());
        assert_eq!(calls, 1);
    }

    // Block n is mined at n * 10_000 s; the genesis is one day after block 5, so
    // the scan starts at block 5 and ends at the head, 0x14.
    #[test]
    fn scans_from_a_day_before_the_genesis_to_the_head() {
        let mut server = mockito::Server::new();
        let address = "0x0000000000000000000000000000000000000001";
        server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(
                serde_json::json!({"method": "eth_blockNumber"}),
            ))
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":"0x14"}"#)
            .create();
        server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(
                serde_json::json!({"method": "eth_getBlockByNumber"}),
            ))
            .with_body_from_request(|request| {
                let body: serde_json::Value =
                    serde_json::from_slice(request.body().unwrap()).unwrap();
                let number = parse_hex_u64("test", body["params"][0].as_str().unwrap()).unwrap();
                format!(
                    r#"{{"jsonrpc":"2.0","id":1,"result":{{"timestamp":"{:#x}"}}}}"#,
                    number * 10_000
                )
                .into()
            })
            .create();
        let logs = server
            .mock("POST", "/")
            .match_body(mockito::Matcher::PartialJson(serde_json::json!({
                "method": "eth_getLogs",
                "params": [{"fromBlock": "0x5", "toBlock": "0x14"}],
            })))
            .with_body(r#"{"jsonrpc":"2.0","id":1,"result":[]}"#)
            .create();

        let found = EthClient::new(&server.url())
            .unwrap()
            .funds_in_logs_since(address, 50_000 + 86_400)
            .unwrap();
        assert!(found.is_empty());
        logs.assert();
    }

    #[test]
    fn ignores_other_events() {
        let log = log(&[&word("1234")], &["64"]);
        assert!(log.as_funds_in().unwrap().is_none());
    }
}
