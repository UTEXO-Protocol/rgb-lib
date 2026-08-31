use super::*;

pub struct ProxyClient {
    client: RestClient,
    base_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcRequest<P> {
    method: String,
    jsonrpc: String,
    id: Option<String>,
    params: Option<P>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct JsonRpcResponse<R> {
    jsonrpc: String,
    id: Option<String>,
    pub(crate) result: Option<R>,
    pub(crate) error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct NullRequest;

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ServerInfoResponse {
    pub(crate) protocol_version: String,
    pub(crate) version: String,
    pub(crate) uptime: i64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetConsignmentResponse {
    pub(crate) consignment: String,
    pub(crate) txid: String,
    pub(crate) vout: Option<u32>,
    pub(crate) validated: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PostAckParams {
    recipient_id: String,
    ack: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PostConsignmentParams {
    recipient_id: String,
    txid: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PostConsignmentWithVoutParams {
    recipient_id: String,
    txid: String,
    vout: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct RecipientIDParam {
    recipient_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct AttachmentIdParam {
    attachment_id: String,
}

impl ProxyClient {
    pub(crate) fn new(base_url: &str) -> Result<Self, Error> {
        let mut builder = RestClient::builder()
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT))
            .timeout(Duration::from_secs(READ_WRITE_TIMEOUT))
            .redirect(Policy::none());
        if let Some((host, addrs)) = Self::plaintext_pin(base_url)? {
            builder = builder.resolve_to_addrs(&host, &addrs);
        }
        let client = builder.build()?;
        Ok(Self {
            client,
            base_url: base_url.to_string(),
        })
    }

    /// Resolve a plaintext (`http`) proxy host once, at construction, and pin the
    /// connection to the addresses it yielded. A `ProxyClient` is built per
    /// operation and used immediately, so this closes the window in which a
    /// hostname could be re-pointed between resolution and the request.
    ///
    /// Returns `None` for `https`, where TLS authenticates the host and pinning
    /// would only defeat DNS-based failover.
    fn plaintext_pin(base_url: &str) -> Result<Option<(String, Vec<SocketAddr>)>, Error> {
        let url = Url::parse(base_url).map_err(Self::req_err)?;
        if url.scheme() != "http" {
            return Ok(None);
        }
        let host = url.host_str().ok_or_else(|| Error::Proxy {
            details: s!("plaintext proxy URL has no host to resolve"),
        })?;
        let port = url.port_or_known_default().unwrap_or(80);
        let addrs: Vec<SocketAddr> = (host, port)
            .to_socket_addrs()
            .map_err(Self::req_err)?
            .collect();
        if addrs.is_empty() {
            return Err(Error::Proxy {
                details: format!("plaintext proxy host '{host}' resolved to no addresses"),
            });
        }
        Ok(Some((host.to_string(), addrs)))
    }

    fn req_err(e: impl std::fmt::Display) -> Error {
        Error::Proxy {
            details: e.to_string(),
        }
    }

    pub(crate) fn get_info(&self) -> Result<JsonRpcResponse<ServerInfoResponse>, Error> {
        let body: JsonRpcRequest<NullRequest> = JsonRpcRequest {
            method: s!("server.info"),
            jsonrpc: s!("2.0"),
            id: None,
            params: None,
        };
        self.client
            .post(&self.base_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<ServerInfoResponse>>()
            .map_err(Self::req_err)
    }

    pub(crate) fn get_ack(&self, recipient_id: &str) -> Result<JsonRpcResponse<bool>, Error> {
        let body = JsonRpcRequest {
            method: s!("ack.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(RecipientIDParam {
                recipient_id: recipient_id.to_string(),
            }),
        };
        self.client
            .post(&self.base_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<bool>>()
            .map_err(Self::req_err)
    }

    pub(crate) fn get_consignment(
        &self,
        recipient_id: &str,
    ) -> Result<JsonRpcResponse<GetConsignmentResponse>, Error> {
        let body = JsonRpcRequest {
            method: s!("consignment.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(RecipientIDParam {
                recipient_id: recipient_id.to_string(),
            }),
        };
        self.client
            .post(&self.base_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<GetConsignmentResponse>>()
            .map_err(Self::req_err)
    }

    pub(crate) fn get_media(&self, attachment_id: &str) -> Result<JsonRpcResponse<String>, Error> {
        let body = JsonRpcRequest {
            method: s!("media.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(AttachmentIdParam {
                attachment_id: attachment_id.to_string(),
            }),
        };
        self.client
            .post(&self.base_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<String>>()
            .map_err(Self::req_err)
    }

    pub(crate) fn post_ack(
        &self,
        recipient_id: &str,
        ack: bool,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let body = JsonRpcRequest {
            method: s!("ack.post"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(PostAckParams {
                recipient_id: recipient_id.to_string(),
                ack,
            }),
        };
        self.client
            .post(&self.base_url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<bool>>()
            .map_err(Self::req_err)
    }

    pub(crate) fn post_consignment<P: AsRef<Path>>(
        &self,
        recipient_id: &str,
        consignment_path: P,
        txid: &str,
        vout: Option<u32>,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let params = if let Some(vout) = vout {
            serde_json::to_string(&PostConsignmentWithVoutParams {
                recipient_id: recipient_id.to_string(),
                txid: txid.to_string(),
                vout,
            })
            .expect("serializable")
        } else {
            serde_json::to_string(&PostConsignmentParams {
                recipient_id: recipient_id.to_string(),
                txid: txid.to_string(),
            })
            .expect("serializable")
        };
        let form = multipart::Form::new()
            .text("method", "consignment.post")
            .text("jsonrpc", "2.0")
            .text("id", "null")
            .text("params", params)
            .file("file", consignment_path)?;
        self.client
            .post(&self.base_url)
            .multipart(form)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<bool>>()
            .map_err(Self::req_err)
    }

    pub(crate) fn post_media<P: AsRef<Path>>(
        &self,
        attachment_id: &str,
        media_path: P,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let params = serde_json::to_string(&AttachmentIdParam {
            attachment_id: attachment_id.to_string(),
        })
        .expect("serializable");
        let form = multipart::Form::new()
            .text("method", "media.post")
            .text("jsonrpc", "2.0")
            .text("id", "null")
            .text("params", params)
            .file("file", media_path)?;
        self.client
            .post(&self.base_url)
            .multipart(form)
            .send()
            .map_err(Self::req_err)?
            .json::<JsonRpcResponse<bool>>()
            .map_err(Self::req_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_host_is_not_pinned() {
        assert!(
            ProxyClient::plaintext_pin("https://proxy.example.com/json-rpc")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn plaintext_host_is_pinned_to_its_resolved_addresses() {
        let (host, addrs) = ProxyClient::plaintext_pin("http://127.0.0.1:3000/json-rpc")
            .unwrap()
            .expect("a plaintext endpoint must be pinned");
        assert_eq!(host, "127.0.0.1");
        assert!(
            addrs
                .iter()
                .any(|a| a.ip().is_loopback() && a.port() == 3000)
        );
    }

    #[test]
    fn plaintext_without_explicit_port_pins_the_http_default() {
        let (_, addrs) = ProxyClient::plaintext_pin("http://127.0.0.1/json-rpc")
            .unwrap()
            .expect("a plaintext endpoint must be pinned");
        assert!(addrs.iter().all(|a| a.port() == 80));
    }

    #[test]
    fn plaintext_host_that_does_not_resolve_is_refused_rather_than_left_unpinned() {
        let result = ProxyClient::plaintext_pin("http://rgb-lib-nonexistent-host.invalid/json-rpc");
        assert_matches!(result, Err(Error::Proxy { .. }));
    }

    #[test]
    fn get_info_error() {
        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        let result = client.get_info().unwrap_err();
        assert_matches!(result, Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_info().unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_info().unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();
    }

    #[test]
    fn get_ack_error() {
        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        let result = client.get_ack("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_ack("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_ack("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();
    }

    #[test]
    fn get_consignment_error() {
        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        let result = client.get_consignment("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_consignment("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_consignment("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();
    }

    #[test]
    fn get_media_error() {
        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        let result = client.get_media("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_media("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.get_media("123").unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();
    }

    #[test]
    fn post_ack_error() {
        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        let result = client.post_ack("123", true).unwrap_err();
        assert_matches!(result, Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.post_ack("123", true).unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.post_ack("123", true).unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();
    }

    #[test]
    fn post_consignment_error() {
        let tmp_path = tempfile::NamedTempFile::new().unwrap();

        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        let result = client
            .post_consignment("123", tmp_path.path(), "123", None)
            .unwrap_err();
        assert_matches!(result, Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client
            .post_consignment("123", tmp_path.path(), "123", None)
            .unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client
            .post_consignment("123", tmp_path.path(), "123", None)
            .unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();
    }

    #[test]
    fn post_media_error() {
        let tmp_path = tempfile::NamedTempFile::new().unwrap();

        // network error
        let client = ProxyClient::new("http://127.0.0.1:1").unwrap();
        let result = client.post_media("123", tmp_path.path()).unwrap_err();
        assert_matches!(result, Error::Proxy { .. });

        // malformed JSON response
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body("not valid json")
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.post_media("123", tmp_path.path()).unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();

        // unexpected JSON
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/")
            .with_status(409)
            .with_header("content-type", JSON)
            .with_body(r#"{"unexpected": "json"}"#)
            .create();
        let client = ProxyClient::new(&server.url()).unwrap();
        let result = client.post_media("123", tmp_path.path()).unwrap_err();
        assert_matches!(result, Error::Proxy { .. });
        mock.assert();
    }
}
