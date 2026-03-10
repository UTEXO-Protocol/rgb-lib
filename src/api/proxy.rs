use super::*;

const JSON: &str = "application/json";

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
    pub(crate) uptime: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct GetConsignmentResponse {
    pub(crate) consignment: String,
    pub(crate) txid: String,
    pub(crate) vout: Option<u32>,
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

pub(crate) trait Proxy {
    fn get_info(self, url: &str) -> Result<JsonRpcResponse<ServerInfoResponse>, Error>;

    fn get_ack(self, url: &str, recipient_id: String) -> Result<JsonRpcResponse<bool>, Error>;

    fn get_consignment(
        self,
        url: &str,
        recipient_id: String,
    ) -> Result<JsonRpcResponse<GetConsignmentResponse>, Error>;

    fn get_media(self, url: &str, attachment_id: String) -> Result<JsonRpcResponse<String>, Error>;

    fn post_ack(
        self,
        url: &str,
        recipient_id: String,
        ack: bool,
    ) -> Result<JsonRpcResponse<bool>, Error>;

    fn post_consignment<P: AsRef<Path>>(
        self,
        url: &str,
        recipient_id: String,
        consignment_path: P,
        txid: String,
        vout: Option<u32>,
    ) -> Result<JsonRpcResponse<bool>, Error>;

    fn post_media<P: AsRef<Path>>(
        self,
        url: &str,
        attachment_id: String,
        media_path: P,
    ) -> Result<JsonRpcResponse<bool>, Error>;
}

#[cfg(not(target_arch = "wasm32"))]
impl Proxy for RestClient {
    fn get_info(self, url: &str) -> Result<JsonRpcResponse<ServerInfoResponse>, Error> {
        let body: JsonRpcRequest<NullRequest> = JsonRpcRequest {
            method: s!("server.info"),
            jsonrpc: s!("2.0"),
            id: None,
            params: None,
        };
        Ok(self
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<ServerInfoResponse>>()
            .map_err(InternalError::from)?)
    }

    fn get_ack(self, url: &str, recipient_id: String) -> Result<JsonRpcResponse<bool>, Error> {
        let body = JsonRpcRequest {
            method: s!("ack.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(RecipientIDParam { recipient_id }),
        };
        Ok(self
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<bool>>()
            .map_err(InternalError::from)?)
    }

    fn get_consignment(
        self,
        url: &str,
        recipient_id: String,
    ) -> Result<JsonRpcResponse<GetConsignmentResponse>, Error> {
        let body = JsonRpcRequest {
            method: s!("consignment.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(RecipientIDParam { recipient_id }),
        };
        Ok(self
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<GetConsignmentResponse>>()
            .map_err(InternalError::from)?)
    }

    fn get_media(self, url: &str, attachment_id: String) -> Result<JsonRpcResponse<String>, Error> {
        let body = JsonRpcRequest {
            method: s!("media.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(AttachmentIdParam { attachment_id }),
        };
        Ok(self
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<String>>()
            .map_err(InternalError::from)?)
    }

    fn post_ack(
        self,
        url: &str,
        recipient_id: String,
        ack: bool,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let body = JsonRpcRequest {
            method: s!("ack.post"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(PostAckParams { recipient_id, ack }),
        };
        Ok(self
            .post(url)
            .header(CONTENT_TYPE, JSON)
            .json(&body)
            .send()
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<bool>>()
            .map_err(InternalError::from)?)
    }

    fn post_consignment<P: AsRef<Path>>(
        self,
        url: &str,
        recipient_id: String,
        consignment_path: P,
        txid: String,
        vout: Option<u32>,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let params = if let Some(vout) = vout {
            serde_json::to_string(&PostConsignmentWithVoutParams {
                recipient_id,
                txid,
                vout,
            })
            .map_err(InternalError::from)?
        } else {
            serde_json::to_string(&PostConsignmentParams { recipient_id, txid })
                .map_err(InternalError::from)?
        };
        let form = multipart::Form::new()
            .text("method", "consignment.post")
            .text("jsonrpc", "2.0")
            .text("id", "1")
            .text("params", params)
            .file("file", consignment_path)?;
        Ok(self
            .post(url)
            .multipart(form)
            .send()
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<bool>>()
            .map_err(InternalError::from)?)
    }

    fn post_media<P: AsRef<Path>>(
        self,
        url: &str,
        attachment_id: String,
        media_path: P,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let form = multipart::Form::new()
            .text("method", "media.post")
            .text("jsonrpc", "2.0")
            .text("id", "1")
            .text(
                "params",
                serde_json::to_string(&AttachmentIdParam { attachment_id })
                    .map_err(InternalError::from)?,
            )
            .file("file", media_path)?;
        Ok(self
            .post(url)
            .multipart(form)
            .send()
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<bool>>()
            .map_err(InternalError::from)?)
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) struct WasmProxyClient {
    client: reqwest::Client,
}

#[cfg(target_arch = "wasm32")]
impl WasmProxyClient {
    pub(crate) fn new() -> Result<Self, Error> {
        let client = reqwest::Client::new();
        Ok(Self { client })
    }

    pub(crate) async fn get_info(
        &self,
        url: &str,
    ) -> Result<JsonRpcResponse<ServerInfoResponse>, Error> {
        let body: JsonRpcRequest<NullRequest> = JsonRpcRequest {
            method: s!("server.info"),
            jsonrpc: s!("2.0"),
            id: None,
            params: None,
        };
        Ok(self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<ServerInfoResponse>>()
            .await
            .map_err(InternalError::from)?)
    }

    pub(crate) async fn get_ack(
        &self,
        url: &str,
        recipient_id: String,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let body = JsonRpcRequest {
            method: s!("ack.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(RecipientIDParam { recipient_id }),
        };
        Ok(self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<bool>>()
            .await
            .map_err(InternalError::from)?)
    }

    pub(crate) async fn get_consignment(
        &self,
        url: &str,
        recipient_id: String,
    ) -> Result<JsonRpcResponse<GetConsignmentResponse>, Error> {
        let body = JsonRpcRequest {
            method: s!("consignment.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(RecipientIDParam { recipient_id }),
        };
        Ok(self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<GetConsignmentResponse>>()
            .await
            .map_err(InternalError::from)?)
    }

    pub(crate) async fn post_ack(
        &self,
        url: &str,
        recipient_id: String,
        ack: bool,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let body = JsonRpcRequest {
            method: s!("ack.post"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(PostAckParams { recipient_id, ack }),
        };
        Ok(self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<bool>>()
            .await
            .map_err(InternalError::from)?)
    }

    pub(crate) async fn post_consignment(
        &self,
        url: &str,
        recipient_id: String,
        consignment_bytes: &[u8],
        txid: String,
        vout: Option<u32>,
    ) -> Result<JsonRpcResponse<bool>, Error> {
        let params = if let Some(vout) = vout {
            serde_json::to_string(&PostConsignmentWithVoutParams {
                recipient_id,
                txid,
                vout,
            })
            .map_err(InternalError::from)?
        } else {
            serde_json::to_string(&PostConsignmentParams { recipient_id, txid })
                .map_err(InternalError::from)?
        };

        let form_data = web_sys::FormData::new().map_err(|e| Error::Proxy {
            details: format!("FormData::new failed: {e:?}"),
        })?;
        form_data
            .append_with_str("method", "consignment.post")
            .map_err(|e| Error::Proxy {
                details: format!("FormData append failed: {e:?}"),
            })?;
        form_data
            .append_with_str("jsonrpc", "2.0")
            .map_err(|e| Error::Proxy {
                details: format!("FormData append failed: {e:?}"),
            })?;
        form_data
            .append_with_str("id", "1")
            .map_err(|e| Error::Proxy {
                details: format!("FormData append failed: {e:?}"),
            })?;
        form_data
            .append_with_str("params", &params)
            .map_err(|e| Error::Proxy {
                details: format!("FormData append failed: {e:?}"),
            })?;

        // Create Blob from consignment bytes
        let uint8arr = js_sys::Uint8Array::from(consignment_bytes);
        let array = js_sys::Array::new();
        array.push(&uint8arr);
        let blob = web_sys::Blob::new_with_u8_array_sequence(&array).map_err(|e| Error::Proxy {
            details: format!("Blob::new failed: {e:?}"),
        })?;
        form_data
            .append_with_blob_and_filename("file", &blob, "consignment")
            .map_err(|e| Error::Proxy {
                details: format!("FormData append blob failed: {e:?}"),
            })?;

        // Send via gloo-net (supports FormData body)
        let resp = gloo_net::http::Request::post(url)
            .body(form_data)
            .map_err(|e| Error::Proxy {
                details: format!("gloo-net request build failed: {e}"),
            })?
            .send()
            .await
            .map_err(|e| Error::Proxy {
                details: format!("gloo-net send failed: {e}"),
            })?;
        resp.json::<JsonRpcResponse<bool>>()
            .await
            .map_err(|e| Error::Proxy {
                details: format!("gloo-net response parse failed: {e}"),
            })
    }

    pub(crate) async fn get_media(
        &self,
        url: &str,
        attachment_id: String,
    ) -> Result<JsonRpcResponse<String>, Error> {
        let body = JsonRpcRequest {
            method: s!("media.get"),
            jsonrpc: s!("2.0"),
            id: None,
            params: Some(AttachmentIdParam { attachment_id }),
        };
        Ok(self
            .client
            .post(url)
            .header("Content-Type", JSON)
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Proxy {
                details: e.to_string(),
            })?
            .json::<JsonRpcResponse<String>>()
            .await
            .map_err(InternalError::from)?)
    }

    pub(crate) async fn get_reject_list(&self, url: &str) -> Result<String, Error> {
        Ok(self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::RejectListService {
                details: e.to_string(),
            })?
            .text()
            .await
            .map_err(InternalError::from)?)
    }
}
