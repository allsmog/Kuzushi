//! JSON-RPC 2.0 message types.
//!
//! MCP's stdio transport uses newline-delimited JSON: one complete JSON
//! object per line, no Content-Length framing. These types deserialize from
//! either a request, a notification (no `id`), or a response.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC_VERSION: &str = "2.0";

// JSON-RPC 2.0 standard error codes plus a few MCP-specific ones we use.
pub const ERROR_PARSE: i32 = -32700;
pub const ERROR_INVALID_REQUEST: i32 = -32600;
pub const ERROR_METHOD_NOT_FOUND: i32 = -32601;
pub const ERROR_INVALID_PARAMS: i32 = -32602;
pub const ERROR_INTERNAL: i32 = -32603;

/// JSON-RPC request frame. `id` is absent for notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC response frame. Exactly one of `result` or `error` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    pub fn err_with_data(id: Value, code: i32, message: impl Into<String>, data: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: Some(data),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_round_trips() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Some(json!(1)));
        assert!(req.params.is_none());
    }

    #[test]
    fn notification_has_no_id() {
        let raw = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert!(req.id.is_none());
    }

    #[test]
    fn ok_response_has_no_error_field() {
        let resp = JsonRpcResponse::ok(json!(1), json!({"tools": []}));
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("error"));
        assert!(serialized.contains("result"));
    }

    #[test]
    fn err_response_has_no_result_field() {
        let resp = JsonRpcResponse::err(json!(1), ERROR_METHOD_NOT_FOUND, "no such method");
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(serialized.contains("error"));
        assert!(!serialized.contains("\"result\""));
    }

    #[test]
    fn err_with_data_includes_payload() {
        let resp = JsonRpcResponse::err_with_data(
            json!(2),
            ERROR_INVALID_PARAMS,
            "bad",
            json!({"field": "name"}),
        );
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(serialized.contains("\"field\":\"name\""));
    }
}
