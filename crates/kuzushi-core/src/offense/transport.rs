//! The network edge for live plays.
//!
//! A [`PlayTransport`] is the only thing that actually sends bytes at a
//! target. Keeping it behind a trait means every play's planning and
//! classification logic is pure and testable with a mock, and the real
//! HTTP implementation (the outward-facing part) is a thin adapter that can
//! be swapped or stubbed. A transport never sees a raw host the caller chose
//! — the executor hands it [`ScopeTarget`]s that came from an
//! [`super::AuthorizedTarget`].

use super::engagement_scope::ScopeTarget;

/// A request a play wants to send. HTTP-shaped because that is the first
/// supported play surface (web exploit chaining); `scheme`/`port` keep it
/// general enough for other request-response protocols later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayRequest {
    pub scheme: String,
    pub port: Option<u16>,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl PlayRequest {
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            scheme: "https".to_string(),
            port: None,
            method: "GET".to_string(),
            path: path.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }
}

/// The response a transport observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub elapsed_ms: u64,
}

impl PlayResponse {
    /// True if `needle` appears in the body or any header value.
    pub fn contains(&self, needle: &str) -> bool {
        self.body.contains(needle)
            || self
                .headers
                .iter()
                .any(|(_, value)| value.contains(needle))
    }

    /// A compact `status + body excerpt` summary for the audit trail and for
    /// feeding an LLM planner the hop's result without the full body.
    pub fn observe(&self, max_body: usize) -> String {
        let body: String = self.body.chars().take(max_body).collect();
        let truncated = if self.body.chars().count() > max_body {
            "…"
        } else {
            ""
        };
        format!("status={} body={body}{truncated}", self.status)
    }
}

/// Sends a request at an (already authorized) target and returns what came
/// back, or a transport-level error string.
pub trait PlayTransport {
    fn send(&self, target: &ScopeTarget, request: &PlayRequest) -> Result<PlayResponse, String>;
}
