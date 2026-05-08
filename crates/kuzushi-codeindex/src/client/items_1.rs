use super::prelude::*;
use super::*;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("MCP server exited unexpectedly")]
    Exited,
    #[error("MCP server returned error: {0}")]
    Server(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub struct McpClient {
    pub(crate) child: Mutex<Child>,
    pub(crate) stdin: Mutex<ChildStdin>,
    pub(crate) stdout: Mutex<BufReader<ChildStdout>>,
    pub(crate) next_id: AtomicI64,
    pub(crate) initialized: Mutex<bool>,
    pub(crate) binary: String,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("binary", &self.binary)
            .finish_non_exhaustive()
    }
}
