use serde_json::{json, Value};
use std::time::Duration;

pub(crate) const MAX_MCP_FRAME_BYTES: usize = 512 * 1024;
pub(crate) const MAX_MCP_RESPONSE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_MCP_SKIPPED_MESSAGES: usize = 64;
pub(crate) const MAX_REPO_STDOUT_BYTES: usize = 512 * 1024;
pub(crate) const MAX_REPO_STDERR_BYTES: usize = 16 * 1024;
pub(crate) const REPO_SEARCH_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn receipt() -> Value {
    json!({"mcpFrameBytes":MAX_MCP_FRAME_BYTES,"mcpCumulativeResponseBytes":MAX_MCP_RESPONSE_BYTES,
        "mcpSkippedMessages":MAX_MCP_SKIPPED_MESSAGES,"repositoryOutputBytes":MAX_REPO_STDOUT_BYTES,
        "repositorySearchStderrBytes":MAX_REPO_STDERR_BYTES,
        "repositorySearchTimeoutMs":REPO_SEARCH_TIMEOUT.as_millis() as u64,
        "compileDatabaseSourceBytes":kuzushi_mcp_common::compile_database::MAX_COMPILE_DATABASE_BYTES,
        "compileDatabasePreparedBytes":kuzushi_mcp_common::compile_database::MAX_COMPILE_DATABASE_BYTES,
        "compileDatabaseCommands":kuzushi_mcp_common::compile_database::MAX_COMPILE_COMMANDS})
}
