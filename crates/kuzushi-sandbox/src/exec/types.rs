use crate::backend::SandboxBackend;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;

pub(crate) const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

pub(crate) const TRUNCATION_MARKER: &str = "\n[kuzushi-sandbox] output truncated at 1 MiB\n";

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox backend `{0:?}` is not available")]
    BackendUnavailable(SandboxBackend),
    #[error("could not spawn sandbox child: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("sandbox child IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid sandbox execution options: {0}")]
    InvalidOptions(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MountSpec {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxExecOptions {
    pub cmd: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only_mounts: Vec<MountSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_write_mounts: Vec<MountSpec>,
}

pub(crate) fn default_timeout_ms() -> u64 {
    30_000
}

impl SandboxExecOptions {
    pub fn new(cmd: Vec<String>) -> Self {
        Self {
            cmd,
            stdin: None,
            timeout_ms: default_timeout_ms(),
            memory_mb: None,
            workdir: None,
            env: HashMap::new(),
            network: false,
            read_only_mounts: Vec::new(),
            read_write_mounts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitOutcome {
    /// Exited normally with a status code (which may be non-zero).
    Exited,
    /// Killed by signal.
    Signaled,
    /// Wallclock timeout fired and the child was killed.
    TimedOut,
    /// A stream exceeded the retained-output budget; the child was terminated.
    OutputLimitExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxExecResult {
    pub backend: SandboxBackend,
    pub outcome: ExitOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
}
