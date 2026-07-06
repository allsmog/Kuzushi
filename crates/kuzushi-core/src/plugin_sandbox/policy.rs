use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    None,
    HostAllowlist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubprocessPolicy {
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvPolicy {
    None,
    ExplicitAllowlist,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxPolicy {
    pub read_snapshot: bool,
    pub read_ast: bool,
    pub write_workspace: bool,
    pub network: NetworkPolicy,
    pub subprocess: SubprocessPolicy,
    pub env: EnvPolicy,
    pub memory_limit_bytes: u64,
    pub fuel_limit: u64,
    pub timeout_ms: u64,
    pub max_bytes_served: u64,
    pub max_findings_returned: u32,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            read_snapshot: false,
            read_ast: false,
            write_workspace: false,
            network: NetworkPolicy::None,
            subprocess: SubprocessPolicy::None,
            env: EnvPolicy::None,
            memory_limit_bytes: 256 * 1024 * 1024,
            fuel_limit: 10_000_000,
            timeout_ms: 5_000,
            max_bytes_served: 16 * 1024 * 1024,
            max_findings_returned: 1_000,
        }
    }
}
