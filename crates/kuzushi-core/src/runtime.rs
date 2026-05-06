use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, TriageOutcome};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub finding: Finding,
    pub prompt_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub system_prompt: String,
    pub prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryResponse {
    pub text: String,
    pub structured: Option<Value>,
}

/// Specialist role for a sub-agent. Mirrors the RoboDuck pattern of
/// spawning narrowly-scoped sub-agents per task so the main agent's
/// context stays focused. Each role prepends a deterministic
/// system-prompt preamble so providers don't need any role-specific code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubagentRole {
    /// Generic sub-agent — same behaviour as `query`, used as a sentinel.
    Generic,
    /// Reasons about a single `unsafe { ... }` block in Rust: bounds,
    /// alignment, raw-pointer arithmetic, `from_raw_parts*`, `transmute`.
    UnsafeBlockReasoner,
    /// Reasons about lifetimes and aliasing: `'static` smuggling,
    /// mutable aliasing, `&mut` from raw pointer, `Pin` violations.
    LifetimeAliasingReasoner,
    /// Reasons about FFI boundaries: `extern "C"` ABI mismatches,
    /// ownership transfer, `repr(C)` invariant misuse.
    FfiBoundaryReasoner,
}

impl SubagentRole {
    /// Human-readable role name used in logs and audit trails.
    pub fn name(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::UnsafeBlockReasoner => "unsafe-block",
            Self::LifetimeAliasingReasoner => "lifetime-aliasing",
            Self::FfiBoundaryReasoner => "ffi-boundary",
        }
    }

    /// Deterministic system-prompt prefix prepended to the caller's prompt.
    /// Empty for `Generic` so existing callers see no behavioural change.
    pub fn system_prompt_prefix(self) -> &'static str {
        match self {
            Self::Generic => "",
            Self::UnsafeBlockReasoner => {
                "You are a focused Rust unsafe-block reasoner. Restrict analysis to the \
                 single `unsafe { ... }` region you are given. Cite line numbers. Look \
                 for: raw-pointer arithmetic, `from_raw_parts*` on attacker-influenced \
                 lengths, `transmute`, alignment violations, uninitialised reads. \
                 Refuse claims that cannot be grounded in the supplied source.\n"
            }
            Self::LifetimeAliasingReasoner => {
                "You are a focused Rust lifetime and aliasing reasoner. Restrict \
                 analysis to lifetime annotations, mutable aliasing, `Pin`/`!Unpin` \
                 invariants, `'static` smuggling, and `&mut` derived from raw pointers. \
                 Cite line numbers. Be conservative when the borrow checker has not \
                 been overridden.\n"
            }
            Self::FfiBoundaryReasoner => {
                "You are a focused Rust FFI-boundary reasoner. Restrict analysis to \
                 `extern \"C\"` declarations, ABI mismatches, ownership transfer across \
                 the boundary, `repr(C)` invariant violations, and null/dangling \
                 pointers reaching foreign code. Cite line numbers.\n"
            }
        }
    }
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        anyhow::bail!("agent runtime does not support generic pi-agent-core queries")
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome>;

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_blocking(request)
    }

    /// Spawn a role-scoped sub-agent. The default implementation prepends
    /// the role's system-prompt preamble and forwards to `query_blocking`,
    /// so any provider that implements `query_blocking` automatically gains
    /// sub-agent support without further changes. Providers that can run
    /// children in genuinely separate sessions / workers may override this.
    fn spawn_subagent_blocking(
        &self,
        role: SubagentRole,
        mut request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        let preamble = role.system_prompt_prefix();
        if !preamble.is_empty() {
            request.system_prompt = if request.system_prompt.is_empty() {
                preamble.to_string()
            } else {
                format!("{preamble}\n{}", request.system_prompt)
            };
        }
        self.query_blocking(request)
    }

    /// Async wrapper for `spawn_subagent_blocking`. Override when the
    /// provider can dispatch role-scoped queries in parallel without
    /// blocking the executor.
    async fn spawn_subagent(
        &self,
        role: SubagentRole,
        request: AgentQueryRequest,
    ) -> Result<AgentQueryResponse> {
        self.spawn_subagent_blocking(role, request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Stub runtime that records the system prompt it received so we can
    /// verify the role preamble is prepended exactly once.
    #[derive(Default)]
    struct RecordingRuntime {
        last_system_prompt: Mutex<Option<String>>,
    }

    impl AgentRuntime for RecordingRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
            *self.last_system_prompt.lock().unwrap() = Some(request.system_prompt.clone());
            Ok(AgentQueryResponse {
                text: "ok".to_string(),
                structured: None,
            })
        }

        fn triage_finding_blocking(&self, _request: TriageRequest) -> Result<TriageOutcome> {
            unreachable!("not exercised in this test")
        }
    }

    fn request(system_prompt: &str) -> AgentQueryRequest {
        AgentQueryRequest {
            model: "openai:gpt-4.1".to_string(),
            cwd: PathBuf::from("."),
            system_prompt: system_prompt.to_string(),
            prompt: "hello".to_string(),
        }
    }

    #[test]
    fn generic_role_does_not_modify_system_prompt() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::Generic, request("base prompt"))
            .unwrap();
        assert_eq!(
            runtime.last_system_prompt.lock().unwrap().as_deref(),
            Some("base prompt")
        );
    }

    #[test]
    fn unsafe_block_role_prepends_preamble() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::UnsafeBlockReasoner, request("base"))
            .unwrap();
        let recorded = runtime.last_system_prompt.lock().unwrap().clone().unwrap();
        assert!(recorded.starts_with("You are a focused Rust unsafe-block reasoner."));
        assert!(recorded.ends_with("base"));
    }

    #[test]
    fn empty_base_prompt_yields_pure_preamble() {
        let runtime = RecordingRuntime::default();
        runtime
            .spawn_subagent_blocking(SubagentRole::FfiBoundaryReasoner, request(""))
            .unwrap();
        let recorded = runtime.last_system_prompt.lock().unwrap().clone().unwrap();
        // No leading newline when base was empty.
        assert!(recorded.starts_with("You are a focused Rust FFI-boundary reasoner."));
        assert!(!recorded.contains("\n\n"));
    }

    #[test]
    fn role_names_are_stable() {
        assert_eq!(SubagentRole::Generic.name(), "generic");
        assert_eq!(SubagentRole::UnsafeBlockReasoner.name(), "unsafe-block");
        assert_eq!(
            SubagentRole::LifetimeAliasingReasoner.name(),
            "lifetime-aliasing"
        );
        assert_eq!(SubagentRole::FfiBoundaryReasoner.name(), "ffi-boundary");
    }
}
