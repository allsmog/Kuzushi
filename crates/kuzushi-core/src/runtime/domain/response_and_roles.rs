use super::*;

impl AgentToolPolicy {
    pub fn new(
        profile: impl Into<String>,
        tools: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            profile: profile.into(),
            tools: tools.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_default(&self) -> bool {
        self.profile == "default" && self.tools.is_empty()
    }
}

impl Default for AgentToolPolicy {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            tools: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentQueryResponse {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub structured: Option<Value>,
    /// Cost in USD for this single API call. Populated by providers
    /// that track token usage (e.g. `AnthropicOAuthRuntime` reads
    /// `usage.input_tokens` / `usage.output_tokens` and multiplies by
    /// the per-model rate). Defaults to `0.0` for providers that
    /// don't surface usage.
    #[serde(default)]
    pub cost_usd: f64,
    /// Input/output token counts when the provider reports them.
    /// Used for cost aggregation and as a sanity check on the cost
    /// calculation. Both default to `0`.
    #[serde(default)]
    pub input_tokens: u32,
    #[serde(default)]
    pub output_tokens: u32,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTier {
    /// Cheapest tier — Haiku-class. ~$0.001/k tokens. Use for fast
    /// scans + Stage 2 noise reduction.
    Cheap,
    /// Mid-tier — current Sonnet. Default when no explicit tier is
    /// requested.
    Mid,
    /// Most-capable tier — Opus. Reserve for Stage 3 verify on the
    /// few survivors that warrant the cost.
    Deep,
}

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
        subagent_role_descriptor(self).name
    }

    /// Deterministic system-prompt prefix prepended to the caller's prompt.
    /// Empty for `Generic` so existing callers see no behavioural change.
    pub fn system_prompt_prefix(self) -> &'static str {
        subagent_role_descriptor(self).system_prompt_prefix
    }
}

struct SubagentRoleDescriptor {
    role: SubagentRole,
    name: &'static str,
    system_prompt_prefix: &'static str,
}

const SUBAGENT_ROLE_DESCRIPTORS: &[SubagentRoleDescriptor] = &[
    SubagentRoleDescriptor {
        role: SubagentRole::Generic,
        name: "generic",
        system_prompt_prefix: "",
    },
    SubagentRoleDescriptor {
        role: SubagentRole::UnsafeBlockReasoner,
        name: "unsafe-block",
        system_prompt_prefix:
            "You are a focused Rust unsafe-block reasoner. Restrict analysis to the \
             single `unsafe { ... }` region you are given. Cite line numbers. Look \
             for: raw-pointer arithmetic, `from_raw_parts*` on attacker-influenced \
             lengths, `transmute`, alignment violations, uninitialised reads. \
             Refuse claims that cannot be grounded in the supplied source.\n",
    },
    SubagentRoleDescriptor {
        role: SubagentRole::LifetimeAliasingReasoner,
        name: "lifetime-aliasing",
        system_prompt_prefix: "You are a focused Rust lifetime and aliasing reasoner. Restrict \
             analysis to lifetime annotations, mutable aliasing, `Pin`/`!Unpin` \
             invariants, `'static` smuggling, and `&mut` derived from raw pointers. \
             Cite line numbers. Be conservative when the borrow checker has not \
             been overridden.\n",
    },
    SubagentRoleDescriptor {
        role: SubagentRole::FfiBoundaryReasoner,
        name: "ffi-boundary",
        system_prompt_prefix: "You are a focused Rust FFI-boundary reasoner. Restrict analysis to \
             `extern \"C\"` declarations, ABI mismatches, ownership transfer across \
             the boundary, `repr(C)` invariant violations, and null/dangling \
             pointers reaching foreign code. Cite line numbers.\n",
    },
];

fn subagent_role_descriptor(role: SubagentRole) -> &'static SubagentRoleDescriptor {
    SUBAGENT_ROLE_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.role == role)
        .unwrap_or(&SUBAGENT_ROLE_DESCRIPTORS[0])
}
