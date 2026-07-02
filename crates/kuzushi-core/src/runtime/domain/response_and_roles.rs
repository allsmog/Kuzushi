use super::*;

impl AgentToolPolicy {
    pub fn new(
        profile: impl Into<String>,
        tools: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            profile: profile.into(),
            tools: tools.into_iter().map(Into::into).collect(),
            mcps: false,
            mcps_attached: Vec::new(),
        }
    }

    /// Force-enable the legacy MCP boolean. Prefer
    /// [`Self::with_mcps_for_target`] which probes artifacts on disk —
    /// the bare boolean attaches every MCP whether or not its backing
    /// artifact exists, which makes the operator chase confusing
    /// runtime errors when (for example) a CPG was never built.
    #[deprecated(note = "Use `with_mcps_for_target` to gate attachment on artifact existence.")]
    pub fn with_mcps(mut self, mcps: bool) -> Self {
        self.mcps = mcps;
        self
    }

    /// Replace the attachment plan with the supplied list and flip
    /// `mcps` to reflect whether anything is attached. Callers that
    /// already computed a plan (e.g. for the shell's startup log) can
    /// pass it through directly without re-probing.
    pub fn with_mcps_plan(mut self, plan: Vec<crate::runtime::domain::McpAttachment>) -> Self {
        self.mcps = !plan.is_empty();
        self.mcps_attached = plan;
        self
    }

    /// Probe `target` for foundational artifacts and populate the
    /// attachment plan. This is the canonical entry point for any tool
    /// that wants the MCP surface attached — it never attaches a
    /// server whose backing artifact is missing.
    pub fn with_mcps_for_target(self, target: &std::path::Path) -> Self {
        let plan = crate::runtime::mcp_probe::mcp_attachment_plan_for_target(target);
        self.with_mcps_plan(plan)
    }

    pub fn is_default(&self) -> bool {
        self.profile == "default"
            && self.tools.is_empty()
            && !self.mcps
            && self.mcps_attached.is_empty()
    }
}

impl Default for AgentToolPolicy {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            tools: Vec::new(),
            mcps: false,
            mcps_attached: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod policy_tests {
    use super::*;
    use crate::runtime::domain::McpAttachment;

    #[test]
    fn default_policy_does_not_enable_mcps() {
        let policy = AgentToolPolicy::default();
        assert!(!policy.mcps, "default policy must keep MCP surface off");
        assert!(
            policy.mcps_attached.is_empty(),
            "default policy must not list any attachments"
        );
        assert!(policy.is_default(), "fresh default policy is_default");
    }

    #[test]
    fn with_mcps_flips_flag_and_loses_is_default() {
        let policy = AgentToolPolicy::default().with_mcps(true);
        assert!(policy.mcps);
        assert!(
            !policy.is_default(),
            "is_default must consider mcps so callers can detect a non-default policy"
        );
    }

    #[test]
    fn mcps_field_round_trips_through_serde_camelcase() {
        let policy = AgentToolPolicy::new("whitebox-static", ["Read", "Glob"]).with_mcps(true);
        let json = serde_json::to_value(&policy).expect("serialise");
        // Bridge JS reads `request.toolPolicy.mcps === true`; the field
        // must serialise as camelCase `mcps`, not `Mcps` or snake_case.
        assert_eq!(json["mcps"], serde_json::Value::Bool(true));
        assert_eq!(
            json["profile"],
            serde_json::Value::String("whitebox-static".into())
        );
        let round_tripped: AgentToolPolicy = serde_json::from_value(json).expect("deserialise");
        assert_eq!(round_tripped, policy);
    }

    #[test]
    fn with_mcps_plan_replaces_attachment_list() {
        let plan = vec![
            McpAttachment::constant("treesitter"),
            McpAttachment::new("joern", "/work/.kuzushi/cpg.bin"),
        ];
        let policy = AgentToolPolicy::default().with_mcps_plan(plan.clone());
        assert!(policy.mcps);
        assert_eq!(policy.mcps_attached, plan);
        assert!(!policy.is_default());
    }

    #[test]
    fn empty_plan_keeps_policy_at_default_when_other_fields_match() {
        let policy = AgentToolPolicy::default().with_mcps_plan(Vec::new());
        assert!(!policy.mcps);
        assert!(policy.is_default());
    }

    #[test]
    fn with_mcps_for_target_attaches_only_when_artifact_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
        std::fs::write(
            tmp.path().join(".kuzushi/context-snapshot.json"),
            "{\"target\":\"x\"}",
        )
        .unwrap();
        let policy = AgentToolPolicy::default().with_mcps_for_target(tmp.path());
        assert!(policy.mcps);
        let names: Vec<&str> = policy
            .mcps_attached
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert!(names.contains(&"treesitter"));
        assert!(names.contains(&"context"));
        assert!(!names.contains(&"joern"));
        assert!(!names.contains(&"codeql"));
    }

    #[test]
    fn mcps_attached_round_trips_through_serde() {
        let policy = AgentToolPolicy::default().with_mcps_plan(vec![
            McpAttachment::constant("treesitter"),
            McpAttachment::new("context", "/work/.kuzushi/context-snapshot.json"),
        ]);
        let json = serde_json::to_value(&policy).expect("serialise");
        assert_eq!(json["mcps"], serde_json::Value::Bool(true));
        let attachments = json["mcpsAttached"]
            .as_array()
            .expect("mcpsAttached should serialise as camelCase");
        assert_eq!(attachments.len(), 2);
        assert_eq!(attachments[0]["name"], "treesitter");
        assert_eq!(
            attachments[1]["artifactPath"],
            "/work/.kuzushi/context-snapshot.json"
        );
        let round_tripped: AgentToolPolicy = serde_json::from_value(json).expect("deserialise");
        assert_eq!(round_tripped, policy);
    }

    #[test]
    fn backward_compatible_with_old_bridge_payload() {
        // A bridge that knows only `mcps: true` (no `mcpsAttached`)
        // must still deserialize cleanly with an empty plan.
        let json = serde_json::json!({
            "profile": "legacy",
            "tools": ["Read"],
            "mcps": true,
        });
        let policy: AgentToolPolicy = serde_json::from_value(json).expect("deserialise");
        assert!(policy.mcps);
        assert!(policy.mcps_attached.is_empty());
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
    /// Cheap stage label. The runtime still uses the operator-configured
    /// model unless an explicit operator route selected another one.
    Cheap,
    /// Mid stage label. Default when no explicit tier is requested.
    Mid,
    /// Deep stage label. Reserve for stages that warrant more scrutiny.
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
