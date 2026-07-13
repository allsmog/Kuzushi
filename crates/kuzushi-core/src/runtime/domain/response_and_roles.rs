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
            mcp_read_roots: Vec::new(),
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
        let Ok(target) = std::fs::canonicalize(target) else {
            return self.with_mcps_plan(Vec::new());
        };
        let plan = crate::runtime::mcp_probe::mcp_attachment_plan_for_target(&target);
        let mut policy = self.with_mcps_plan(plan);
        policy.mcp_read_roots = vec![target];
        policy
    }

    pub fn is_default(&self) -> bool {
        self.profile == "default"
            && self.tools.is_empty()
            && !self.mcps
            && self.mcps_attached.is_empty()
            && self.mcp_read_roots.is_empty()
    }
}

impl Default for AgentToolPolicy {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            tools: Vec::new(),
            mcps: false,
            mcps_attached: Vec::new(),
            mcp_read_roots: Vec::new(),
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
        assert!(policy.mcp_read_roots.is_empty());
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
        assert_eq!(
            policy.mcp_read_roots,
            vec![std::fs::canonicalize(tmp.path()).unwrap()]
        );
        let json = serde_json::to_value(&policy).unwrap();
        assert_eq!(
            json["mcpReadRoots"][0],
            std::fs::canonicalize(tmp.path())
                .unwrap()
                .display()
                .to_string()
        );
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
        assert!(json.get("mcpReadRoots").is_none());
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
        assert!(policy.mcp_read_roots.is_empty());
    }

    #[test]
    fn missing_target_does_not_grant_cwd_or_attach_servers() {
        let policy = AgentToolPolicy::default()
            .with_mcps_for_target(std::path::Path::new("/definitely/missing/kuzushi-target"));

        assert!(!policy.mcps);
        assert!(policy.mcps_attached.is_empty());
        assert!(policy.mcp_read_roots.is_empty());
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentQueryResponse {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub structured: Option<Value>,
    /// Exact provider-reported cost in USD for this single API call.
    /// Defaults to `0.0` for compatibility; consult `cost_usd_reported`
    /// before treating a zero as exact.
    #[serde(default)]
    pub cost_usd: f64,
    /// True when the provider explicitly reported `cost_usd`, including an
    /// explicit zero. Legacy positive values are inferred as reported for
    /// compatibility; a default zero without this bit is unresolved observed
    /// spend because receiving a response proves the provider call occurred.
    #[serde(default)]
    pub cost_usd_reported: bool,
    /// Locally calculated estimate when usage is available but the provider
    /// does not report an exact monetary charge. Never aggregate this as
    /// actual spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
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

impl AgentQueryResponse {
    /// Validate provider-reported cost before it enters aggregation or
    /// persistence. The response is returned unchanged for ergonomic use at
    /// runtime adapter boundaries.
    pub fn validate_cost(self) -> anyhow::Result<Self> {
        self.checked_cost_report()?;
        Ok(self)
    }

    pub fn checked_cost_report(&self) -> anyhow::Result<super::RuntimeCostReport> {
        let cost = super::RuntimeCost::from_usd(self.cost_usd, "agent query response cost")?;
        if let Some(estimate) = self.estimated_cost_usd {
            super::RuntimeCost::from_usd(estimate, "agent query response estimated cost")?;
        }
        if self.cost_usd_reported || self.cost_usd != 0.0 {
            return Ok(super::RuntimeCostReport::known(cost));
        }
        // A provider response proves that a call happened. Missing usage is
        // unresolved spend, not the absence of a cost receipt.
        Ok(super::RuntimeCostReport::INCOMPLETE_ZERO)
    }
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
