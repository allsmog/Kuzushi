use super::*;
use anyhow::Context;

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
            read_scope: None,
        }
    }

    /// Force-enable the legacy MCP boolean. Prefer
    /// [`Self::try_with_mcps_for_target`] which probes artifacts on disk —
    /// the bare boolean attaches every MCP whether or not its backing
    /// artifact exists, which makes the operator chase confusing
    /// runtime errors when (for example) a CPG was never built.
    #[deprecated(note = "Use `try_with_mcps_for_target` to gate attachment on artifact validity.")]
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
    pub fn try_with_mcps_for_target(self, target: &std::path::Path) -> anyhow::Result<Self> {
        let target = std::fs::canonicalize(target).with_context(|| {
            format!(
                "could not resolve MCP attachment target {}",
                target.display()
            )
        })?;
        let plan = crate::runtime::mcp_probe::try_mcp_attachment_plan_for_target(&target)?;
        let mut policy = self.with_mcps_plan(plan);
        policy.mcp_read_roots = vec![target];
        Ok(policy)
    }

    /// Source-compatible, fail-closed wrapper for integrations that have not
    /// migrated to the fallible attachment API. Invalid managed artifacts are
    /// never attached; in-repo execution paths use `try_with_mcps_for_target`.
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
            read_scope: None,
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
            McpAttachment::new("cpg", "/work/.kuzushi/cpg-rs"),
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
    fn try_with_mcps_for_target_attaches_only_when_artifact_exists() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
        std::fs::write(
            tmp.path().join(".kuzushi/context-snapshot.json"),
            "{\"target\":\"x\"}",
        )
        .unwrap();
        let policy = AgentToolPolicy::default()
            .try_with_mcps_for_target(tmp.path())
            .unwrap();
        assert!(policy.mcps);
        let names: Vec<&str> = policy
            .mcps_attached
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        assert!(names.contains(&"treesitter"));
        assert!(names.contains(&"context"));
        assert!(!names.contains(&"cpg"));
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
            McpAttachment::new("context", "/work/.kuzushi/context-snapshot.json")
                .with_artifact_identity("sha256:context-snapshot"),
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
        assert_eq!(
            attachments[1]["artifactIdentity"],
            "sha256:context-snapshot"
        );
        assert!(attachments[0].get("artifactIdentity").is_none());
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
    fn old_attachment_payload_defaults_missing_identity() {
        let attachment: McpAttachment = serde_json::from_value(serde_json::json!({
            "name": "codeql",
            "artifactPath": "/work/.kuzushi/v3/codeql-db"
        }))
        .expect("deserialize attachment without identity");

        assert_eq!(attachment.artifact_identity, None);
        assert!(serde_json::to_value(attachment)
            .expect("serialize attachment")
            .get("artifactIdentity")
            .is_none());
    }

    #[test]
    fn missing_target_does_not_grant_cwd_or_attach_servers() {
        let error = AgentToolPolicy::default()
            .try_with_mcps_for_target(std::path::Path::new("/definitely/missing/kuzushi-target"))
            .unwrap_err()
            .to_string();

        assert!(error.contains("could not resolve MCP attachment target"));
    }
}

/// Provider-reported prompt-cache accounting for one call. Present only when
/// the provider reported it, so an absent value means "not reported", never
/// "zero cache traffic". Cache reads bill at roughly a tenth of the input
/// rate and cache writes at roughly 1.25x; a run that keeps reporting zero
/// reads across identical-prefix calls has a caching setup problem worth
/// diagnosing, which is why these counts ride the response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PromptCacheUsage {
    #[serde(default)]
    pub read_input_tokens: u32,
    #[serde(default)]
    pub creation_input_tokens: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
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
    /// True only when `cost_usd` is an exact receipt. False may accompany a
    /// positive observed lower bound when one call in a multi-turn query did
    /// not report cost. Legacy serialized positive values that omit this bit
    /// are inferred as exact during deserialization.
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
    /// Prompt-cache read/write counts when the provider reported them. Cached
    /// tokens are not part of `input_tokens`, so the two can be summed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache: Option<PromptCacheUsage>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct AgentQueryResponseWire {
    text: String,
    structured: Option<Value>,
    cost_usd: f64,
    cost_usd_reported: Option<bool>,
    estimated_cost_usd: Option<f64>,
    input_tokens: u32,
    output_tokens: u32,
    prompt_cache: Option<PromptCacheUsage>,
    truncated: bool,
    stop_reason: Option<String>,
}

impl<'de> Deserialize<'de> for AgentQueryResponse {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = AgentQueryResponseWire::deserialize(deserializer)?;
        Ok(Self {
            text: wire.text,
            structured: wire.structured,
            cost_usd: wire.cost_usd,
            cost_usd_reported: wire.cost_usd_reported.unwrap_or(wire.cost_usd > 0.0),
            estimated_cost_usd: wire.estimated_cost_usd,
            input_tokens: wire.input_tokens,
            output_tokens: wire.output_tokens,
            prompt_cache: wire.prompt_cache,
            truncated: wire.truncated,
            stop_reason: wire.stop_reason,
        })
    }
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
        let estimate = self
            .estimated_cost_usd
            .map(|usd| super::RuntimeCost::from_usd(usd, "agent query response estimated cost"))
            .transpose()?;
        if self.cost_usd_reported {
            return Ok(super::RuntimeCostReport::known(cost));
        }
        // A provider response proves that a call happened. Preserve any
        // reported subtotal while refusing to present it as exact; the local
        // estimate rides alongside, labelled, never as spend.
        Ok(super::RuntimeCostReport::incomplete(cost).with_unmetered_estimate(estimate))
    }
}

#[cfg(test)]
mod agent_query_response_cost_tests {
    use super::*;

    #[test]
    fn positive_partial_cost_remains_an_incomplete_lower_bound() {
        let response = AgentQueryResponse {
            cost_usd: 0.25,
            cost_usd_reported: false,
            ..Default::default()
        };

        let cost = response.checked_cost_report().unwrap();

        assert_eq!(cost.observed_usd(), 0.25);
        assert!(!cost.is_complete());
    }

    #[test]
    fn legacy_serialized_positive_cost_stays_exact() {
        let response: AgentQueryResponse =
            serde_json::from_value(serde_json::json!({"cost_usd": 0.25})).unwrap();

        assert!(response.cost_usd_reported);
        assert_eq!(
            response.checked_cost_report().unwrap().exact_usd(),
            Some(0.25)
        );
    }

    #[test]
    fn prompt_cache_usage_is_absent_unless_reported_and_round_trips_when_it_is() {
        let unreported: AgentQueryResponse =
            serde_json::from_value(serde_json::json!({"input_tokens": 10})).unwrap();
        assert_eq!(unreported.prompt_cache, None);
        assert!(serde_json::to_value(&unreported)
            .unwrap()
            .get("prompt_cache")
            .is_none());

        let reported: AgentQueryResponse = serde_json::from_value(
            serde_json::json!({"prompt_cache": {"read_input_tokens": 4000}}),
        )
        .unwrap();
        assert_eq!(
            reported.prompt_cache,
            Some(PromptCacheUsage {
                read_input_tokens: 4000,
                creation_input_tokens: 0,
            })
        );
        let wire = serde_json::to_value(&reported).unwrap();
        assert_eq!(wire["prompt_cache"]["read_input_tokens"], 4000);
        assert_eq!(wire["prompt_cache"]["creation_input_tokens"], 0);
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
