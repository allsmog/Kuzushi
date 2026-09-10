//! Operator autonomy posture — the always-visible "how far is the agent
//! authorized to act on its own" dial, and the pure gate that enforces it at
//! the shared tool-dispatch boundary.
//!
//! The posture is an *authorization ceiling* over the five-phase engagement
//! spine. It is orthogonal to the reality-derived journey phase: raising the
//! dial authorizes more autonomous effect, it does not forge phase progress.
//!
//! The gate **only ever refuses** a tool that sits above the ceiling — it
//! never redirects or substitutes a different tool, model, or runtime, so it
//! cannot participate in a silent model/runtime fallback (that policy lives in
//! `runtime/policy/no_silent_fallback.rs` and is untouched here).

mod tool_phase;
mod workflow_phase;

pub use tool_phase::{classify, classify_descriptor, tool_mutates, tool_phase, ToolClassification};
pub use workflow_phase::WorkflowPhase;

use crate::config::GuidedPhase;
use serde::{Deserialize, Serialize};

/// Operator authorization ceiling over the five-phase spine. Ordered so that
/// raising the dial authorizes strictly more autonomous effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum AutonomyPosture {
    /// Read/map tools only.
    ReconOnly,
    /// + scanners and semantic hunts.
    #[serde(alias = "hunt")]
    Scan,
    /// + triage, classification, and finding decisions.
    Review,
    /// + empirical verification.
    #[serde(alias = "confirm")]
    Prove,
    /// + patch/report. The most permissive rung and the headless default,
    /// so existing `kuzushi run`/scan callers that never touch the dial stay
    /// unconstrained (behavior-preserving).
    #[default]
    Fix,
}

impl AutonomyPosture {
    /// Rungs low → high.
    pub const ORDER: &'static [AutonomyPosture] = &[
        AutonomyPosture::ReconOnly,
        AutonomyPosture::Scan,
        AutonomyPosture::Review,
        AutonomyPosture::Prove,
        AutonomyPosture::Fix,
    ];

    /// The highest spine phase this posture authorizes.
    pub fn ceiling(self) -> WorkflowPhase {
        match self {
            AutonomyPosture::ReconOnly => WorkflowPhase::Map,
            AutonomyPosture::Scan => WorkflowPhase::Scan,
            AutonomyPosture::Review => WorkflowPhase::Review,
            AutonomyPosture::Prove => WorkflowPhase::Prove,
            AutonomyPosture::Fix => WorkflowPhase::Fix,
        }
    }

    /// The posture whose ceiling is exactly `phase` — used to align the dial's
    /// default to where the engagement actually is.
    pub fn from_phase(phase: WorkflowPhase) -> Self {
        match phase {
            WorkflowPhase::Map => AutonomyPosture::ReconOnly,
            WorkflowPhase::Scan => AutonomyPosture::Scan,
            WorkflowPhase::Review => AutonomyPosture::Review,
            WorkflowPhase::Prove => AutonomyPosture::Prove,
            WorkflowPhase::Fix => AutonomyPosture::Fix,
        }
    }

    /// The posture cap implied by a project-declared `phases.stop_after`.
    pub fn from_guided_phase(phase: GuidedPhase) -> Self {
        match phase {
            GuidedPhase::Map => AutonomyPosture::ReconOnly,
            GuidedPhase::Scan => AutonomyPosture::Scan,
            GuidedPhase::Review => AutonomyPosture::Review,
            GuidedPhase::Prove => AutonomyPosture::Prove,
            GuidedPhase::Fix => AutonomyPosture::Fix,
        }
    }

    /// Raise one rung, saturating at `Fix` (never wraps).
    pub fn raised(self) -> Self {
        match self {
            AutonomyPosture::ReconOnly => AutonomyPosture::Scan,
            AutonomyPosture::Scan => AutonomyPosture::Review,
            AutonomyPosture::Review => AutonomyPosture::Prove,
            AutonomyPosture::Prove | AutonomyPosture::Fix => AutonomyPosture::Fix,
        }
    }

    /// Lower one rung, saturating at `ReconOnly` (never wraps).
    pub fn lowered(self) -> Self {
        match self {
            AutonomyPosture::Fix => AutonomyPosture::Prove,
            AutonomyPosture::Prove => AutonomyPosture::Review,
            AutonomyPosture::Review => AutonomyPosture::Scan,
            AutonomyPosture::Scan | AutonomyPosture::ReconOnly => AutonomyPosture::ReconOnly,
        }
    }

    /// Clamp to a cap (never authorize beyond `cap`).
    pub fn capped_by(self, cap: AutonomyPosture) -> Self {
        self.min(cap)
    }

    /// Plain one-word rung name.
    pub fn label(self) -> &'static str {
        match self {
            AutonomyPosture::ReconOnly => "recon",
            AutonomyPosture::Scan => "scan",
            AutonomyPosture::Review => "review",
            AutonomyPosture::Prove => "prove",
            AutonomyPosture::Fix => "fix",
        }
    }

    /// Judo glyph for the ceiling phase — reused from `WorkflowPhase` so the
    /// posture chip and the phase chip stay glyph-consistent.
    pub fn kanji(self) -> &'static str {
        self.ceiling().kanji()
    }

    pub fn parse(raw: &str) -> Option<AutonomyPosture> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "recon" | "recon-only" | "recononly" | "reconnaissance" | "read" | "map" => {
                Some(AutonomyPosture::ReconOnly)
            }
            "scan" | "hunt" => Some(AutonomyPosture::Scan),
            "review" => Some(AutonomyPosture::Review),
            "prove" | "confirm" | "verify" => Some(AutonomyPosture::Prove),
            "fix" | "patch" => Some(AutonomyPosture::Fix),
            _ => None,
        }
    }
}

/// The gate's verdict for a single tool under a posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomyDecision {
    /// Tool sits at/under the ceiling and does not mutate target state.
    Allow,
    /// Tool sits at/under the ceiling but mutates target state — the caller's
    /// existing approval gate should confirm the write. Advisory: the dispatch
    /// boundary proceeds (headless callers have no operator to prompt); the
    /// TUI routes this through `confirm_gate_for_tool` before dispatch.
    RequireApproval,
    /// Tool sits above the ceiling — refused. Never redirected.
    Refuse {
        needed: WorkflowPhase,
        ceiling: WorkflowPhase,
    },
    /// Effectful tool without a declared journey phase, or an unknown name in
    /// the compatibility API. Unknown policy fails closed at every posture.
    RefuseUnclassified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutonomyRefusal {
    pub tool_name: String,
    pub needed: WorkflowPhase,
    pub ceiling: WorkflowPhase,
}

impl std::fmt::Display for AutonomyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} is a {} action but autonomy posture is capped at {}; raise posture (Ctrl+Up) to authorize",
            self.tool_name,
            self.needed.word(),
            self.ceiling.word()
        )
    }
}

impl std::error::Error for AutonomyRefusal {}

/// Pure autonomy gate. No IO, no model, no runtime. Refuses tools above the
/// posture ceiling; otherwise allows (flagging mutating tools for approval).
pub fn gate(tool_name: &str, posture: AutonomyPosture) -> AutonomyDecision {
    let registry = crate::modules::registry::ModuleRegistry::with_v2_builtins();
    let Some(tool) = registry.resolve_tool(tool_name) else {
        return AutonomyDecision::RefuseUnclassified;
    };
    gate_descriptor(tool, posture)
}

/// Gate the descriptor actually selected for dispatch. Dynamic tools never
/// fall back to a built-in name table.
pub fn gate_descriptor(
    tool: &crate::modules::descriptor::ToolDescriptor,
    posture: AutonomyPosture,
) -> AutonomyDecision {
    let Some(classification) = classify_descriptor(tool) else {
        return AutonomyDecision::RefuseUnclassified;
    };
    let decision = classification_gate(classification, posture);
    if decision != AutonomyDecision::Allow {
        return decision;
    }
    if tool.approval == crate::modules::descriptor::ApprovalPolicy::Explicit {
        return AutonomyDecision::RequireApproval;
    }
    AutonomyDecision::Allow
}

fn classification_gate(
    classification: ToolClassification,
    posture: AutonomyPosture,
) -> AutonomyDecision {
    match classification {
        ToolClassification::Phase(needed) => gate_phase(needed, posture),
        ToolClassification::Read | ToolClassification::Report => AutonomyDecision::Allow,
    }
}

/// Gate an explicitly resolved workflow phase. Composite tools use this after
/// inspecting their prepared input so the highest requested nested stage is
/// authorized before any lower-phase side effect begins.
pub fn gate_phase(needed: WorkflowPhase, posture: AutonomyPosture) -> AutonomyDecision {
    let ceiling = posture.ceiling();
    if needed > ceiling {
        return AutonomyDecision::Refuse { needed, ceiling };
    }
    AutonomyDecision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::registry::ModuleRegistry;

    #[test]
    fn order_is_recon_scan_review_prove_fix() {
        assert!(AutonomyPosture::ReconOnly < AutonomyPosture::Scan);
        assert!(AutonomyPosture::Scan < AutonomyPosture::Review);
        assert!(AutonomyPosture::Review < AutonomyPosture::Prove);
        assert!(AutonomyPosture::Prove < AutonomyPosture::Fix);
        assert_eq!(AutonomyPosture::default(), AutonomyPosture::Fix);
    }

    #[test]
    fn raise_and_lower_saturate_without_wrapping() {
        assert_eq!(AutonomyPosture::Fix.raised(), AutonomyPosture::Fix);
        assert_eq!(AutonomyPosture::ReconOnly.raised(), AutonomyPosture::Scan);
        assert_eq!(
            AutonomyPosture::ReconOnly.lowered(),
            AutonomyPosture::ReconOnly
        );
        assert_eq!(AutonomyPosture::Fix.lowered(), AutonomyPosture::Prove);
    }

    #[test]
    fn from_phase_and_ceiling_round_trip() {
        for phase in WorkflowPhase::ORDER {
            assert_eq!(AutonomyPosture::from_phase(*phase).ceiling(), *phase);
        }
    }

    #[test]
    fn capped_by_never_exceeds_cap() {
        assert_eq!(
            AutonomyPosture::Fix.capped_by(AutonomyPosture::Scan),
            AutonomyPosture::Scan
        );
        assert_eq!(
            AutonomyPosture::ReconOnly.capped_by(AutonomyPosture::Fix),
            AutonomyPosture::ReconOnly
        );
    }

    #[test]
    fn parse_accepts_names_and_aliases_but_rejects_numbers() {
        assert_eq!(
            AutonomyPosture::parse("recon"),
            Some(AutonomyPosture::ReconOnly)
        );
        assert_eq!(AutonomyPosture::parse("HUNT"), Some(AutonomyPosture::Scan));
        assert_eq!(
            AutonomyPosture::parse("review"),
            Some(AutonomyPosture::Review)
        );
        assert_eq!(
            AutonomyPosture::parse("confirm"),
            Some(AutonomyPosture::Prove)
        );
        assert_eq!(AutonomyPosture::parse("3"), None);
        assert_eq!(AutonomyPosture::parse("fix"), Some(AutonomyPosture::Fix));
        assert_eq!(AutonomyPosture::parse("nope"), None);
    }

    #[test]
    fn serde_normalizes_legacy_posture_aliases() {
        assert_eq!(
            serde_json::from_str::<AutonomyPosture>("\"hunt\"").unwrap(),
            AutonomyPosture::Scan
        );
        assert_eq!(
            serde_json::from_str::<AutonomyPosture>("\"confirm\"").unwrap(),
            AutonomyPosture::Prove
        );
        assert_eq!(
            serde_json::to_string(&AutonomyPosture::Review).unwrap(),
            "\"review\""
        );
    }

    #[test]
    fn gate_refuses_tools_above_the_ceiling() {
        // A fix action under a scan posture is refused, naming both phases.
        let decision = gate("patch:finding", AutonomyPosture::Scan);
        assert_eq!(
            decision,
            AutonomyDecision::Refuse {
                needed: WorkflowPhase::Fix,
                ceiling: WorkflowPhase::Scan,
            }
        );
        // A prove action under a scan posture is likewise refused.
        assert!(matches!(
            gate("verify:finding", AutonomyPosture::Scan),
            AutonomyDecision::Refuse { .. }
        ));
    }

    #[test]
    fn gate_allows_tools_at_or_under_the_ceiling() {
        assert_eq!(
            gate("semgrep:scan", AutonomyPosture::Scan),
            AutonomyDecision::Allow
        );
        assert_eq!(
            gate("context:build", AutonomyPosture::Scan),
            AutonomyDecision::Allow
        );
        // Read/infra tools are always allowed, even at the lowest rung.
        assert_eq!(
            gate("findings:list", AutonomyPosture::ReconOnly),
            AutonomyDecision::Allow
        );
        assert_eq!(
            gate("config:show", AutonomyPosture::ReconOnly),
            AutonomyDecision::Allow
        );
    }

    #[test]
    fn gate_flags_mutating_tools_at_the_ceiling_for_approval() {
        assert_eq!(
            gate("patch:finding", AutonomyPosture::Fix),
            AutonomyDecision::RequireApproval
        );
    }

    #[test]
    fn reports_are_exits_at_every_posture_and_keep_export_approval() {
        let registry = ModuleRegistry::with_v2_builtins();
        let report = registry.resolve_tool("report:build").unwrap();
        let sarif = registry.resolve_tool("report:sarif").unwrap();
        for posture in AutonomyPosture::ORDER {
            assert_eq!(gate_descriptor(report, *posture), AutonomyDecision::Allow);
            assert_eq!(gate_descriptor(sarif, *posture), AutonomyDecision::RequireApproval);
        }
        assert_eq!(crate::modules::phase_results::phase_result_phase(report), None);
        assert_eq!(crate::modules::phase_results::phase_result_phase(sarif), None);
    }

    #[test]
    fn report_phase_cannot_authorize_repository_execution_or_external_actions() {
        use crate::modules::descriptor::{ApprovalPolicy, ToolEffect};
        let registry = ModuleRegistry::with_v2_builtins();
        let mut tool = registry.resolve_tool("report:build").unwrap().clone();
        tool.approval = ApprovalPolicy::Explicit;
        for effect in [ToolEffect::RepositoryExecute, ToolEffect::ExternalAction] {
            tool.effect = effect;
            assert_eq!(gate_descriptor(&tool, AutonomyPosture::Fix), AutonomyDecision::RefuseUnclassified);
        }
    }

    #[test]
    fn fix_posture_never_refuses_anything() {
        // The headless default (`Fix`) leaves every tool runnable — the
        // regression guard for existing `kuzushi run`/scan callers that never
        // touch the dial.
        let registry = ModuleRegistry::with_v2_builtins();
        for name in registry.tools.keys() {
            assert!(
                !matches!(
                    gate(name, AutonomyPosture::Fix),
                    AutonomyDecision::Refuse { .. } | AutonomyDecision::RefuseUnclassified
                ),
                "{name} was refused under the most-permissive Fix posture"
            );
        }
    }

    /// The anti-escape guard: every descriptor accepted by the shared
    /// dispatch boundary must classify. Executor-only legacy DAG ids are not
    /// included because dispatch now refuses anything without a descriptor.
    #[test]
    fn every_registered_tool_is_classified() {
        let registry = ModuleRegistry::with_v2_builtins();
        let unclassified: Vec<&String> = registry
            .tools
            .keys()
            .filter(|name| classify(name).is_none())
            .collect();
        assert!(
            unclassified.is_empty(),
            "these dispatchable tools escape autonomy classification (add their module \
             prefix to tool_phase.rs): {unclassified:?}"
        );
    }

    #[test]
    fn unknown_tool_fails_closed() {
        assert_eq!(
            gate("unknown:act", AutonomyPosture::Fix),
            AutonomyDecision::RefuseUnclassified
        );
    }
}
