use super::WorkflowPhase;
use crate::modules::descriptor::{ToolDescriptor, ToolEffect, ToolPhase};
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// How a descriptor relates to the engagement spine for autonomy gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolClassification {
    Read,
    Report,
    Phase(WorkflowPhase),
}

/// Descriptor-owned classification used by the shared dispatch boundary.
pub fn classify_descriptor(tool: &ToolDescriptor) -> Option<ToolClassification> {
    if tool.effect == ToolEffect::Read {
        return Some(ToolClassification::Read);
    }
    if tool.phase == ToolPhase::Report {
        return report_classification(tool.effect);
    }
    workflow_phase(tool.phase).map(ToolClassification::Phase)
}

// Report is an exit at any posture, never a way to authorize execution or
// external actions. File exports retain the descriptor's explicit approval.
fn report_classification(effect: ToolEffect) -> Option<ToolClassification> {
    match effect {
        ToolEffect::WorkspaceWrite | ToolEffect::TargetWrite => Some(ToolClassification::Report),
        _ => None,
    }
}

/// Compatibility lookup for shell presentation. Built-ins are resolved from
/// their registered descriptor, so this cannot drift from dispatch policy.
pub fn classify(tool_name: &str) -> Option<ToolClassification> {
    builtin_tool_policies()
        .get(tool_name)
        .and_then(|policy| policy.classification)
}

pub fn tool_phase(tool_name: &str) -> Option<WorkflowPhase> {
    match classify(tool_name) {
        Some(ToolClassification::Phase(phase)) => Some(phase),
        Some(ToolClassification::Read | ToolClassification::Report) | None => None,
    }
}

pub fn tool_mutates(tool_name: &str) -> bool {
    builtin_tool_policies()
        .get(tool_name)
        .is_some_and(|policy| policy.mutates)
}

#[derive(Debug, Clone, Copy)]
struct BuiltinToolPolicy {
    classification: Option<ToolClassification>,
    mutates: bool,
}

/// The builtin descriptor set is process-static, but registry construction
/// is not cheap: it clones every descriptor. The shell consults these
/// lookups per frame (journey/autonomy chrome), so the derived policy is
/// computed once. Exact-name keying matches `resolve_tool`, and dynamic
/// modules were never part of this compatibility surface.
fn builtin_tool_policies() -> &'static BTreeMap<String, BuiltinToolPolicy> {
    static POLICIES: OnceLock<BTreeMap<String, BuiltinToolPolicy>> = OnceLock::new();
    POLICIES.get_or_init(|| {
        crate::modules::registry::ModuleRegistry::with_v2_builtins()
            .tools
            .iter()
            .map(|(name, tool)| {
                let policy = BuiltinToolPolicy {
                    classification: classify_descriptor(tool),
                    mutates: tool.effect.needs_operator_approval(),
                };
                (name.clone(), policy)
            })
            .collect()
    })
}

fn workflow_phase(phase: ToolPhase) -> Option<WorkflowPhase> {
    match phase {
        ToolPhase::Map => Some(WorkflowPhase::Map),
        ToolPhase::Scan => Some(WorkflowPhase::Scan),
        ToolPhase::Review => Some(WorkflowPhase::Review),
        ToolPhase::Prove => Some(WorkflowPhase::Prove),
        ToolPhase::Fix => Some(WorkflowPhase::Fix),
        ToolPhase::Report | ToolPhase::Operate => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_descriptor_drives_phase_and_effect() {
        assert_eq!(tool_phase("context:build"), Some(WorkflowPhase::Map));
        assert_eq!(tool_phase("semgrep:scan"), Some(WorkflowPhase::Scan));
        assert_eq!(tool_phase("triage:run"), Some(WorkflowPhase::Review));
        assert_eq!(
            tool_phase("classifier-gate:score"),
            Some(WorkflowPhase::Review)
        );
        assert_eq!(tool_phase("deep-audit:run"), Some(WorkflowPhase::Review));
        assert_eq!(tool_phase("verify:finding"), Some(WorkflowPhase::Prove));
        assert_eq!(tool_phase("patch:finding"), Some(WorkflowPhase::Fix));
        assert_eq!(tool_phase("prompt-armor:report"), Some(WorkflowPhase::Fix));
        assert_eq!(classify("findings:list"), Some(ToolClassification::Read));
        assert!(tool_mutates("patch:finding"));
        assert!(!tool_mutates("findings:dismiss"));
    }

    #[test]
    fn unknown_tool_has_no_compatibility_classification() {
        assert_eq!(classify("brand-new-module:do-thing"), None);
    }

    #[test]
    fn cached_policies_match_a_freshly_built_registry_exactly() {
        let registry = crate::modules::registry::ModuleRegistry::with_v2_builtins();
        for (name, tool) in &registry.tools {
            assert_eq!(
                classify(name),
                classify_descriptor(tool),
                "cached classification drifted for {name}"
            );
            assert_eq!(
                tool_mutates(name),
                tool.effect.needs_operator_approval(),
                "cached mutation policy drifted for {name}"
            );
        }
    }
}
