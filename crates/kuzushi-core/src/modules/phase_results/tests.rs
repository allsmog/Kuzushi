use super::*;
use crate::modules::{autonomy, AllowanceCategory, ModuleMaturity, ModuleRegistry, ToolEffect};

#[test]
fn recorded_capture_imports_keep_authorization_without_claiming_scan_completion() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in ["recon:import", "bounty:import-har", "bounty:import-burp"] {
        let tool = registry.resolve_tool(name).unwrap();
        assert_eq!(phase_result_phase(tool), None, "{name}");
        assert_eq!(autonomy::tool_has_phase_result(name), Some(false));
        assert_eq!(
            classify_descriptor(tool),
            Some(ToolClassification::Phase(WorkflowPhase::Scan))
        );
        let mut previous = tool.clone();
        previous.phase_result = true;
        for posture in autonomy::AutonomyPosture::ORDER {
            assert_eq!(
                autonomy::gate_descriptor(tool, *posture),
                autonomy::gate_descriptor(&previous, *posture),
                "{name}"
            );
        }
    }
    assert_eq!(
        phase_result_phase(registry.resolve_tool("sast:scan").unwrap()),
        Some(WorkflowPhase::Scan)
    );
    assert_eq!(autonomy::tool_has_phase_result("sast:scan"), Some(true));
    assert_eq!(autonomy::tool_has_phase_result("unknown:legacy"), None);
}

#[test]
fn map_preparation_keeps_authorization_and_does_not_own_a_context_result() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "context:build",
        "context-lite:index",
        "entry-points:extract",
    ] {
        let tool = registry.resolve_tool(name).unwrap();
        assert_eq!(phase_result_phase(tool), None, "{name}");
        assert_eq!(
            classify_descriptor(tool),
            Some(ToolClassification::Phase(WorkflowPhase::Map))
        );
        let mut prior = tool.clone();
        prior.phase_result = true;
        for posture in autonomy::AutonomyPosture::ORDER {
            assert_eq!(
                autonomy::gate_descriptor(tool, *posture),
                autonomy::gate_descriptor(&prior, *posture),
                "{name}"
            );
        }
    }
    assert_eq!(
        phase_result_phase(registry.resolve_tool("threat-model:build").unwrap()),
        Some(WorkflowPhase::Map)
    );
}

#[test]
fn trace_result_policy_does_not_weaken_execution_authorization() {
    let registry = ModuleRegistry::with_v2_builtins();
    let trace = registry.resolve_tool("trace:expand").unwrap();
    assert_eq!(trace.discovery_maturity, Some(ModuleMaturity::Labs));
    assert_eq!(trace.allowance_category, Some(AllowanceCategory::Discovery));
    assert_eq!(phase_result_phase(trace), None);
    assert_eq!(
        classify_descriptor(trace),
        Some(ToolClassification::Phase(WorkflowPhase::Prove))
    );
    assert_eq!(trace.effect, ToolEffect::WorkspaceWrite);
    let mut previous = trace.clone();
    previous.phase_result = true;
    for posture in autonomy::AutonomyPosture::ORDER {
        assert_eq!(
            autonomy::gate_descriptor(trace, *posture),
            autonomy::gate_descriptor(&previous, *posture)
        );
    }
    assert_eq!(
        phase_result_phase(registry.resolve_tool("verify:finding").unwrap()),
        Some(WorkflowPhase::Prove)
    );
}

#[test]
fn descriptor_phase_result_default_preserves_serialized_identity() {
    let registry = ModuleRegistry::with_v2_builtins();
    let verify = registry.resolve_tool("verify:finding").unwrap();
    let value = serde_json::to_value(verify).unwrap();
    assert!(value.get("phase_result").is_none());
    let restored: ToolDescriptor = serde_json::from_value(value).unwrap();
    assert_eq!(*verify, restored);
    assert!(restored.phase_result);
    let auxiliary = restored.clone().without_phase_result();
    assert_ne!(auxiliary, restored);
    let value = serde_json::to_value(&auxiliary).unwrap();
    assert_eq!(value["phase_result"], false);
    assert_eq!(
        serde_json::from_value::<ToolDescriptor>(value).unwrap(),
        auxiliary
    );
}
