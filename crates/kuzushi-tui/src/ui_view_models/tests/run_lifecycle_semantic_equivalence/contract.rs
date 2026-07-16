use super::fixture::FixtureIds;
use kuzushi_core::run_lifecycle::{
    ModelCallPresentationV1, ModelUsage, RunCellRoleV1, RunItemStatus, RunPresentationPayloadV1,
    RunPresentationV1, ToolCallPresentationV1,
};
use std::collections::BTreeSet;

pub(super) fn assert_complete_contract(presentation: &RunPresentationV1, ids: FixtureIds) {
    assert_complete_roles(presentation);
    assert_exact_model(presentation, ids);
    assert_unavailable_model(presentation, ids);
    let child = tool_call(presentation, "tree_sitter:query");
    assert_eq!(child.parent_item_id, Some(ids.tool_item));
    assert_eq!(child.preview.len(), 2);
    assert_outer_tool_contract(presentation, ids);
    assert_hydrated_result_contract(presentation);
}

fn assert_complete_roles(presentation: &RunPresentationV1) {
    let roles = presentation
        .semantic_keys()
        .into_iter()
        .map(|key| key.role)
        .collect::<BTreeSet<_>>();
    for role in [
        RunCellRoleV1::ModelCall,
        RunCellRoleV1::ResultSummary,
        RunCellRoleV1::ProgressDisclosure,
        RunCellRoleV1::Question,
        RunCellRoleV1::Decision,
        RunCellRoleV1::Artifact,
        RunCellRoleV1::FindingDelta,
        RunCellRoleV1::SafeReasoning,
        RunCellRoleV1::TerminalOutcome,
        RunCellRoleV1::PhaseReceipt,
    ] {
        assert!(roles.contains(&role), "fixture lacks {role:?}");
    }
}

fn assert_exact_model(presentation: &RunPresentationV1, ids: FixtureIds) {
    let model = model_call(presentation, "claude-fixture");
    assert_eq!(model.parent_item_id, Some(ids.tool_item));
    assert_eq!(
        model.usage,
        Some(ModelUsage {
            input_tokens: Some(1_234),
            output_tokens: Some(321),
        })
    );
    assert!(model.cost.is_complete());
}

fn assert_unavailable_model(presentation: &RunPresentationV1, ids: FixtureIds) {
    let model = model_call(presentation, "claude-usage-unavailable");
    assert_eq!(model.parent_item_id, Some(ids.child_tool_item));
    assert_eq!(
        model.usage,
        Some(ModelUsage {
            input_tokens: None,
            output_tokens: None,
        })
    );
    assert!(model.cost.is_unavailable());
}

pub(super) fn assert_partial_contract(presentation: &RunPresentationV1) {
    assert_eq!(presentation.terminal_status, Some(RunItemStatus::Partial));
    let tool = tool_call(presentation, "verification:verify");
    assert_eq!(tool.preview.len(), 2);
    assert!(!tool.cost.is_complete());
    assert!(!tool.cost.is_unavailable());
    assert_eq!(tool.cost.observed_usd(), 0.004);
    let model = model_call(presentation, "claude-fixture");
    assert_eq!(
        model.usage,
        Some(ModelUsage {
            input_tokens: Some(210),
            output_tokens: None,
        })
    );
    assert!(!model.cost.is_complete());
    assert!(!model.cost.is_unavailable());
}

fn assert_outer_tool_contract(presentation: &RunPresentationV1, ids: FixtureIds) {
    let tool = tool_call(presentation, "verification:verify");
    let result = tool.result_artifact.as_ref().expect("result reference");
    assert_eq!(result.path.as_str(), "result.json");
    assert_eq!(result.producing_item_id, ids.tool_item);
    assert_eq!(tool.preview.len(), 2);
    assert_eq!((tool.warning_count, tool.error_count), (10, 10));
    assert!(tool.cost.is_complete());
    assert_eq!(tool.related_artifacts.len(), 2);
    assert!(tool
        .related_artifacts
        .iter()
        .all(|artifact| artifact.producing_item_id == ids.tool_item));
}

fn assert_hydrated_result_contract(presentation: &RunPresentationV1) {
    let result = presentation
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .find_map(|cell| match &cell.payload {
            RunPresentationPayloadV1::ResultSummary(result) => Some(result),
            _ => None,
        })
        .expect("hydrated result summary");
    assert_eq!(
        (result.output_lines.len(), result.output_line_count),
        (12, 14)
    );
    assert_eq!((result.warnings.len(), result.warning_count), (8, 10));
    assert_eq!((result.errors.len(), result.error_count), (8, 10));
    assert_eq!((result.artifacts.len(), result.artifact_count), (1, 1));
}

fn tool_call<'a>(presentation: &'a RunPresentationV1, label: &str) -> &'a ToolCallPresentationV1 {
    presentation
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .find_map(|cell| match &cell.payload {
            RunPresentationPayloadV1::ToolCall(tool) if tool.label.as_str() == label => Some(tool),
            _ => None,
        })
        .unwrap_or_else(|| panic!("tool call {label}"))
}

fn model_call<'a>(
    presentation: &'a RunPresentationV1,
    model_name: &str,
) -> &'a ModelCallPresentationV1 {
    presentation
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .find_map(|cell| match &cell.payload {
            RunPresentationPayloadV1::ModelCall(model) if model.model.as_str() == model_name => {
                Some(model)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("model call {model_name}"))
}
