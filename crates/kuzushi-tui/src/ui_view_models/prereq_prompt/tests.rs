use super::*;
use crate::{PrereqPlanAction, PrereqPlanStep};
use std::path::PathBuf;

#[test]
fn prereq_prompt_model_formats_step_details() {
    let prompt = PendingPrereqPrompt {
        final_tool: "carlini-threat-hunt:run".to_string(),
        recommended_action: PrereqPlanAction::Reuse,
        steps: vec![PrereqPlanStep {
            tool: "context-lite:index".to_string(),
            artifact_path: PathBuf::from(".kuzushi/context-snapshot.json"),
            artifact_label: "context snapshot".to_string(),
            artifact_state: PrereqArtifactState::Cached,
            writes: vec![PathBuf::from(".kuzushi/context-snapshot.json")],
            model_backed: false,
            expensive: false,
            risk: "local filesystem reads only".to_string(),
            cost_hint: "no model cost".to_string(),
        }],
    };

    let model = PrereqPromptModel::from_prompt(&prompt);

    assert_eq!(model.final_tool, "carlini-threat-hunt:run");
    assert_eq!(model.recommended_action, "reuse");
    assert_eq!(model.steps[0].state_label, "cached");
    assert!(model.steps[0].cached);
    assert_eq!(model.steps[0].artifact_label, "context snapshot");
    assert_eq!(model.steps[0].tool, "context-lite:index");
    assert_eq!(model.steps[0].writes, ".kuzushi/context-snapshot.json");
    assert_eq!(model.steps[0].risk, "local filesystem reads only");
    assert_eq!(model.steps[0].cost_hint, "no model cost");
}

#[test]
fn plain_prereq_plan_model_formats_operator_rows() {
    let prompt = PendingPrereqPrompt {
        final_tool: "carlini-threat-hunt:run".to_string(),
        recommended_action: PrereqPlanAction::Reuse,
        steps: vec![PrereqPlanStep {
            tool: "context-lite:index".to_string(),
            artifact_path: PathBuf::from(".kuzushi/context-snapshot.json"),
            artifact_label: "context snapshot".to_string(),
            artifact_state: PrereqArtifactState::Cached,
            writes: vec![PathBuf::from(".kuzushi/context-snapshot.json")],
            model_backed: false,
            expensive: false,
            risk: "local filesystem reads only".to_string(),
            cost_hint: "no model cost".to_string(),
        }],
    };

    let model = PlainPrereqPlanModel::from_prompt_model(PrereqPromptModel::from_prompt(&prompt));

    assert_eq!(model.title, "PREREQUISITE PLAN");
    assert_eq!(
        model.rows,
        vec![
            "final tool: carlini-threat-hunt:run".to_string(),
            "review required before prerequisites or final tool start".to_string(),
            "- cached context snapshot via context-lite:index".to_string(),
            "  writes: .kuzushi/context-snapshot.json".to_string(),
            "  risk: local filesystem reads only".to_string(),
            "  cost: no model cost".to_string(),
            "actions: approve | reuse cached | regenerate | cancel (recommended: reuse)"
                .to_string(),
        ]
    );
}
