use crate::{PendingPrereqPrompt, PrereqArtifactState, PrereqPlanStep, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrereqPromptModel {
    pub(crate) final_tool: String,
    pub(crate) recommended_action: String,
    pub(crate) steps: Vec<PrereqPromptStepModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrereqPromptStepModel {
    pub(crate) state_label: String,
    pub(crate) cached: bool,
    pub(crate) artifact_label: String,
    pub(crate) tool: String,
    pub(crate) writes: String,
    pub(crate) risk: String,
    pub(crate) cost_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainPrereqPlanModel {
    pub(crate) title: &'static str,
    pub(crate) rows: Vec<String>,
}

pub(crate) fn prereq_prompt_model(app: &ShellApp) -> Option<PrereqPromptModel> {
    app.pending_prereq_prompt
        .as_ref()
        .map(PrereqPromptModel::from_prompt)
}

pub(crate) fn plain_prereq_plan_model(app: &ShellApp) -> Option<PlainPrereqPlanModel> {
    prereq_prompt_model(app).map(PlainPrereqPlanModel::from_prompt_model)
}

impl PrereqPromptModel {
    fn from_prompt(prompt: &PendingPrereqPrompt) -> Self {
        Self {
            final_tool: prompt.final_tool.clone(),
            recommended_action: prompt.recommended_action.label().to_string(),
            steps: prompt
                .steps
                .iter()
                .map(PrereqPromptStepModel::from_step)
                .collect(),
        }
    }
}

impl PlainPrereqPlanModel {
    fn from_prompt_model(model: PrereqPromptModel) -> Self {
        let mut rows = vec![
            format!("final tool: {}", model.final_tool),
            "review required before prerequisites or final tool start".to_string(),
        ];
        for step in model.steps {
            rows.extend(plain_prereq_step_rows(step));
        }
        rows.push(format!(
            "actions: approve | reuse cached | regenerate | cancel (recommended: {})",
            model.recommended_action
        ));
        Self {
            title: "PREREQUISITE PLAN",
            rows,
        }
    }
}

impl PrereqPromptStepModel {
    fn from_step(step: &PrereqPlanStep) -> Self {
        Self {
            state_label: step.artifact_state.label().to_string(),
            cached: step.artifact_state == PrereqArtifactState::Cached,
            artifact_label: step.artifact_label.clone(),
            tool: step.tool.clone(),
            writes: step
                .writes
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
            risk: step.risk.clone(),
            cost_hint: step.cost_hint.clone(),
        }
    }
}

fn plain_prereq_step_rows(step: PrereqPromptStepModel) -> Vec<String> {
    vec![
        format!(
            "- {} {} via {}",
            step.state_label, step.artifact_label, step.tool
        ),
        format!("  writes: {}", step.writes),
        format!("  risk: {}", step.risk),
        format!("  cost: {}", step.cost_hint),
    ]
}

#[cfg(test)]
mod tests;
