use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatModelActivationSelection {
    pub(crate) model_id: String,
    pub(crate) revision_id: Option<String>,
}

impl From<kuzushi_core::capabilities::threat_model::ThreatModelRef>
    for ThreatModelActivationSelection
{
    fn from(model_ref: kuzushi_core::capabilities::threat_model::ThreatModelRef) -> Self {
        Self {
            model_id: model_ref.model_id.to_string(),
            revision_id: Some(model_ref.revision_id.to_string()),
        }
    }
}

/// Compile an activation pointer event into the ordinary descriptor-backed
/// run worker. The existing worker owns preparation, authorization, receipts,
/// and result normalization; this helper only shapes the canonical input.
pub(crate) fn threat_model_activation_worker_effect(
    selection: ThreatModelActivationSelection,
    target: Option<PathBuf>,
) -> ShellEffect {
    ShellEffect::PrepareRunTool(RunToolPreparation {
        tool_name: "threat-model:activate".to_string(),
        input: Some(activation_input(&selection).to_string()),
        target,
    })
}

fn activation_input(selection: &ThreatModelActivationSelection) -> serde_json::Value {
    let mut input = serde_json::json!({"modelId": selection.model_id});
    if let Some(revision_id) = selection.revision_id.as_ref() {
        input["revisionId"] = serde_json::Value::String(revision_id.clone());
    }
    input
}

impl ShellApp {
    pub(crate) fn reduce_threat_model_cycle(&mut self, reverse: bool) -> Vec<ShellEffect> {
        let picker = crate::ui_view_models::threat_model_picker(self);
        let Some(model_ref) = picker.cycle_ref(reverse) else {
            self.log("threats", picker.status);
            return Vec::new();
        };
        self.log(
            "threats",
            format!(
                "activating {}@{}",
                model_ref.model_id, model_ref.revision_id
            ),
        );
        vec![threat_model_activation_worker_effect(
            model_ref.into(),
            self.target_owned(),
        )]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_worker_preserves_an_exact_revision_selection() {
        let selection = ThreatModelActivationSelection {
            model_id: "tm_11111111111111111111111111111111".to_string(),
            revision_id: Some("tmr_22222222222222222222222222222222".to_string()),
        };

        assert_eq!(
            activation_input(&selection),
            serde_json::json!({
                "modelId": "tm_11111111111111111111111111111111",
                "revisionId": "tmr_22222222222222222222222222222222"
            })
        );
    }

    #[test]
    fn activation_worker_omits_revision_to_select_the_head() {
        let selection = ThreatModelActivationSelection {
            model_id: "tm_11111111111111111111111111111111".to_string(),
            revision_id: None,
        };

        assert_eq!(
            activation_input(&selection),
            serde_json::json!({"modelId": "tm_11111111111111111111111111111111"})
        );
    }
}
