use crate::{ShellApp, ThreatPatch};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThreatPatchCardModel {
    pub(crate) goal: String,
    pub(crate) summary: String,
    pub(crate) top_level_keys: usize,
    pub(crate) unsupported: Vec<String>,
}

pub(crate) fn threat_patch_card_model(app: &ShellApp) -> Option<ThreatPatchCardModel> {
    app.engagement
        .pending_threat_patch()
        .map(ThreatPatchCardModel::from_patch)
}

impl ThreatPatchCardModel {
    fn from_patch(patch: &ThreatPatch) -> Self {
        Self {
            goal: patch.goal.clone(),
            summary: patch.summary.clone(),
            top_level_keys: patch.patch.as_object().map_or(0, |map| map.len()),
            unsupported: patch.unsupported.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn threat_patch_card_model_counts_top_level_patch_keys() {
        let patch = ThreatPatch {
            goal: "regen".to_string(),
            summary: "add trust zones".to_string(),
            patch: json!({"dfd": {}, "threats": []}),
            unsupported: vec!["needs review".to_string()],
        };

        let model = ThreatPatchCardModel::from_patch(&patch);

        assert_eq!(model.goal, "regen");
        assert_eq!(model.summary, "add trust zones");
        assert_eq!(model.top_level_keys, 2);
        assert_eq!(model.unsupported, vec!["needs review"]);
    }
}
