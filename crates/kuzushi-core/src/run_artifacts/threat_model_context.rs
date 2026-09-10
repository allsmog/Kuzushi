//! Recorded scan context for run comparisons, independent of the active model.
use crate::capabilities::threat_model::{ThreatModelRef, ThreatModelSelection};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum RunThreatModelContext {
    #[default]
    Unavailable,
    Omitted,
    Revision { reference: ThreatModelRef },
}

impl RunThreatModelContext {
    pub fn from_scan_input(input: Option<&Value>) -> Self {
        let selection = input.map(ThreatModelSelection::from_input);
        match selection {
            Some(Ok(ThreatModelSelection::None)) => Self::Omitted,
            Some(Ok(ThreatModelSelection::Revision(reference))) => Self::Revision { reference },
            _ => Self::Unavailable,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Unavailable => "not recorded or unreadable".to_string(),
            Self::Omitted => "explicitly no threat-model context".to_string(),
            Self::Revision { reference } => format!("{}@{} ({})", reference.model_id, reference.revision_id, reference.sha256),
        }
    }

    pub fn comparison_label(&self, later: &Self) -> &'static str {
        match (self, later) {
            (Self::Unavailable, _) | (_, Self::Unavailable) => "comparison unavailable",
            _ if self == later => "same recorded context",
            _ => "changed; scan conditions differ",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_and_malformed_context_never_become_explicit_absence() {
        assert_eq!(RunThreatModelContext::from_scan_input(None), RunThreatModelContext::Unavailable);
        assert_eq!(RunThreatModelContext::from_scan_input(Some(&json!({}))), RunThreatModelContext::Unavailable);
        assert_eq!(RunThreatModelContext::from_scan_input(Some(&json!({"threatModelRef": {}}))), RunThreatModelContext::Unavailable);
        assert_eq!(RunThreatModelContext::from_scan_input(Some(&json!({"threatModelRef": null}))), RunThreatModelContext::Omitted);
    }

    #[test]
    fn recorded_revision_round_trips_without_loading_a_current_model() {
        let root = tempfile::tempdir().unwrap();
        let reference = crate::capabilities::threat_model::commit_test_model(root.path(), "selected");
        let context = RunThreatModelContext::from_scan_input(Some(&json!({"threatModelRef": reference})));
        let serialized = serde_json::to_value(&context).unwrap();
        assert_eq!(serialized["state"], "revision");
        assert_eq!(serde_json::from_value::<RunThreatModelContext>(serialized).unwrap(), context);
        assert!(context.label().contains(&reference.sha256));
        assert_eq!(context.comparison_label(&context), "same recorded context");
        assert_eq!(context.comparison_label(&RunThreatModelContext::Omitted), "changed; scan conditions differ");
        assert_eq!(context.comparison_label(&RunThreatModelContext::Unavailable), "comparison unavailable");
    }
}
