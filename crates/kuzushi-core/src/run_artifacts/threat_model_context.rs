//! Recorded scan context for run comparisons, independent of the active model.
use crate::capabilities::threat_model::{ThreatModelRef, ThreatModelSelection};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(super) fn bind_summary_context(
    target: &std::path::Path, input: &Value, summary: super::RunSummary,
) -> anyhow::Result<super::RunSummary> {
    match ThreatModelSelection::from_input(input)? {
        ThreatModelSelection::Active => Ok(summary),
        ThreatModelSelection::None => Ok(summary.with_threat_model_ref(None, None, None)
            .with_threat_model_provenance(None, Some("explicit-omission".into()))),
        ThreatModelSelection::Revision(reference) => {
            let path = crate::capabilities::threat_model::threat_model_object_path(target, &reference.sha256)?;
            let relative = path.strip_prefix(target)?.to_string_lossy().into_owned();
            Ok(summary.with_threat_model_ref(Some(reference.model_id.to_string()),
                Some(reference.revision_id.to_string()), Some(reference.sha256))
                .with_threat_model_provenance(Some(relative), Some("explicit-input".into())))
        }
    }
}

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
    fn start_and_terminal_receipts_preserve_explicit_context_while_active_model_changes() {
        use super::super::{ToolRunRecord, try_record_tool_run_started_with_reproducibility,
            try_record_tool_run_complete, load_run_summary};
        let root = tempfile::tempdir().unwrap();
        let first = crate::capabilities::threat_model::commit_test_model(root.path(), "selected-alpha");
        crate::capabilities::threat_model::commit_test_model(root.path(), "active-beta");
        for (run, value, expected, via) in [
            ("selected", json!(first), Some(first.sha256.clone()), "explicit-input"),
            ("omitted", Value::Null, None, "explicit-omission"),
        ] {
            let record = ToolRunRecord::new(root.path(), run, "scan", "sast:scan");
            try_record_tool_run_started_with_reproducibility(record, &json!({"threatModelRef": value}), None, None, vec![]).unwrap();
            let started = load_run_summary(root.path(), run).unwrap();
            assert_eq!(started.threat_model_sha256, expected);
            assert_eq!(started.threat_model_resolved_via.as_deref(), Some(via));
            crate::capabilities::threat_model::commit_test_model(root.path(), "later-gamma");
            try_record_tool_run_complete(record, &json!({"ok": true, "status": "completed", "data": {}})).unwrap();
            let terminal = load_run_summary(root.path(), run).unwrap();
            assert_eq!(terminal.threat_model_sha256, expected);
            assert_eq!(terminal.threat_model_id, started.threat_model_id);
            assert_eq!(terminal.threat_model_source, started.threat_model_source);
            assert_eq!(terminal.threat_model_resolved_via.as_deref(), Some(via));
        }
    }

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
