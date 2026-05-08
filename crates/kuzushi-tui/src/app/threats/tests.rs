#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn threat_view_labels_match_command_suffixes() {
        assert_eq!(threat_view_label(ThreatView::Dfd), "dfd");
        assert_eq!(threat_view_label(ThreatView::Stride), "stride");
        assert_eq!(threat_view_label(ThreatView::Stories), "stories");
        assert_eq!(threat_view_label(ThreatView::Scope), "scope");
        assert_eq!(threat_view_label(ThreatView::Summary), "summary");
    }

    #[test]
    fn apply_threat_patch_event_records_proposal_answer_failure_and_abort() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.threat_worker_running = true;
        app.apply_threat_patch_event(ThreatPatchEvent::Proposed(ThreatPatch {
            goal: "regen".to_string(),
            summary: "summary".to_string(),
            patch: serde_json::json!({"summary": "updated"}),
            unsupported: vec!["manual review".to_string()],
        }));
        assert!(!app.threat_worker_running);
        assert!(app.pending_threat_patch.is_some());
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("patch proposed")));

        app.apply_threat_patch_event(ThreatPatchEvent::Answer {
            text: "answer text".to_string(),
        });
        assert!(app.log.iter().any(|line| line.body == "answer text"));

        app.apply_threat_patch_event(ThreatPatchEvent::Failed {
            error: "boom".to_string(),
        });
        assert!(app
            .log
            .iter()
            .any(|line| line.body.contains("threats worker failed: boom")));

        app.threat_abort_requested = true;
        app.apply_threat_patch_event(ThreatPatchEvent::Answer {
            text: "discarded".to_string(),
        });
        assert!(!app.threat_abort_requested);
        assert!(!app.log.iter().any(|line| line.body == "discarded"));
    }
}
