#[cfg(test)]
mod tests {
    use super::super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn threat_view_labels_match_command_suffixes() {
        assert_eq!(threat_view_label(ThreatView::Stride), "stride");
        assert_eq!(threat_view_label(ThreatView::Stories), "stories");
        assert_eq!(threat_view_label(ThreatView::Scope), "scope");
        assert_eq!(threat_view_label(ThreatView::Summary), "summary");
    }

    #[test]
    fn apply_threat_patch_event_records_proposal_answer_failure_and_abort() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_threat_worker_running(true);
        app.apply_threat_patch_event(ThreatPatchEvent::Proposed {
            patch: ThreatPatch {
                goal: "regen".to_string(),
                summary: "summary".to_string(),
                patch: serde_json::json!({"summary": "updated"}),
                unsupported: vec!["manual review".to_string()],
            },
            audit: AgentCallAudit::test(),
        });
        assert!(!app.threat_worker_running());
        assert!(app.engagement.has_pending_threat_patch());
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body.contains("patch proposed")));

        app.apply_threat_patch_event(ThreatPatchEvent::Answer {
            text: "answer text".to_string(),
            audit: AgentCallAudit::test(),
        });
        assert!(app
            .log_lines()
            .iter()
            .any(|line| line.body == "answer text"));

        app.apply_threat_patch_event(ThreatPatchEvent::Failed {
            error: "boom".to_string(),
            audit: AgentCallAudit::test(),
        });
        assert!(app.log_lines().iter().any(|line| line
            .body
            .contains("threats worker failed: model request failed (runtime_error)")));

        app.set_threat_abort_requested(true);
        app.apply_threat_patch_event(ThreatPatchEvent::Answer {
            text: "discarded".to_string(),
            audit: AgentCallAudit::test(),
        });
        assert!(!app.threat_abort_requested());
        assert!(!app.log_lines().iter().any(|line| line.body == "discarded"));
    }

    #[test]
    fn threat_event_records_checked_provider_cost() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_activity(Some(ActivitySession::new("threat-cost")));
        let cost = kuzushi_core::runtime::RuntimeCost::from_usd(0.02, "test threat cost").unwrap();

        app.apply_threat_patch_event(ThreatPatchEvent::Answer {
            text: "answer".to_string(),
            audit: AgentCallAudit::test()
                .with_cost(kuzushi_core::runtime::RuntimeCostReport::known(cost)),
        });

        assert_eq!(app.session().session_cost_usd(), 0.02);
        assert_eq!(
            app.activity()
                .unwrap()
                .runtime_cost_report()
                .unwrap()
                .exact_usd(),
            Some(0.02)
        );
    }
}
