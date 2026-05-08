#[cfg(test)]
mod tests {
    use super::super::*;
    use std::fs;

    #[test]
    fn trace_step_v2_round_trip_preserves_new_fields() {
        let step = RunTraceStep::new(7, "tool", "semgrep started")
            .with_latency_ms(Some(143))
            .with_cost_usd(Some(0.0021))
            .with_module_id("semgrep")
            .with_verb("scan")
            .with_parent_step(3)
            .with_severity("warn")
            .with_started_at_ms(1_700_000_000_000);

        let json = serde_json::to_string(&step).unwrap();
        let parsed: RunTraceStep = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, step);
        // optional fields use snake_case, not camelCase, per RunTraceStep's serde rename.
        assert!(json.contains("\"module_id\":\"semgrep\""));
        assert!(json.contains("\"parent_step\":3"));
        assert!(json.contains("\"started_at_ms\":1700000000000"));
    }

    #[test]
    fn trace_step_v1_forward_compat_leaves_new_fields_none() {
        // A pre-v2 trace.jsonl line — only the original five fields.
        let v1 = "{\"n\":1,\"kind\":\"tool\",\"label\":\"context:build started\"}";
        let parsed: RunTraceStep = serde_json::from_str(v1).unwrap();
        assert_eq!(parsed.n, 1);
        assert_eq!(parsed.kind, "tool");
        assert_eq!(parsed.label, "context:build started");
        assert!(parsed.module_id.is_none());
        assert!(parsed.verb.is_none());
        assert!(parsed.parent_step.is_none());
        assert!(parsed.severity.is_none());
        assert!(parsed.started_at_ms.is_none());
    }

    #[test]
    fn trace_step_v2_omits_unset_optional_fields_from_serialized_form() {
        // Optional fields use skip_serializing_if = "Option::is_none"; an unset step
        // should round-trip with no module_id/parent_step keys at all.
        let step = RunTraceStep::new(1, "tool", "context:build started");
        let json = serde_json::to_string(&step).unwrap();
        assert!(!json.contains("module_id"));
        assert!(!json.contains("verb"));
        assert!(!json.contains("parent_step"));
        assert!(!json.contains("severity"));
        assert!(!json.contains("started_at_ms"));
    }

    #[test]
    fn writes_summary_artifact_and_trace_under_run_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let run_id = new_run_id("tool");
        let summary = RunSummary::running(
            run_id.clone(),
            "tool",
            Some("context:build".to_string()),
            tmp.path().display().to_string(),
        );

        let summary_path = write_run_summary(tmp.path(), &summary).unwrap();
        assert!(summary_path.ends_with("summary.json"));
        let result = serde_json::json!({"ok": true});
        let artifact =
            write_run_artifact_json(tmp.path(), &run_id, "result.json", "result", &result).unwrap();
        append_run_trace_step(
            tmp.path(),
            &run_id,
            &RunTraceStep::new(1, "tool", "context:build started"),
        )
        .unwrap();
        write_run_summary(tmp.path(), &summary.complete().with_artifact(artifact)).unwrap();

        let loaded = load_run_summary(tmp.path(), &run_id).unwrap();
        assert_eq!(loaded.status, "complete");
        assert_eq!(loaded.tool.as_deref(), Some("context:build"));
        assert_eq!(loaded.artifacts.len(), 1);
        let trace = fs::read_to_string(run_dir(tmp.path(), &run_id).join("trace.jsonl")).unwrap();
        assert!(trace.contains("context:build started"));
    }

    #[test]
    fn lists_run_summaries_sorted_and_ignores_incomplete_entries() {
        let tmp = tempfile::tempdir().unwrap();

        assert!(list_run_summaries(tmp.path()).unwrap().is_empty());

        let first = RunSummary::running("run-a", "scan", None, "target-a").complete();
        let second =
            RunSummary::running("run-b", "tool", Some("ctx:build".to_string()), "target-b")
                .complete();
        write_run_summary(tmp.path(), &first).unwrap();
        write_run_summary(tmp.path(), &second).unwrap();

        let root = runs_root(tmp.path());
        fs::write(root.join("not-a-run"), "ignored").unwrap();
        fs::create_dir_all(root.join("missing-summary")).unwrap();
        fs::create_dir_all(root.join("invalid-summary")).unwrap();
        fs::write(root.join("invalid-summary").join("summary.json"), "{").unwrap();

        let run_ids = list_run_summaries(tmp.path())
            .unwrap()
            .into_iter()
            .map(|summary| summary.run_id)
            .collect::<Vec<_>>();

        assert_eq!(run_ids, vec!["run-b", "run-a"]);
    }
}
