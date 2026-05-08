#[cfg(test)]
mod tests {
    use super::super::*;

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
