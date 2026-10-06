use super::*;

#[test]
fn unrelated_failure_and_cancellation_keep_existing_terminal_digest_seeds() {
    let root = tempfile::tempdir().unwrap();
    for (id, canceled) in [("failed-legacy", false), ("canceled-legacy", true)] {
        let record = ToolRunRecord::new(root.path(), id, "tool", "unrelated:read");
        try_record_tool_run_started_with_reproducibility(
            record,
            &json!({}),
            None,
            None,
            Vec::new(),
        )
        .unwrap();
        let expected = if canceled {
            let prepared =
                prepare_reason_terminal(record, "canceled", "operator stopped", None).unwrap();
            let expected =
                terminal_result_digest("canceled", &json!({"reason":"operator stopped"}));
            assert_eq!(
                prepared.summary.terminal_result_sha256.as_deref(),
                Some(expected.as_str())
            );
            expected
        } else {
            let prepared =
                prepare_unsuccessful_result(record, "engine stopped", RunItemStatus::Failed, None)
                    .unwrap();
            let expected = terminal_result_digest("failed", &json!({"error":"engine stopped"}));
            assert_eq!(
                prepared.summary.terminal_result_sha256.as_deref(),
                Some(expected.as_str())
            );
            expected
        };
        assert!(!expected.is_empty());
    }
}
