use super::*;

#[test]
fn candidate_caps_below_two_are_honored_without_raising_them() {
    let (_root, store) = seeded_store();
    for cap in [0, 1] {
        let selected =
            super::super::candidates::dedupe_candidates(&store, cap, Default::default(), None)
                .unwrap();
        assert!(selected.findings.is_empty());
        assert_eq!(selected.coverage.effective_candidate_limit, cap);
        assert_eq!(selected.coverage.omitted_candidates, 2);
    }
}

#[test]
fn candidate_receipt_discloses_whole_file_groups_omitted_by_the_cap() {
    let (root, store) = seeded_store();
    store
        .with_run_lifecycle("third-origin", root.path(), || {
            let finding = Finding::new_tool(
                "third",
                "third",
                "webapp/files.py",
                21,
                None,
                Severity::Info,
                "Labeled third distinct observation",
            );
            store.insert_finding("third-origin", &finding)?;
            Ok(((), 1usize))
        })
        .unwrap();
    let selected =
        super::super::candidates::dedupe_candidates(&store, 2, Default::default(), None).unwrap();
    assert!(selected.findings.is_empty());
    assert_eq!(selected.coverage.omitted_candidates, 3);
    assert_eq!(selected.coverage.omitted_file_buckets, 1);
    let result = super::super::dedupe_result::with_input_coverage(
        super::super::dedupe_result::empty_dedupe_result(0, 3),
        &selected.coverage,
    )
    .unwrap();
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("omitted 3 eligible"));
    assert_eq!(result["data"]["inputCoverage"]["selectedCandidates"], 0);
    assert_eq!(store.list_all_findings().unwrap().len(), 3);
}

#[test]
fn all_judge_batches_are_checked_before_any_query_and_zero_groups_make_no_request() {
    let (_root, store) = seeded_store();
    let candidates = dedupe_candidates(&store, 200).unwrap();
    let mut options =
        super::super::DedupeOptions::from_input(&serde_json::json!({"maxJudgePromptBytes":1}))
            .unwrap();
    let result = super::super::validate_judge_inputs(
        "openai-codex:gpt-5.5",
        std::path::Path::new("/tmp"),
        &candidates,
        &options,
    );
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("maxJudgePromptBytes"));
    options.max_groups = 0;
    super::super::validate_judge_inputs(
        "openai-codex:gpt-5.5",
        std::path::Path::new("/tmp"),
        &candidates,
        &options,
    )
    .unwrap();
}

#[test]
fn candidate_loading_refuses_oversized_ledger_before_judging() {
    let (root, store) = seeded_store();
    let message = "x".repeat(64 * 1024);
    store
        .with_run_lifecycle("oversized-metadata", root.path(), || {
            let findings = (0..140)
                .map(|index| {
                    Finding::new_tool(
                        "owned",
                        &format!("different-file-{index}"),
                        "other.txt",
                        1,
                        None,
                        Severity::Info,
                        &message,
                    )
                })
                .collect::<Vec<_>>();
            store.insert_findings("oversized-metadata", &findings)?;
            Ok(((), 140usize))
        })
        .unwrap();
    let result = dedupe_candidates(&store, 200);
    assert!(
        result.is_err(),
        "A prompt candidate cap must not permit unbounded aggregate ledger materialization"
    );
    assert!(result.unwrap_err().to_string().contains("maxLedgerBytes"));
    let count: i64 = store
        .conn
        .query_row("select count(*) from finding_observations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 142);
}
