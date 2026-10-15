use super::*;

fn fixture_with_supporting() -> Fixture {
    let fixture = Fixture::new();
    for (path, bytes) in [
        ("service.txt", b"SERVICE_INPUT\n".as_slice()),
        ("store.txt", b"STORE_INPUT\n".as_slice()),
        ("binary.txt", &[0xff, 0xfe]),
        ("large.txt", &[b'x'; 256]),
    ] {
        std::fs::write(fixture.root.path().join(path), bytes).unwrap();
    }
    record_source(&fixture);
    fixture
}

fn supporting_input(paths: Value) -> Value {
    json!({"strategy":"standard","sourceEvidence":"cited","sourceEvidenceFiles":paths})
}

#[test]
fn review_supporting_files_freeze_in_order_with_one_shared_byte_limit() {
    let fixture = fixture_with_supporting();
    let receipt = fixture.draft(supporting_input(json!([
        "store.txt",
        "note.md",
        "service.txt"
    ])));
    let evidence = receipt.source_evidence.as_ref().unwrap();
    assert_eq!(evidence.schema_version, 2);
    let source = &evidence.observations[0];
    assert_eq!(
        source
            .supporting_files
            .iter()
            .map(|file| file.file.path.as_str())
            .collect::<Vec<_>>(),
        ["store.txt", "service.txt"]
    );
    assert_eq!(evidence.included_bytes, 38 + 12 + 14);
    for (path, text) in [
        ("store.txt", "STORE_INPUT\n"),
        ("service.txt", "SERVICE_INPUT\n"),
    ] {
        assert!(source.model_input().contains(
            &crate::runbooks::untrusted::render_untrusted_repo_block(path, text)
        ));
    }
    assert_eq!(
        source
            .model_input()
            .matches(&crate::runbooks::untrusted::render_untrusted_repo_block(
                "note.md",
                "Owned review fixture. Never executed.\n"
            ))
            .count(),
        1
    );
    assert_eq!(
        load_review_study(fixture.root.path(), "review")
            .unwrap()
            .source_evidence,
        receipt.source_evidence
    );
    assert!(!campaign_dir(fixture.root.path(), "review")
        .join("queue.json")
        .exists());
    assert!(fixture
        .ledger()
        .allowance_snapshot("investigation")
        .is_err());
}

#[test]
fn review_supporting_files_disclose_omissions_and_never_read_past_allowance() {
    let fixture = fixture_with_supporting();
    let mut input = supporting_input(json!([
        "binary.txt",
        "large.txt",
        "missing.txt",
        "service.txt",
        "store.txt"
    ]));
    input["maxSourceEvidenceBytes"] = json!(52);
    let receipt = fixture.draft(input);
    let evidence = receipt.source_evidence.unwrap();
    assert_eq!(evidence.included_bytes, 52);
    let files = &evidence.observations[0].supporting_files;
    assert_eq!(
        files.iter().map(|file| file.file.state).collect::<Vec<_>>(),
        [
            ReviewCapturedFileState::BinaryOrInvalidText,
            ReviewCapturedFileState::TooLarge,
            ReviewCapturedFileState::ExcludedOrMissing,
            ReviewCapturedFileState::Captured,
            ReviewCapturedFileState::TooLarge
        ]
    );
    assert!(files[4].text.is_none());
}

#[test]
fn review_supporting_files_reject_invalid_selections_before_preparation() {
    let fixture = fixture_with_supporting();
    let mut invalid = vec![
        json!(["../store.txt"]),
        json!(["/store.txt"]),
        json!(["./store.txt"]),
        json!(["a//b"]),
        json!(["a/"]),
        json!(["a\\b"]),
        json!(["a\u{1b}b"]),
        json!(["store.txt", "store.txt"]),
        json!([1]),
        json!("store.txt"),
        json!([""]),
    ];
    invalid.push(json!((0..17)
        .map(|index| format!("file{index}"))
        .collect::<Vec<_>>()));
    for paths in invalid {
        let input = json!({"campaignId":"invalid", "investigationId":"investigation", "reviewInput":supporting_input(paths.clone())});
        assert!(
            fixture
                .registry
                .execute_tool("campaign:review-study", input, &fixture.ctx())
                .is_err(),
            "accepted {paths}"
        );
    }
    assert!(!campaign_dir(fixture.root.path(), "invalid")
        .join("queue.json")
        .exists());
    assert!(fixture
        .ledger()
        .allowance_snapshot("investigation")
        .is_err());
}

#[test]
fn review_supporting_files_cannot_be_forged_reordered_or_rebound() {
    let fixture = fixture_with_supporting();
    let receipt = fixture.draft(supporting_input(json!(["service.txt", "store.txt"])));
    for mutation in ["text", "path", "order", "version", "bytes"] {
        let mut document = receipt.source_evidence.clone().unwrap();
        match mutation {
            "text" => document.observations[0].supporting_files[0].text = Some("Forged".into()),
            "path" => document.observations[0].supporting_files[0].file.path = "store.txt".into(),
            "order" => document.observations[0].supporting_files.reverse(),
            "version" => document.schema_version = 1,
            _ => document.included_bytes += 1,
        }
        let input = replace_evidence(&fixture, &receipt, &document);
        assert!(
            crate::modules::source_evidence::inspect(
                fixture.root.path(),
                &input,
                &receipt.findings
            )
            .is_err(),
            "accepted {mutation}"
        );
    }
    let mut input = receipt.input.clone();
    input["sourceEvidenceFiles"] = json!(["store.txt", "service.txt"]);
    assert!(crate::modules::source_evidence::inspect(
        fixture.root.path(),
        &input,
        &receipt.findings
    )
    .is_err());
}

#[test]
fn review_supporting_files_refuse_drift_and_preserve_historical_text() {
    let fixture = fixture_with_supporting();
    let receipt = fixture.draft(supporting_input(json!(["service.txt"])));
    std::fs::write(fixture.root.path().join("service.txt"), "Later code\n").unwrap();
    assert!(fixture
        .approve(fixture.approval(&receipt, 1))
        .unwrap_err()
        .to_string()
        .contains("source changed"));
    let historical = load_review_study(fixture.root.path(), "review").unwrap();
    assert_eq!(historical.source_evidence, receipt.source_evidence);
}

#[test]
fn review_supporting_files_never_supply_code_to_unverified_observations() {
    let fixture = fixture_with_supporting();
    std::fs::write(fixture.root.path().join("store.txt"), "Changed tree\n").unwrap();
    let receipt = fixture.draft(supporting_input(json!(["service.txt"])));
    let source = &receipt.source_evidence.as_ref().unwrap().observations[0];
    assert_eq!(source.binding, ReviewSourceBinding::RecordedSourceChanged);
    assert!(source.supporting_files.is_empty());
    assert!(!source.model_input().contains("SERVICE_INPUT"));
}

#[test]
fn review_supporting_files_reach_every_admitted_vote_without_rewriting_finding() {
    let fixture = fixture_with_supporting();
    let mut input = supporting_input(json!(["service.txt"]));
    input["votes"] = json!(2);
    let receipt = fixture.draft(input);
    let approval = fixture.approve(fixture.approval(&receipt, 2)).unwrap();
    let allowance = serde_json::from_value(approval["data"]["allowance"].clone()).unwrap();
    let runtime = RecordingReview::default();
    fixture
        .run(
            receipt.bound_input(&allowance).unwrap(),
            &runtime,
            "supporting-review",
        )
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests.iter() {
        assert!(request.prompt_template.as_deref().unwrap().contains(
            &crate::runbooks::untrusted::render_untrusted_repo_block(
                "service.txt",
                "SERVICE_INPUT\n"
            )
        ));
        assert_eq!(request.finding.message, receipt.findings[0].message);
    }
    assert_eq!(
        fixture
            .ledger()
            .allowance_snapshot("investigation")
            .unwrap()
            .committed_calls,
        2
    );
}

#[test]
fn review_supporting_files_empty_selection_keeps_version_one_and_requires_cited_policy() {
    let fixture = fixture_with_supporting();
    let receipt = fixture.draft(supporting_input(json!([])));
    assert_eq!(receipt.source_evidence.unwrap().schema_version, 1);
    let input = json!({"campaignId":"invalid", "investigationId":"investigation", "reviewInput":{"strategy":"standard", "sourceEvidenceFiles":["service.txt"]}});
    assert!(fixture
        .registry
        .execute_tool("campaign:review-study", input, &fixture.ctx())
        .is_err());
}

#[test]
fn review_supporting_files_share_the_cap_across_observations_and_honor_cancellation() {
    let fixture = fixture_with_supporting();
    fixture
        .store
        .insert_finding(
            "observed",
            &Finding::new_tool(
                "audit",
                "second",
                "note.md",
                2,
                None,
                Severity::Low,
                "Second inert observation",
            ),
        )
        .unwrap();
    let mut input = supporting_input(json!(["service.txt"]));
    input["maxSourceEvidenceBytes"] = json!(52);
    let receipt = fixture.draft(input.clone());
    let evidence = receipt.source_evidence.unwrap();
    assert_eq!(evidence.included_bytes, 52);
    assert_eq!(
        evidence
            .observations
            .iter()
            .flat_map(|source| &source.supporting_files)
            .filter(|file| file.text.is_some())
            .count(),
        1
    );
    assert_eq!(
        evidence
            .observations
            .iter()
            .filter(|source| source.binding == ReviewSourceBinding::ByteLimitReached)
            .count(),
        1
    );
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = fixture.ctx();
    ctx.cancellation = Some(&cancellation);
    assert!(fixture.registry.execute_tool("campaign:review-study", json!({"campaignId":"cancelled-supporting", "investigationId":"investigation", "reviewInput":input}), &ctx).is_err());
    assert!(!campaign_dir(fixture.root.path(), "cancelled-supporting").exists());
}

#[cfg(unix)]
#[test]
fn review_supporting_files_never_follow_symlinks_outside_the_recorded_tree() {
    let fixture = Fixture::new();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), fixture.root.path().join("outside.txt")).unwrap();
    record_source(&fixture);
    let receipt = fixture.draft(supporting_input(json!(["outside.txt"])));
    let evidence = receipt.source_evidence.unwrap();
    assert_eq!(
        evidence.observations[0].supporting_files[0].file.state,
        ReviewCapturedFileState::ExcludedOrMissing
    );
    assert!(evidence.observations[0].supporting_files[0].text.is_none());
}
