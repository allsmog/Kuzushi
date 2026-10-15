use super::*;

#[test]
fn review_source_wrapping_preserves_code_indentation_and_unicode() {
    let source = "    2 │     if 東京 == e\u{301}:  # keep  spaces";
    for width in [12, 36, 76, 116, 156] {
        let rows = wrap_review_document(vec![source.into()], width, true);
        assert_eq!(rows.concat(), source);
        assert!(!rows.iter().any(|row| row.starts_with('\u{301}')));
    }
}
use kuzushi_core::capabilities::campaign::{ReviewObservationSource, ReviewStudyReceipt};
use kuzushi_core::run_artifacts::RunTargetGitMetadata;
use serde_json::json;

fn receipt() -> ReviewStudyReceipt {
    ReviewStudyReceipt {
        schema_version: 1,
        campaign_id: "review".into(),
        investigation_id: "investigation".into(),
        plan_sha256: "plan".into(),
        config_sha256: "config".into(),
        model: "selected:model".into(),
        source_identity: format!("git:{};tree:{}", "b".repeat(40), "c".repeat(64)),
        input: json!({}),
        findings: vec![],
        source_evidence: None,
        observation_sources: vec![ReviewObservationSource {
            generation_id: 7,
            run_id: Some("original-run".into()),
            recorded_git: Some(RunTargetGitMetadata {
                sha: "a".repeat(40),
                branch: Some("earlier".into()),
                dirty: false,
            }),
            metadata_unavailable: false,
        }],
    }
}

#[test]
fn recorded_observation_commit_is_distinct_from_the_planned_review_source() {
    let receipt = receipt();
    let text = observation_source_lines(&receipt, Some(7)).join("\n");
    assert!(text.contains(&format!("Recorded observation commit: {}", "a".repeat(40))));
    assert!(!text.contains(&"b".repeat(40)));
    assert!(text.contains("Different commit"));
    assert!(text.contains("does not establish a fix"));
}

#[test]
fn legacy_and_unreadable_sources_are_disclosed_without_an_invented_commit() {
    let mut receipt = receipt();
    receipt.observation_sources.clear();
    assert!(observation_source_lines(&receipt, Some(7))[0].contains("not recorded in this draft"));
    receipt.observation_sources.push(ReviewObservationSource {
        generation_id: 7,
        run_id: Some("original-run".into()),
        recorded_git: None,
        metadata_unavailable: true,
    });
    assert_eq!(
        observation_source_lines(&receipt, Some(7)),
        vec!["Observation commit metadata is unavailable."]
    );
    receipt.observation_sources[0].metadata_unavailable = false;
    assert_eq!(
        observation_source_lines(&receipt, Some(7)),
        vec!["Observation commit was not recorded."]
    );
}

#[test]
fn matching_dirty_commit_is_not_presented_as_unchanged_source() {
    let mut receipt = receipt();
    receipt.source_identity = format!("git:{};tree:{}", "a".repeat(40), "c".repeat(64));
    receipt.observation_sources[0]
        .recorded_git
        .as_mut()
        .unwrap()
        .dirty = true;
    let text = observation_source_lines(&receipt, Some(7)).join("\n");
    assert!(text.contains("dirty"));
    assert!(!text.contains("unchanged"));
    assert!(!text.contains("Different commit"));
}
