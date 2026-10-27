use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, ScopeRef, ThreatModelCommit, ThreatModelRevisionSource,
};
use crate::findings::{
    test_support::ReviewedFindingFixture, LessonContent, LessonState, ReviewDecisionVerdict,
};
use serde_json::json;

mod accounting;

fn context(fixture: &ReviewedFindingFixture) -> (ThreatModelRef, crate::findings::FindingLesson) {
    fixture.record_human_decision(ReviewDecisionVerdict::Confirmed);
    let root = fixture.workspace.root();
    let finding = fixture.store.list_all_findings().unwrap()[0].id.unwrap();
    let draft = fixture
        .store
        .draft_finding_lesson(
            LessonContent {
                title: "Owned review guidance".into(),
                text: "Read the selected greeting source.".into(),
                applicability: "Owned source-only tests".into(),
                limitations: "No vulnerability is claimed".into(),
            },
            fixture.store.lesson_origin(root, finding).unwrap(),
            None,
        )
        .unwrap();
    let accepted = fixture
        .store
        .review_finding_lesson(
            &draft.reference().unwrap(),
            LessonState::Accepted,
            "Reviewed owned test guidance".into(),
        )
        .unwrap();
    let doc = json!({"version":"1","methodology":"stride","systemContext":"Owned fixture",
        "dfd":{"nodes":[{"id":"greeting","name":"Owned greeting","type":"data-store","trustZone":"repository"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{},"reviewedLessons":[accepted]});
    let result = commit_threat_model_revision(
        root,
        &doc,
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: "Owned reviewed context".into(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Import,
            source_revision_id: None,
            run_id: None,
            activate: Some(false),
            actor: "owned fixture".into(),
        },
    )
    .unwrap();
    (result.model_ref, accepted)
}

#[test]
fn exact_reviewed_context_exposes_unrecorded_cost_without_creating_an_allowance() {
    let fixture = ReviewedFindingFixture::new();
    let (reference, lesson) = context(&fixture);
    let result = load_lesson_followup_context(fixture.workspace.root(), &reference, None).unwrap();
    assert_eq!(result.lesson_count, 1);
    assert_eq!(
        result.source_run_ids,
        vec![lesson.origin.finding.run_id.unwrap()]
    );
    assert_eq!(result.unaccounted_source_runs, 1);
    assert!(result.allowance.is_none());
    assert_eq!(fixture.store.list_all_findings().unwrap().len(), 1);
}

#[test]
fn retirement_and_changed_context_hash_are_refused_before_any_plan() {
    let fixture = ReviewedFindingFixture::new();
    let (mut reference, lesson) = context(&fixture);
    let hash = reference.sha256.clone();
    reference.sha256 = "0".repeat(64);
    assert!(load_lesson_followup_context(fixture.workspace.root(), &reference, None).is_err());
    reference.sha256 = hash;
    fixture
        .store
        .review_finding_lesson(
            &lesson.reference().unwrap(),
            LessonState::Retired,
            "Retired owned guidance".into(),
        )
        .unwrap();
    let error =
        load_lesson_followup_context(fixture.workspace.root(), &reference, None).unwrap_err();
    assert!(format!("{error:#}").contains("retired"));
}

#[test]
fn multiple_source_investigations_require_a_deliberate_selection() {
    let sources = BTreeSet::from(["one".into(), "two".into()]);
    assert!(select_investigation(&sources, None).is_err());
    assert_eq!(
        select_investigation(&sources, Some("current")).unwrap(),
        Some("current")
    );
    assert_eq!(
        select_investigation(&BTreeSet::from(["one".into()]), None).unwrap(),
        Some("one")
    );
}
