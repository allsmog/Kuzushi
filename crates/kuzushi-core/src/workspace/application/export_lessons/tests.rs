use super::*;
use crate::findings::{
    LessonContent, LessonState, ReviewDecision, ReviewDecisionVerdict, Severity, TriageAuthor,
};

struct Fixture {
    root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    finding: Finding,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::write(
            root.path().join("hello.txt"),
            "Owned greeting. Never executed.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("lesson-origin", root.path(), "run")
            .unwrap();
        store
            .insert_finding(
                "lesson-origin",
                &Finding::new_tool(
                    "owned-fixture",
                    "greeting",
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled observation",
                ),
            )
            .unwrap();
        store
            .record_run_finished("lesson-origin", "completed", 1)
            .unwrap();
        let finding = store.list_all_findings().unwrap()[0].clone();
        store
            .append_user_review_decision(
                finding.id.unwrap(),
                &decision(ReviewDecisionVerdict::Confirmed),
            )
            .unwrap();
        Self {
            root,
            workspace,
            store,
            finding,
        }
    }

    fn draft(&self, title: &str) -> FindingLesson {
        self.store
            .draft_finding_lesson(
                LessonContent {
                    title: title.into(),
                    text: "Inspect recorded greeting.\nUnicode café and ``` stay inert.".into(),
                    applicability: "Owned defensive source review".into(),
                    limitations: "Historical, synthetic. No current-source verdict.".into(),
                },
                self.store
                    .lesson_origin(self.root.path(), self.finding.id.unwrap())
                    .unwrap(),
                None,
            )
            .unwrap()
    }

    fn export(&self, name: &str, format: WorkspaceExportFormat) -> PathBuf {
        let path = self.root.path().join(name);
        super::super::export_workspace_findings(&self.workspace, &path, Some(format)).unwrap();
        path
    }
}

fn decision(verdict: ReviewDecisionVerdict) -> ReviewDecision {
    ReviewDecision {
        verdict,
        author: TriageAuthor::Human,
        confidence: 1.0,
        rationale: "Synthetic review solely for export testing".into(),
        dismiss_reason: None,
        actor: Some("fixture operator".into()),
    }
}

#[test]
fn lesson_exports_preserve_all_states_and_origin_without_changing_verdicts() {
    let f = Fixture::new();
    let draft = f.draft("Draft guidance");
    let accepted = f
        .store
        .review_finding_lesson(
            &f.draft("Accepted guidance").reference().unwrap(),
            LessonState::Accepted,
            "Reviewed historical limits".into(),
        )
        .unwrap();
    let retired = f
        .store
        .review_finding_lesson(
            &f.draft("Retired guidance").reference().unwrap(),
            LessonState::Retired,
            "Retain history only".into(),
        )
        .unwrap();
    let before = f.store.projection_meta().unwrap().applied_seq;
    let path = f.export("lessons.json", WorkspaceExportFormat::Json);
    let json: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let rows = json["findings"][0]["lessons"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for lesson in [&draft, &accepted, &retired] {
        let row = rows
            .iter()
            .find(|row| row["lesson"]["id"] == lesson.id)
            .unwrap();
        assert_eq!(row["lesson"], serde_json::to_value(lesson).unwrap());
        assert_eq!(
            row["lessonRef"],
            serde_json::to_value(lesson.reference().unwrap()).unwrap()
        );
        assert_eq!(
            row["eligibleForContext"],
            lesson.state == LessonState::Accepted
        );
    }
    assert_eq!(json["findings"][0]["reviewDecision"], "confirmed");
    assert_eq!(f.store.projection_meta().unwrap().applied_seq, before);
    let sarif: serde_json::Value = serde_json::from_slice(
        &fs::read(f.export("lessons.sarif", WorkspaceExportFormat::Sarif)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["kuzushiLessons"],
        json["findings"][0]["lessons"]
    );
    let bundle = f.export("bundle", WorkspaceExportFormat::MarkdownBundle);
    let body = fs::read_to_string(bundle.join("findings/F-0001.md")).unwrap();
    assert!(body.contains("## Reusable lessons"));
    assert!(body.contains("    \"eligibleForContext\": true"));
    assert!(body.contains("Unicode café and ``` stay inert"));
}

#[test]
fn changed_confirmation_remains_exportable_but_is_ineligible_for_context() {
    let f = Fixture::new();
    let accepted = f
        .store
        .review_finding_lesson(
            &f.draft("Historical acceptance").reference().unwrap(),
            LessonState::Accepted,
            "Reviewed".into(),
        )
        .unwrap();
    f.store
        .append_user_review_decision(
            f.finding.id.unwrap(),
            &decision(ReviewDecisionVerdict::NeedsReview),
        )
        .unwrap();
    let path = f.export("changed.json", WorkspaceExportFormat::Json);
    let json: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let row = &json["findings"][0]["lessons"][0];
    assert_eq!(row["lesson"], serde_json::to_value(accepted).unwrap());
    assert_eq!(row["eligibleForContext"], false);
    assert!(row["eligibilityNote"]
        .as_str()
        .unwrap()
        .contains("confirmation changed"));
    assert_eq!(json["findings"][0]["reviewDecision"], "needs_review");
}

#[test]
fn workspace_history_does_not_claim_a_completed_scan() {
    let f = Fixture::new();
    let body = fs::read(f.export("history.json", WorkspaceExportFormat::VulnFindings)).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(document["scan_completed"], false);
    assert_eq!(document["findings"].as_array().unwrap().len(), 1);
}

#[test]
fn attachment_matches_generation_even_when_export_order_differs_and_omissions_are_named() {
    let f = Fixture::new();
    f.draft("Bound to greeting");
    f.store
        .record_run_started("other", f.root.path(), "run")
        .unwrap();
    f.store
        .insert_finding(
            "other",
            &Finding::new_tool(
                "owned-fixture",
                "other",
                "hello.txt",
                2,
                None,
                Severity::High,
                "Different observation",
            ),
        )
        .unwrap();
    let mut findings = f.store.list_all_findings().unwrap();
    findings.reverse();
    let mut records = super::super::workspace_finding_export_records_with_reviews(&findings, &[]);
    attach_lessons(&f.store, &findings, &mut records).unwrap();
    for record in records {
        assert_eq!(
            record.lessons.len(),
            usize::from(record.fingerprint == f.finding.fingerprint)
        );
    }
    for format in [
        WorkspaceExportFormat::Csv,
        WorkspaceExportFormat::VulnFindings,
    ] {
        assert!(super::super::workspace_export_omitted_fields(format).contains(&"lessons"));
    }
}
