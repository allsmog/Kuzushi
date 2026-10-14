use super::*;
use crate::findings::{
    Finding, FindingStore, LessonContent, LessonState, ReviewDecision, ReviewDecisionVerdict,
    Severity, TriageAuthor,
};

fn fixture() -> (
    tempfile::TempDir,
    FindingStore,
    crate::findings::FindingLesson,
    ThreatModelRef,
) {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .with_run_lifecycle("lesson-source", root.path(), || {
            store.insert_finding(
                "lesson-source",
                &Finding::new_tool(
                    "owned-fixture",
                    "greeting",
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled synthetic claim",
                ),
            )?;
            Ok(((), 1))
        })
        .unwrap();
    let id = store.list_all_findings().unwrap()[0].id.unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Reviewed fixture".into(),
                dismiss_reason: None,
                actor: None,
            },
        )
        .unwrap();
    let content = LessonContent {
        title: "Review boundary evidence".into(),
        text: "Unique accepted lesson marker".into(),
        applicability: "Source review".into(),
        limitations: "Historical only".into(),
    };
    let draft = store
        .draft_finding_lesson(content, store.lesson_origin(root.path(), id).unwrap(), None)
        .unwrap();
    let accepted = store
        .review_finding_lesson(
            &draft.reference().unwrap(),
            LessonState::Accepted,
            "Reviewed lesson".into(),
        )
        .unwrap();
    let base =
        crate::capabilities::threat_model::persistence::commit_test_model(root.path(), "Base");
    (root, store, accepted, base)
}

fn dispatch(root: &Path, store: &FindingStore, input: Value) -> Result<Value> {
    let config = crate::V2Config::default();
    let workspace = crate::WorkspaceTarget::new(root)?;
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = crate::ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("threat-model:reuse-lessons", input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

#[test]
fn selected_accepted_lessons_create_an_inactive_copy_and_retirement_blocks_scanning() {
    let (root, store, accepted, base) = fixture();
    let mirror = fs::read(persistent_threat_model_path(root.path())).unwrap();
    let result = dispatch(
        root.path(),
        &store,
        json!({"threatModelRef":base,"lessons":[accepted.reference().unwrap()]}),
    )
    .unwrap();
    let reference: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    let document = load_exact_threat_model(root.path(), &reference).unwrap();
    let selection = ThreatModelSelection::Revision(reference.clone());
    assert_eq!(
        load_selected_threat_model(root.path(), &selection).unwrap(),
        Some(document.clone())
    );
    assert!(
        crate::capabilities::agentic_sast::render_threat_model_digest(&document)
            .unwrap()
            .contains("Unique accepted lesson marker")
    );
    assert_eq!(
        fs::read(persistent_threat_model_path(root.path())).unwrap(),
        mirror
    );
    assert!(load_exact_threat_model(root.path(), &base)
        .unwrap()
        .get("reviewedLessons")
        .is_none());
    store
        .review_finding_lesson(
            &accepted.reference().unwrap(),
            LessonState::Retired,
            "No longer applicable".into(),
        )
        .unwrap();
    assert!(load_selected_threat_model(root.path(), &selection).is_err());
    assert_eq!(
        load_exact_threat_model(root.path(), &reference).unwrap(),
        document
    );
    let cleared = dispatch(
        root.path(),
        &store,
        json!({"threatModelRef":reference,"lessons":[]}),
    )
    .unwrap();
    assert_eq!(cleared["data"]["document"]["reviewedLessons"], json!([]));
}

#[test]
fn forged_duplicate_and_stale_lesson_selection_does_not_publish_a_copy() {
    let (root, store, accepted, base) = fixture();
    let reference = accepted.reference().unwrap();
    let mut wrong = reference.clone();
    wrong.sha256 = "0".repeat(64);
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    for refs in [vec![wrong], vec![reference.clone(), reference.clone()]] {
        assert!(dispatch(
            root.path(),
            &store,
            json!({"threatModelRef":base,"lessons":refs})
        )
        .is_err());
    }
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
fn lesson_selection_rejects_excessive_and_duplicate_references() {
    let root = tempfile::tempdir().unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let reference = json!({"lessonId":"lesson_test","revision":1,"sha256":"a".repeat(64)});
    assert!(
        selected_lessons(root.path(), &json!({"lessons":vec![reference;9]}), &ctx)
            .unwrap_err()
            .to_string()
            .contains("eight")
    );
}
