use super::*;

pub(crate) fn seeded_lesson() -> (tempfile::TempDir, FindingStore, i64) {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .with_run_lifecycle("lesson-fixture", root.path(), || {
            store.insert_finding(
                "lesson-fixture",
                &Finding::new_tool(
                    "owned-fixture",
                    "greeting",
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled synthetic review observation",
                ),
            )?;
            Ok(((), 1))
        })
        .unwrap();
    let id = store.list_all_findings().unwrap()[0].id.unwrap();
    (root, store, id)
}

fn confirmed(store: &FindingStore, id: i64) {
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::Confirmed,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Reviewed owned fixture evidence".into(),
                dismiss_reason: None,
                actor: Some("operator".into()),
            },
        )
        .unwrap();
}

fn content() -> LessonContent {
    LessonContent {
        title: "Review boundary evidence".into(),
        text: "Check recorded source before accepting a claim.".into(),
        applicability: "Manual source review".into(),
        limitations: "Historical example; current source needs separate review.".into(),
    }
}

#[test]
fn lesson_requires_explicit_confirmation_and_preserves_finding_truth() {
    let (root, store, id) = seeded_lesson();
    assert!(store.lesson_origin(root.path(), id).is_err());
    confirmed(&store, id);
    let before = store.list_all_findings().unwrap();
    let origin = store.lesson_origin(root.path(), id).unwrap();
    let draft = store.draft_finding_lesson(content(), origin, None).unwrap();
    assert!(store
        .accepted_finding_lesson(&draft.reference().unwrap())
        .is_err());
    let accepted = store
        .review_finding_lesson(
            &draft.reference().unwrap(),
            LessonState::Accepted,
            "Reviewed lesson scope and limits".into(),
        )
        .unwrap();
    assert_eq!(
        store
            .accepted_finding_lesson(&accepted.reference().unwrap())
            .unwrap(),
        accepted
    );
    let mut updated = content();
    updated.text = "Review evidence and disclose omissions.".into();
    let revised = store
        .revise_finding_lesson(&accepted.reference().unwrap(), updated)
        .unwrap();
    assert_eq!(revised.state, LessonState::Draft);
    assert!(store
        .accepted_finding_lesson(&accepted.reference().unwrap())
        .is_err());
    assert_eq!(
        store
            .finding_lesson_revision(&accepted.reference().unwrap())
            .unwrap(),
        accepted
    );
    assert_eq!(store.list_all_findings().unwrap(), before);
}

#[test]
fn stale_reviews_and_changed_confirmation_are_refused_but_retirement_remains_possible() {
    let (root, store, id) = seeded_lesson();
    confirmed(&store, id);
    let draft = store
        .draft_finding_lesson(
            content(),
            store.lesson_origin(root.path(), id).unwrap(),
            None,
        )
        .unwrap();
    let accepted = store
        .review_finding_lesson(
            &draft.reference().unwrap(),
            LessonState::Accepted,
            "Reviewed".into(),
        )
        .unwrap();
    assert!(store
        .review_finding_lesson(
            &draft.reference().unwrap(),
            LessonState::Rejected,
            "Stale".into()
        )
        .is_err());
    store
        .append_dismissal(
            id,
            DismissReason::FalsePositive,
            "Reassessed owned fixture",
            "operator",
        )
        .unwrap();
    assert!(store
        .accepted_finding_lesson(&accepted.reference().unwrap())
        .is_err());
    let retired = store
        .review_finding_lesson(
            &accepted.reference().unwrap(),
            LessonState::Retired,
            "Origin confirmation withdrawn".into(),
        )
        .unwrap();
    assert_eq!(retired.state, LessonState::Retired);
    assert_eq!(store.finding_lessons(1, 0).unwrap().rows, vec![retired]);
    assert!(store.finding_lessons(0, 0).is_err());
}

#[test]
fn concurrent_lesson_reviews_commit_one_exact_revision() {
    let (root, store, id) = seeded_lesson();
    confirmed(&store, id);
    let draft = store
        .draft_finding_lesson(
            content(),
            store.lesson_origin(root.path(), id).unwrap(),
            None,
        )
        .unwrap();
    let reference = draft.reference().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let path = crate::WorkspaceTarget::new(root.path())
        .unwrap()
        .findings_db_path();
    let outcomes = std::thread::scope(|scope| {
        let handles = [LessonState::Accepted, LessonState::Rejected].map(|state| {
            let reference = reference.clone();
            let barrier = barrier.clone();
            let path = path.clone();
            scope.spawn(move || {
                let store = FindingStore::open(path).unwrap();
                barrier.wait();
                store
                    .review_finding_lesson(&reference, state, "Concurrent explicit review".into())
                    .is_ok()
            })
        });
        handles.map(|handle| handle.join().unwrap())
    });
    assert_eq!(outcomes.iter().filter(|ok| **ok).count(), 1);
    assert_eq!(
        store.finding_lesson(&draft.id).unwrap().unwrap().revision,
        2
    );
}
