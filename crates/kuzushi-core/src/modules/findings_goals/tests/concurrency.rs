use super::*;

#[test]
fn concurrent_goal_writers_admit_only_one_reviewed_revision() {
    let f = Fixture::new();
    let brief = f.brief(0);
    let page = f.page(&brief);
    let input = f.assessment(&brief, &page["rows"][0], "direct", 0);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let writers = (0..2)
        .map(|_| {
            let root = f.workspace.root().to_path_buf();
            let input = input.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let workspace = WorkspaceTarget::new(root).unwrap();
                barrier.wait();
                crate::workspace::execute_goal_review(
                    &workspace,
                    &crate::V2Config::default(),
                    "findings:goal-assess",
                    input,
                )
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = writers
        .into_iter()
        .map(|writer| writer.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        f.store
            .finding_goal_history(page["rows"][0]["basis"]["findingId"].as_i64().unwrap())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn pages_filters_and_exact_old_briefs_keep_their_own_assessments() {
    let f = Fixture::new();
    let brief = f.brief(0);
    let before = f.page(&brief);
    f.call(
        "findings:goal-assess",
        f.assessment(&brief, &before["rows"][1], "related", 0),
    )
    .unwrap();
    let page = f
        .call("findings:goals", json!({"briefRef":brief,"limit":1}))
        .unwrap();
    assert_eq!(page["data"]["total"], 2);
    assert_eq!(page["data"]["hasMore"], true);
    assert_eq!(
        page["data"]["rows"][0]["assessment"]["relevance"],
        "related"
    );
    let filtered = f
        .call(
            "findings:goals",
            json!({"briefRef":brief,"filter":"unassessed"}),
        )
        .unwrap();
    assert_eq!(filtered["data"]["total"], 1);
    let next = f.brief(1);
    assert_ne!(next, brief);
    assert_eq!(
        f.page(&brief)["rows"][0]["assessment"]["relevance"],
        "related"
    );
    assert!(f.page(&next)["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["assessment"].is_null()));
}

#[test]
fn source_changes_do_not_apply_prior_goal_assessments_to_new_generations() {
    let f = Fixture::new();
    let brief = f.brief(0);
    let before = f.page(&brief);
    let chosen = &before["rows"][0];
    f.call(
        "findings:goal-assess",
        f.assessment(&brief, chosen, "direct", 0),
    )
    .unwrap();
    std::fs::write(
        f.workspace.root().join("note.txt"),
        "Changed owned source, no execution\n",
    )
    .unwrap();
    let finding: Finding = serde_json::from_value(chosen["finding"].clone()).unwrap();
    f.store
        .with_run_lifecycle("goals-changed", f.workspace.root(), || {
            f.store.insert_finding("goals-changed", &finding)?;
            Ok(((), 1))
        })
        .unwrap();
    let typed: crate::findings::FindingGoalPage = serde_json::from_value(f.page(&brief)).unwrap();
    assert!(typed
        .rows
        .iter()
        .filter(|row| row.finding.rule_id == finding.rule_id)
        .all(|row| row.relevance().is_none()));
    assert_eq!(
        f.store
            .finding_goal_history(finding.id.unwrap())
            .unwrap()
            .len(),
        1
    );
    assert!(f.store.list_all_review_decisions().unwrap().is_empty());
}
