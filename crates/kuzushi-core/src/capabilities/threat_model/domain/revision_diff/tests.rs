use super::*;

fn document(threats: Value, nodes: &[&str]) -> Value {
    let nodes = nodes.iter().map(|id| json!({"id": id})).collect::<Vec<_>>();
    json!({
        "version": "2.0",
        "methodology": "stride",
        "dfd": {"nodes": nodes, "flows": [], "trustBoundaries": []},
        "threats": threats,
        "coverage": {"entryPointsConsidered": 4, "entryPointsCovered": 2},
        "summary": {}
    })
}

fn threat(stable_id: &str, title: &str, impact: &str) -> Value {
    json!({
        "id": "T1",
        "stableId": stable_id,
        "title": title,
        "impact": impact,
        "likelihood": "likely",
        "category": "tampering",
        "relatedCWEs": ["CWE-89"],
        "targetElementIds": ["app", "db"],
        "status": "unmitigated"
    })
}

#[test]
fn identical_documents_produce_an_empty_diff() {
    let doc = document(json!([threat("tm-a", "SQLi", "high")]), &["app"]);

    let diff = diff_threat_model_documents(&doc, &doc);

    assert!(diff.is_empty(), "{diff:?}");
    assert_eq!(diff.coverage.from.considered, Some(4));
    assert_eq!(diff.coverage.to.covered, Some(2));
}

#[test]
fn reports_added_removed_and_changed_threats_by_stable_id() {
    let from = document(
        json!([
            threat("tm-a", "SQLi", "high"),
            threat("tm-b", "XSS", "medium")
        ]),
        &["app"],
    );
    let mut edited = threat("tm-a", "SQLi in login", "critical");
    edited["targetElementIds"] = json!(["db", "app"]);
    let to = document(json!([edited, threat("tm-c", "SSRF", "high")]), &["app"]);

    let threats = diff_threat_model_documents(&from, &to).threats;

    assert_eq!(threats.added.len(), 1);
    assert_eq!(threats.added[0].key, "tm-c");
    assert_eq!(threats.added[0].impact.as_deref(), Some("high"));
    assert_eq!(threats.removed[0].title.as_deref(), Some("XSS"));
    assert_eq!(threats.changed.len(), 1);
    assert_eq!(threats.changed[0].fields, vec!["title", "impact"]);
}

#[test]
fn falls_back_to_display_id_and_counts_unkeyed_threats() {
    let from = document(
        json!([{"id": "T9", "title": "Old"}, {"title": "orphan"}]),
        &[],
    );
    let to = document(json!([{"id": "T9", "title": "New"}]), &[]);

    let threats = diff_threat_model_documents(&from, &to).threats;

    assert_eq!(threats.changed[0].key, "T9");
    assert_eq!(threats.changed[0].fields, vec!["title"]);
    assert_eq!(threats.unkeyed, UnkeyedThreatCounts { from: 1, to: 0 });
}

#[test]
fn a_shared_display_id_never_pairs_threats() {
    let first = threat("tm-a", "SQLi", "high");
    let second = threat("tm-b", "XSS", "high");
    let fresh = threat("tm-c", "SSRF", "high");

    let threats = diff_threat_model_documents(
        &document(json!([first, second]), &[]),
        &document(json!([fresh]), &[]),
    )
    .threats;

    assert_eq!(threats.rekeyed, 0);
    assert_eq!(threats.removed.len(), 2);
    assert_eq!(threats.added.len(), 1);
}

#[test]
fn permutations_with_fresh_stable_ids_pair_by_display_id() {
    let mut login = threat("tm-1111", "SQLi in login", "critical");
    login["id"] = json!("TH-001");
    let mut relogin = threat("tm-2222", "SQL injection in login", "critical");
    relogin["id"] = json!("TH-001");
    let mut other = threat("tm-3333", "SSRF", "high");
    other["id"] = json!("TH-002");

    let threats = diff_threat_model_documents(
        &document(json!([login]), &[]),
        &document(json!([relogin, other]), &[]),
    )
    .threats;

    assert_eq!(threats.rekeyed, 1);
    assert!(threats.removed.is_empty(), "{threats:?}");
    assert_eq!(threats.added.len(), 1);
    assert_eq!(threats.added[0].key, "tm-3333");
    assert_eq!(threats.changed[0].key, "tm-2222");
    assert_eq!(threats.changed[0].fields, vec!["title"]);
}

#[test]
fn related_cwe_spellings_compare_as_one_field() {
    let before = threat("tm-a", "SQLi", "high");
    let mut after = before.clone();
    after.as_object_mut().unwrap().remove("relatedCWEs");
    after["relatedCwe"] = json!(["CWE-89"]);

    let diff = diff_threat_model_documents(
        &document(json!([before]), &[]),
        &document(json!([after]), &[]),
    );

    assert!(diff.threats.changed.is_empty(), "{diff:?}");
}

#[test]
fn reports_dfd_element_and_methodology_deltas() {
    let from = document(json!([]), &["app", "db"]);
    let mut to = document(json!([]), &["app", "cache"]);
    to["dfd"]["flows"] = json!([{"id": "F1"}]);
    to["dfd"]["trustBoundaries"] = json!([{"id": "TB1"}]);
    to["methodology"] = json!("pasta");

    let diff = diff_threat_model_documents(&from, &to);

    assert_eq!(diff.dfd.nodes_added, vec!["cache"]);
    assert_eq!(diff.dfd.nodes_removed, vec!["db"]);
    assert_eq!(diff.dfd.flows_added, vec!["F1"]);
    assert_eq!(diff.dfd.boundaries_added, vec!["TB1"]);
    assert!(diff.methodology_changed);
    assert!(!diff.is_empty());
}
