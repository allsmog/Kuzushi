use super::*;
use serde_json::json;

fn reference() -> Value {
    json!({
        "proposal": {"proposalId": "scan-scopes-1", "revision": 2, "recordHash": "abc123"},
        "scopeId": "app"
    })
}

fn preview(total: usize, files: &[&str]) -> Value {
    json!({"total": total, "files": files})
}

fn proposal() -> Value {
    json!({
        "reference": {"proposalId": "scan-scopes-1", "revision": 2, "recordHash": "abc123"},
        "record": {
            "schemaVersion": 1,
            "proposalId": "scan-scopes-1",
            "revision": 2,
            "previous": null,
            "source": {"snapshotHash": "snap", "treeHash": "tree123", "gitRevision": null, "dirty": null},
            "inventoryHash": "inventory",
            "draft": {
                "schemaVersion": 1,
                "scopes": [
                    {"id": "app", "name": "Application", "paths": ["app"], "rationale": "Review application source",
                     "sharedDependencies": ["integration"], "openQuestions": []},
                    {"id": "integration", "name": "Shared library", "paths": ["shared"], "rationale": "Shared dependency",
                     "sharedDependencies": [], "openQuestions": []}
                ],
                "sharedScope": {"id": "shared-context", "name": "Shared context", "paths": ["shared"],
                    "rationale": "Context only", "sharedDependencies": [], "openQuestions": []},
                "sharedDiscovery": false,
                "exclusions": [{"path": "app/excluded.rs", "reason": "Operator excluded fixture file"}]
            },
            "acceptance": {"inventoryLimitations": true, "overlappingDiscovery": false, "exclusions": true}
        },
        "coverage": {
            "enumerationComplete": true,
            "inventoryLimited": true,
            "enumeratedFiles": 4,
            "discoveryMembers": {"app": preview(1, &["app/main.rs"]), "integration": preview(1, &["shared/lib.rs"])},
            "contextMembers": {"shared-context": preview(1, &["shared/lib.rs"])},
            "excludedFiles": preview(1, &["app/excluded.rs"]),
            "uncoveredFiles": preview(0, &[]),
            "overlaps": {"total": 0, "files": {}},
            "conflictingExclusions": {"total": 0, "files": {}},
            "limitations": ["Enumeration: filesystem; 1 omitted paths."]
        },
        "identityOmissions": preview(0, &[])
    })
}

fn scope(proposal: Value) -> Value {
    json!({"paths": ["app"], "scanScopeRef": reference(), "acceptedScopeProposal": proposal})
}

const UNAVAILABLE: &str =
    "Boundary: recorded scope details unavailable; inspect the export receipt.";

#[test]
fn unscoped_study_has_no_boundary_lines() {
    assert!(lines(&json!({"paths": ["app"]}), true).is_empty());
}

#[test]
fn missing_or_malformed_proposal_is_disclosed_as_unavailable() {
    let missing = json!({"scanScopeRef": reference()});
    assert_eq!(lines(&missing, false), vec![UNAVAILABLE]);
    assert_eq!(
        lines(&scope(json!({"reference": "broken"})), true),
        vec![UNAVAILABLE]
    );
}

#[test]
fn mismatched_or_unaccepted_proposal_never_claims_acceptance() {
    let mut other = proposal();
    other["reference"]["revision"] = json!(3);
    assert_eq!(lines(&scope(other), false), vec![UNAVAILABLE]);
    let mut draft = proposal();
    draft["record"]["acceptance"] = Value::Null;
    assert_eq!(lines(&scope(draft), false), vec![UNAVAILABLE]);
}

#[test]
fn selected_scope_absent_from_proposal_is_reported() {
    let mut value = scope(proposal());
    value["scanScopeRef"]["scopeId"] = json!("docs");
    assert_eq!(
        lines(&value, false),
        vec!["Boundary: selected scope is missing from its recorded proposal."]
    );
}

#[test]
fn accepted_boundary_states_planned_membership_and_limits() {
    let text = lines(&scope(proposal()), false).join("\n");
    assert!(text.contains("Boundary: Application · 1 planned discovery file(s)"));
    assert!(text.contains("Included paths: app"));
    assert!(text.contains(
        "Proposal coverage: 1 excluded · 0 uncovered · 0 overlap(s) · inventory limited"
    ));
    assert!(text.contains("not completed scanner coverage"));
    assert!(text.contains("Shared dependencies: integration"));
    assert!(text.contains("Shared context only: Shared context · shared"));
    assert!(!text.contains("Boundary rationale"));
}

#[test]
fn shared_discovery_is_not_described_as_context_only() {
    let mut value = proposal();
    value["record"]["draft"]["sharedDiscovery"] = json!(true);
    let text = lines(&scope(value), false).join("\n");
    assert!(!text.contains("Shared context only"));
}

#[test]
fn details_expose_rationale_identity_exclusions_and_limitations() {
    let text = lines(&scope(proposal()), true).join("\n");
    assert!(text.contains("Boundary rationale: Review application source"));
    assert!(text.contains("Scope reference: scan-scopes-1 revision 2 · record abc123 · scope app"));
    assert!(text.contains("Scope source content: tree:tree123"));
    assert!(text.contains("Excluded app/excluded.rs: Operator excluded fixture file"));
    assert!(text.contains("Enumeration: filesystem; 1 omitted paths."));
}
