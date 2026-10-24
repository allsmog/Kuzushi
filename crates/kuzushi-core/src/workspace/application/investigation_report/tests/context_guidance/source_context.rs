use super::*;

fn receipt(run: &str) -> serde_json::Value {
    json!({"schemaVersion":1,"runId":run,"model":"operator-selected-model",
        "scopeRef":{"scopeId":"app"},"inheritedContextRef":{"revisionId":"recorded-parent"},
        "sourcePartial":true,"completeRepositoryCoverage":false,"discoveryFileCount":2,"sharedFileCount":1,
        "selectedFileCount":3,"synthesisRequests":1,"promptSha256":"sha256:recorded",
        "inventory":{"schemaVersion":1,"enumerationComplete":false,"maxEntries":100000,
            "maxInspectedBytes":536870912,"maxFileInspectionBytes":262144,
            "omittedPaths":["uninspected.rs"],"privateField":"DO_NOT_EXPORT_UNKNOWN_FIELDS"},
        "sourceEvidence":{"policy":"accepted-group-source-code-v1","treeHash":"recorded-tree",
            "eligibleFiles":3,"selectedFiles":1,"byteBudget":1024,"fileLimit":2,"readBytes":24,
            "omissions":{"file limit":2},"files":[{"path":" main.rs ","scopeRole":"shared-context",
                "fileSha256":"sha256:recorded-source","totalLines":2,"omittedLines":1,
                "lines":[{"ref":" main.rs :1","text":"OWNED_SOURCE_TEXT_MUST_NOT_BE_EXPORTED"}]}]}})
}

fn with_source(
    fixture: &Fixture,
    goal: &serde_json::Value,
    key: &str,
    receipt: serde_json::Value,
) -> serde_json::Value {
    let base = fixture.imported_context(goal, "Source receipt parent");
    let mut document = crate::capabilities::threat_model::load_exact_threat_model(
        fixture.root.path(),
        &serde_json::from_value(base).unwrap(),
    )
    .unwrap();
    document["provenance"][key] = json!({"receipt":receipt});
    fixture.call(
        "threat-model:import",
        json!({"activate":false,"label":"Recorded source context","document":document}),
    )["modelRef"]
        .clone()
}

#[test]
fn saved_source_context_metadata_preserves_limits_and_excludes_source_text() {
    let fixture = Fixture::new();
    let goal = fixture.goal(0, "Historical source context");
    let reference = with_source(&fixture, &goal, "scopeContext", receipt("original-run"));
    fixture.plan("source-context-report", None, &reference);
    let later = fixture.goal(1, "Later context must not replace historical source");
    fixture.imported_context(&later, "Current context");
    let before = fixture.manifest();
    let exported = fixture.export("source-context-report");
    let evidence = &exported["scope"]["contextEvidence"];
    assert_eq!(evidence["contextRef"], reference);
    let input = &evidence["sourceContext"];
    assert_eq!(input["schemaVersion"], 1);
    assert_eq!(input["projection"], "metadata-only");
    assert_eq!(input["sourceTextIncluded"], false);
    assert_eq!(input["scopeContext"]["status"], "recorded");
    let kept = &input["scopeContext"]["receipt"];
    assert_eq!(kept["runId"], "original-run");
    assert_eq!(kept["sourcePartial"], true);
    assert_eq!(kept["completeRepositoryCoverage"], false);
    assert_eq!(kept["inventory"]["maxFileInspectionBytes"], 262144);
    assert_eq!(kept["inventory"]["omittedPaths"], json!(["uninspected.rs"]));
    assert!(kept["inventory"].get("privateField").is_none());
    assert_eq!(kept["sourceEvidence"]["omissions"], json!({"file limit":2}));
    assert_eq!(kept["sourceEvidence"]["files"][0]["path"], " main.rs ");
    assert_eq!(
        kept["sourceEvidence"]["files"][0]["lines"][0]["ref"],
        " main.rs :1"
    );
    assert!(kept["sourceEvidence"]["files"][0]["lines"][0]
        .get("text")
        .is_none());
    assert!(!serde_json::to_string(&exported)
        .unwrap()
        .contains("OWNED_SOURCE_TEXT_MUST_NOT_BE_EXPORTED"));
    assert_eq!(fixture.manifest(), before);
}

#[test]
fn saved_source_context_matrix_keeps_each_origin_and_explicit_omission() {
    let fixture = Fixture::new();
    let goal = fixture.goal(0, "Source matrix");
    let old = with_source(&fixture, &goal, "scopeContext", receipt("scope-run"));
    let changed = with_source(&fixture, &goal, "fileContext", receipt("evidence-run"));
    fixture.plan(
        "source-context-matrix",
        Some(json!([
            {"id":"old","label":"Accepted boundary","threatModelRef":old},
            {"id":"changed","label":"Evidence files","threatModelRef":changed},
            {"id":"omitted","label":"No context","threatModelRef":null}
        ])),
        &serde_json::Value::Null,
    );
    let exported = fixture.export("source-context-matrix");
    let cases = &exported["scope"]["caseContextEvidence"];
    assert_eq!(
        cases["old"]["sourceContext"]["scopeContext"]["receipt"]["runId"],
        "scope-run"
    );
    assert_eq!(
        cases["changed"]["sourceContext"]["fileContext"]["receipt"]["runId"],
        "evidence-run"
    );
    assert_eq!(cases["omitted"]["status"], "omitted");
    assert!(cases["omitted"].get("sourceContext").is_none());
}

#[test]
fn saved_source_context_malformed_and_unknown_receipts_stay_unavailable() {
    let fixture = Fixture::new();
    let goal = fixture.goal(0, "Unverified receipt shapes");
    for malformed in [
        json!("not a receipt"),
        json!({"schemaVersion":2}),
        json!({"schemaVersion":1,"sourceEvidence":{"files":false}}),
    ] {
        let reference = with_source(&fixture, &goal, "scopeContext", malformed);
        let state = super::super::super::scope::recorded_context_report(
            &fixture.workspace,
            &json!({"threatModelRef":reference}),
        )
        .evidence;
        assert_eq!(
            state["sourceContext"]["scopeContext"]["status"],
            "unavailable"
        );
        assert!(state["sourceContext"]["scopeContext"]
            .get("receipt")
            .is_none());
    }
}
