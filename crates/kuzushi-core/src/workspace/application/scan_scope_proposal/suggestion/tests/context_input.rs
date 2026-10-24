use super::*;

const SELECTED_OVERVIEW: &str = "Owned application context: app/main.py supplies the application component. This is imported source guidance, not a runtime claim.";
const ACTIVE_OVERVIEW: &str = "Different globally active context, not selected for this proposal.";

fn import_context(fixture: &Fixture, overview: &str, activate: bool) -> Value {
    let input = json!({
        "label": overview, "activate": activate,
        "document": {"version":"1.0", "systemContext":overview,
            "dfd":{"nodes":[{"id":"app","name":"Owned application",
                "type":"process","trustZone":"internal","sourceRefs":["app/main.py:1"]}],
                "flows":[],"trustBoundaries":[]},
            "threats":[],"summary":{}}
    });
    let ctx = fixture.context();
    let prepared = fixture
        .registry
        .prepare_dispatch_input("threat-model:import", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let output = fixture
        .registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    output["data"]["modelRef"].clone()
}

#[test]
fn prepared_scope_request_includes_selected_system_overview_without_active_context() {
    let fixture = Fixture::new();
    let selected = import_context(&fixture, SELECTED_OVERVIEW, false);
    let active = import_context(&fixture, ACTIVE_OVERVIEW, true);
    let runtime = OfflineScopeRuntime::new(draft());
    let mut input = fixture.input();
    input["threatModelRef"] = selected.clone();
    let output = fixture.dispatch(input, &runtime).unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let supplied: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    assert!(supplied["context"]["items"]
        .as_array()
        .unwrap()
        .contains(&json!({"field":"/systemContext", "value":SELECTED_OVERVIEW})));
    assert!(!requests[0].prompt.contains(ACTIVE_OVERVIEW));
    assert_eq!(
        output["data"]["record"]["generation"]["contextRef"],
        selected
    );
    let manifest =
        crate::capabilities::threat_model::load_threat_model_manifest(fixture.root.path())
            .unwrap()
            .unwrap();
    assert_eq!(serde_json::to_value(manifest.active).unwrap(), active);
    assert!(output["data"]["record"]["acceptance"].is_null());
}

#[test]
fn context_projection_retains_canonical_and_legacy_overviews_and_all_architecture_fields() {
    let fixture = Fixture::new();
    let (_, inventory) =
        current_inventory(&fixture.context(), &fixture.original.reference).unwrap();
    let context = json!({"systemContext":SELECTED_OVERVIEW,"contextSummary":"Legacy overview",
        "dfd":{"nodes":[],"flows":[],"trustBoundaries":[]},
        "attackSurface":{"entryPoints":[]},"privateUnrelatedField":"Not architecture input"});
    let outline = input::build(&inventory, &fixture.original, Some(&context), "").unwrap();
    assert_eq!(outline.document["context"]["total"], 6);
    assert_eq!(outline.document["context"]["omitted"], 0);
    assert!(outline.limitations[0].starts_with("Context sections: 6/6; omitted 0."));
    assert_eq!(
        outline.document["context"]["items"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert!(!serde_json::to_string(&outline.document)
        .unwrap()
        .contains("privateUnrelatedField"));
}

#[test]
fn oversized_system_overview_is_disclosed_as_omitted_within_existing_input_limit() {
    let fixture = Fixture::new();
    let (_, inventory) =
        current_inventory(&fixture.context(), &fixture.original.reference).unwrap();
    let context = json!({"systemContext":"bounded-overview".repeat(1024)});
    let outline = input::build(&inventory, &fixture.original, Some(&context), "").unwrap();
    assert_eq!(
        outline.document["context"],
        json!({"total":1,"omitted":1,"items":[]})
    );
    assert!(serde_json::to_vec(&outline.document).unwrap().len() <= input::MAX_PROMPT_BYTES);
    assert!(outline.limitations[0].starts_with("Context sections: 0/1; omitted 1."));
}

#[test]
fn explicitly_omitted_context_is_distinct_from_zero_supplied_sections() {
    let fixture = Fixture::new();
    let (_, inventory) =
        current_inventory(&fixture.context(), &fixture.original.reference).unwrap();
    let outline = input::build(&inventory, &fixture.original, None, "").unwrap();
    assert!(outline.document["context"].is_null());
    assert_eq!(outline.limitations[0], "Architecture context: omitted.");
}
