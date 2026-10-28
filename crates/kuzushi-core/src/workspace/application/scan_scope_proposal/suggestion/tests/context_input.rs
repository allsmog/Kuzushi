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
    let outline = input::build(&inventory, &fixture.original, Some(&context), "", None).unwrap();
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
    let outline = input::build(&inventory, &fixture.original, Some(&context), "", None).unwrap();
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
    let outline = input::build(&inventory, &fixture.original, None, "", None).unwrap();
    assert!(outline.document["context"].is_null());
    assert_eq!(outline.limitations[0], "Architecture context: omitted.");
}

#[test]
fn prepared_structural_file_selection_supplies_late_root_and_directory_examples() {
    let mut fixture = Fixture::new();
    for directory in ["a/component", "z/component"] {
        let directory = fixture.root.path().join(directory);
        std::fs::create_dir_all(&directory).unwrap();
        for index in 0..300 {
            std::fs::write(
                directory.join(format!("unit_{index:03}.py")),
                "# Owned input fixture\n",
            )
            .unwrap();
        }
    }
    std::fs::write(fixture.root.path().join("workspace.json"), "{}\n").unwrap();
    fixture.original = create_scan_scope_proposal(&fixture.context(), None).unwrap();
    let mut request = fixture.input();
    request["fileSelection"] = json!("root-balanced-v1");
    let runtime = OfflineScopeRuntime::new(draft());
    let output = fixture.dispatch(request, &runtime).unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let prompt: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    let names = prompt["files"]["items"].as_array().unwrap();
    assert!(names.contains(&json!("workspace.json")));
    assert!(names.contains(&json!("z/component/unit_000.py")));
    assert!(names.len() <= 512);
    assert!(serde_json::to_vec(names).unwrap().len() <= 16_384);
    assert!(output["data"]["record"]["acceptance"].is_null());
}
