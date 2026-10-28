use super::*;

fn prepared(fixture: &Fixture, paths: Value) -> Value {
    let mut input = fixture.input();
    input["sourceEvidenceFiles"] = paths;
    let canonical = fixture
        .registry
        .prepare_dispatch_input("findings:lesson-generate", input, &fixture.context(), None)
        .unwrap()
        .value()
        .clone();
    prepare_generation_input(&canonical, &fixture.context()).unwrap()
}

#[test]
fn supporting_lesson_source_survives_checkout_changes_and_reopening() {
    let fixture = Fixture::with_sources(&[
        ("service.txt", b"Historical service\n"),
        ("policy.txt", b"Historical policy\n"),
    ]);
    let input = prepared(&fixture, json!(["service.txt", "hello.txt", "policy.txt"]));
    let reference = input["sourceEvidenceRef"].as_str().unwrap().to_string();
    let frozen =
        crate::workspace::read_lesson_source_evidence(fixture.root.path(), &reference).unwrap();
    std::fs::write(fixture.root.path().join("service.txt"), "CURRENT_ONLY\n").unwrap();
    std::fs::remove_file(fixture.root.path().join("policy.txt")).unwrap();
    fixture.approve(2);
    let runtime = OfflineRuntime::new();
    let result = fixture
        .dispatch("findings:lesson-generate", input, Some(&runtime), true)
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let payload: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    assert_eq!(payload["supportingSources"].as_array().unwrap().len(), 2);
    assert_eq!(
        payload["supportingSources"][0]["text"],
        "Historical service\n"
    );
    assert_eq!(
        payload["supportingSources"][1]["text"],
        "Historical policy\n"
    );
    assert!(!requests[0].prompt.contains("CURRENT_ONLY"));
    assert_eq!(
        result["data"]["lesson"]["generation"]["sourceEvidenceRef"],
        reference
    );
    assert_eq!(result["data"]["lesson"]["state"], "draft");
    assert_eq!(
        crate::workspace::read_lesson_source_evidence(fixture.root.path(), &reference).unwrap(),
        frozen
    );
    assert_eq!(fixture.store.list_all_review_decisions().unwrap().len(), 1);
}

#[test]
fn historical_supporting_files_share_one_limit_and_disclose_omissions() {
    let fixture = Fixture::with_sources(&[
        ("first.txt", &[b'a'; 900]),
        ("second.txt", &[b'b'; 900]),
        ("binary.txt", &[0xff, 0]),
        ("tail.txt", b"Tail\n"),
    ]);
    let mut input = prepared(
        &fixture,
        json!([
            "first.txt",
            "second.txt",
            "binary.txt",
            "missing.txt",
            "tail.txt"
        ]),
    );
    input["maxSourceBytes"] = json!(1024);
    input.as_object_mut().unwrap().remove("sourceEvidenceRef");
    let input = prepare_generation_input(&input, &fixture.context()).unwrap();
    let origin = selected_origin(&input, &fixture.context()).unwrap();
    let (bundle, _) = sources::load(&input, &origin, &fixture.context()).unwrap();
    let states: Vec<_> = bundle
        .supporting
        .iter()
        .map(|file| file["status"].as_str().unwrap())
        .collect();
    assert_eq!(
        states,
        [
            "included",
            "unavailable_or_over_limit",
            "unavailable_or_over_limit",
            "not_recorded",
            "included"
        ]
    );
    let total = bundle.primary["text"].as_str().unwrap().len()
        + bundle
            .supporting
            .iter()
            .filter_map(|file| file["text"].as_str())
            .map(str::len)
            .sum::<usize>();
    assert!(total <= 1024);
    assert!(bundle
        .supporting
        .iter()
        .all(|file| file["currentSourceRead"] == false));
    assert!(fixture
        .store
        .finding_lessons(50, 0)
        .unwrap()
        .rows
        .is_empty());
}

#[test]
fn changed_selection_or_limit_cannot_reuse_an_approved_source_bundle() {
    let fixture =
        Fixture::with_sources(&[("service.txt", b"Service\n"), ("policy.txt", b"Policy\n")]);
    let input = prepared(&fixture, json!(["service.txt", "policy.txt"]));
    fixture.approve(2);
    let runtime = OfflineRuntime::new();
    for (key, value) in [
        ("sourceEvidenceFiles", json!(["policy.txt", "service.txt"])),
        ("maxSourceBytes", json!(1024)),
        (
            "sourceEvidenceRef",
            json!(format!("lesson-source:{}", "0".repeat(64))),
        ),
    ] {
        let mut changed = input.clone();
        changed[key] = value;
        assert!(fixture
            .dispatch("findings:lesson-generate", changed, Some(&runtime), true)
            .is_err());
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
    assert!(fixture
        .store
        .finding_lessons(50, 0)
        .unwrap()
        .rows
        .is_empty());
    fixture
        .dispatch("findings:lesson-generate", input, Some(&runtime), true)
        .unwrap();
    assert_eq!(runtime.requests.lock().unwrap().len(), 1);
}

#[test]
fn invalid_lesson_supporting_paths_fail_before_a_provider_request() {
    let fixture = Fixture::new();
    fixture.approve(2);
    let runtime = OfflineRuntime::new();
    let mut invalid = vec![
        json!(["../secret"]),
        json!(["/secret"]),
        json!(["./file"]),
        json!(["a//b"]),
        json!(["a\\b"]),
        json!(["file\u{1b}"]),
        json!(["same", "same"]),
    ];
    invalid.push(json!((0..17)
        .map(|index| format!("file{index}"))
        .collect::<Vec<_>>()));
    for paths in invalid {
        let mut input = fixture.input();
        input["sourceEvidenceFiles"] = paths;
        assert!(fixture
            .dispatch("findings:lesson-generate", input, Some(&runtime), true)
            .is_err());
    }
    assert!(runtime.requests.lock().unwrap().is_empty());
}

#[test]
fn missing_historical_blob_never_falls_back_to_a_present_checkout_file() {
    let fixture = Fixture::with_sources(&[("service.txt", b"Original service\n")]);
    let input = prepared(&fixture, json!(["service.txt"]));
    let doc = crate::workspace::read_lesson_source_evidence(
        fixture.root.path(),
        input["sourceEvidenceRef"].as_str().unwrap(),
    )
    .unwrap();
    let hash =
        crate::identity::Blake3Hash::new(doc["supporting"][0]["blobHash"].as_str().unwrap().into())
            .unwrap();
    let objects =
        crate::content_store::ContentStore::open(fixture.workspace.objects_dir()).unwrap();
    std::fs::remove_file(objects.object_path(&hash)).unwrap();
    std::fs::write(fixture.root.path().join("service.txt"), "PRESENT_CURRENT\n").unwrap();
    let mut fresh = input.clone();
    fresh.as_object_mut().unwrap().remove("sourceEvidenceRef");
    let origin = selected_origin(&fresh, &fixture.context()).unwrap();
    let (bundle, _) = sources::load(&fresh, &origin, &fixture.context()).unwrap();
    assert_eq!(bundle.supporting[0]["status"], "unavailable_or_over_limit");
    assert!(bundle.supporting[0]["text"].is_null());
    assert!(validate_generation_input(&input, &fixture.context()).is_err());
}

#[test]
fn a_pruned_repository_tree_discloses_unavailable_membership() {
    let fixture = Fixture::with_sources(&[("service.txt", b"Historical service\n")]);
    let mut input = prepared(&fixture, json!(["service.txt"]));
    let origin = selected_origin(&input, &fixture.context()).unwrap();
    let hash = fixture
        .store
        .lesson_source_tree_hash(&origin)
        .unwrap()
        .unwrap();
    let objects =
        crate::content_store::ContentStore::open(fixture.workspace.objects_dir()).unwrap();
    std::fs::remove_file(objects.object_path(&crate::identity::Blake3Hash::new(hash).unwrap()))
        .unwrap();
    input.as_object_mut().unwrap().remove("sourceEvidenceRef");
    let (bundle, _) = sources::load(&input, &origin, &fixture.context()).unwrap();
    assert_eq!(bundle.supporting[0]["status"], "not_recorded");
    assert!(bundle.supporting[0]["text"].is_null());
    assert_eq!(bundle.primary["status"], "included");
}

#[test]
fn a_pruned_cited_blob_directory_does_not_read_current_source() {
    let fixture = Fixture::new();
    let origin = fixture
        .store
        .lesson_origin(fixture.root.path(), fixture.id)
        .unwrap();
    let (_, hash) = fixture
        .store
        .observed_file_identity_at(&origin.finding.stable_key, origin.observation_seq)
        .unwrap()
        .unwrap();
    let objects =
        crate::content_store::ContentStore::open(fixture.workspace.objects_dir()).unwrap();
    let path = objects.object_path(&crate::identity::Blake3Hash::new(hash).unwrap());
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(fixture.root.path().join("hello.txt"), "CURRENT_ONLY\n").unwrap();
    fixture.approve(2);
    let runtime = OfflineRuntime::new();
    fixture
        .dispatch(
            "findings:lesson-generate",
            fixture.input(),
            Some(&runtime),
            true,
        )
        .unwrap();
    let requests = runtime.requests.lock().unwrap();
    let payload: Value = serde_json::from_str(&requests[0].prompt).unwrap();
    assert_eq!(
        payload["capturedSource"]["status"],
        "unavailable_or_over_limit"
    );
    assert!(payload["capturedSource"]["text"].is_null());
    assert!(!requests[0].prompt.contains("CURRENT_ONLY"));
}
