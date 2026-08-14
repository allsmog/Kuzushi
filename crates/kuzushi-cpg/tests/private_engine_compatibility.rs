#![cfg(feature = "private-engine")]

use kuzushi_cpg::{
    artifact_path, canonical_language, engine_available, ensure_project_in, harvest_spec,
    open_project_in, run_taint_query, supported_languages, validate_graph_artifact, BuildLimits,
    BuildScope, SignalSpec, GRAPH_SHAPE_VERSION,
};

const _: () = assert!(GRAPH_SHAPE_VERSION > 0);

#[test]
fn public_engine_builds_reopens_and_witnesses_a_taint_path() {
    assert!(
        engine_available(),
        "default builds must contain the public engine"
    );
    assert_eq!(canonical_language("ts"), Some("typescript"));
    assert!(supported_languages().contains(&"typescript"));

    let target = tempfile::tempdir().expect("create engine compatibility target");
    std::fs::write(
        target.path().join("users.ts"),
        "function list(req, res) {\n  const id = req.query.id;\n  db.query(\"SELECT \" + id);\n}\n",
    )
    .expect("write TypeScript compatibility fixture");

    let scope = BuildScope::whole(target.path());
    let (project, first) = ensure_project_in(&scope, "typescript", &BuildLimits::default())
        .expect("the pinned public engine must build a TypeScript graph");

    assert!(!first.reused_cache);
    assert_eq!(first.source_files, 1);
    assert!(
        first.methods > 0,
        "public graph must contain methods: {first:?}"
    );
    assert!(
        first.calls > 0,
        "public graph must contain calls: {first:?}"
    );
    assert!(
        first.nodes > 0,
        "public graph must contain nodes: {first:?}"
    );
    assert_eq!(first.cpg_path, artifact_path(target.path(), "typescript"));
    validate_graph_artifact(&first.cpg_path).expect("engine-produced graph must validate");

    let sources = vec!["req.query".to_string()];
    let sinks = vec![".query(".to_string()];
    let spec = SignalSpec {
        sources: &sources,
        sinks: &sinks,
        sanitizers: &[],
    };
    let harvested = harvest_spec(&project, &spec);
    assert!(
        harvested.source_call_matches > 0,
        "source harvest: {harvested:?}"
    );
    assert!(
        harvested.sink_call_matches > 0,
        "sink harvest: {harvested:?}"
    );

    let (findings, stats) = run_taint_query(&project, &harvested);
    assert!(
        stats.flow_count > 0,
        "public engine returned no flow: {stats:?}"
    );
    let flow = findings
        .first()
        .expect("flow count must have a first finding");
    assert!(
        flow.sink_file
            .as_deref()
            .is_some_and(|path| path.ends_with("users.ts")),
        "flow must retain its source artifact: {flow:?}"
    );
    assert!(
        !flow.path.is_empty(),
        "flow must carry a witnessed path: {flow:?}"
    );

    drop(project);
    let reopened = open_project_in(&scope, "typescript")
        .expect("the public adapter must reopen the real persisted graph");
    drop(reopened);

    let (_, second) = ensure_project_in(&scope, "typescript", &BuildLimits::default())
        .expect("a second build must reopen the compatible graph");
    assert!(
        second.reused_cache,
        "the compatible artifact must be reusable"
    );
    assert_eq!(second.methods, first.methods);
    assert_eq!(second.calls, first.calls);
    assert_eq!(second.nodes, first.nodes);
}
