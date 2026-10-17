use super::*;
use crate::modules::ModuleRegistry;

const TOOL: &str = "systems-hunt:systems-context-gatherer";

fn dispatch(
    root: &Path,
    input: Value,
    cancellation: Option<&crate::scan::ScanCancellation>,
) -> Result<Value> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let prepared = registry
        .prepare_dispatch_input(TOOL, input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn source(root: &Path, name: &str, text: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn receipt(output: &Value) -> &Value {
    &output["data"]["metadata"]["inspection"]
}

#[test]
fn real_dispatch_is_auxiliary_read_only_map_without_runtime_or_store() {
    let root = tempfile::tempdir().unwrap();
    source(
        root.path(),
        "loose root.c",
        "// Owned parser packet length metadata. Never executed.\n",
    );
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["surfaces"][0]["filePath"], "loose root.c");
    assert_eq!(receipt(&result)["codeIndex"], "not_requested");
    assert_eq!(receipt(&result)["codeqlInspection"], "not_requested");
    assert_eq!(receipt(&result)["completeRepositoryCoverage"], false);
    assert_eq!(result["costUsd"], 0.0);
    assert!(!root.path().join(".kuzushi/cpg-rs").exists());
    assert!(!root.path().join(".kuzushi/systems-hunt").exists());
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let tool = registry.resolve_tool(TOOL).unwrap();
    assert!(tool.hidden);
    assert!(!tool.phase_result);
    assert_eq!(
        tool.runtime_requirement,
        crate::modules::RuntimeRequirement::Never
    );
    assert_eq!(tool.phase, crate::modules::ToolPhase::Map);
    assert_eq!(tool.effect, crate::modules::ToolEffect::Read);
    assert_eq!(
        tool.finding_store_requirement,
        crate::modules::FindingStoreRequirement::Optional
    );
}

#[test]
fn source_and_surface_limits_produce_partial_usable_context() {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.c", "b.c", "c.c"] {
        source(root.path(), name, "// parser packet length\n");
    }
    let result = dispatch(root.path(), json!({"maxFiles":2,"maxSurfaces":1}), None).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(receipt(&result)["omittedSourceFiles"], 1);
    assert_eq!(receipt(&result)["omittedSurfaces"], 1);
    assert_eq!(result["data"]["surfacePacks"].as_array().unwrap().len(), 1);
    assert!(!result["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn aggregate_bytes_and_file_prefixes_are_honest() {
    let root = tempfile::tempdir().unwrap();
    source(root.path(), "a.c", &"// parser length\n".repeat(20));
    source(root.path(), "b.c", "// packet parser\n");
    let result = dispatch(
        root.path(),
        json!({"max_source_bytes":16,"head_bytes":8}),
        None,
    )
    .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(receipt(&result)["inspectedSourceBytes"], 16);
    assert_eq!(receipt(&result)["truncatedSourceFiles"], 2);
    assert_eq!(receipt(&result)["maxFileBytes"], 8);
}

#[test]
fn test_sources_are_included_only_by_explicit_option() {
    let root = tempfile::tempdir().unwrap();
    for name in [
        "root.c",
        "examples/example.c",
        "tests/parser.c",
        "src/parser_test.c",
        "vendor/ignored.c",
    ] {
        source(root.path(), name, "// parser packet length\n");
    }
    let default = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(default["data"]["metadata"]["systemsSourceFiles"], 1);
    let included = dispatch(root.path(), json!({"include_non_production":true}), None).unwrap();
    assert_eq!(included["data"]["metadata"]["systemsSourceFiles"], 4);
    assert!(included["data"]["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["filePath"] != "vendor/ignored.c"));
}

#[test]
fn invalid_limits_and_unused_legacy_options_fail_through_preparation() {
    let root = tempfile::tempdir().unwrap();
    for input in [
        json!({"maxFiles":0}),
        json!({"headBytes":262145}),
        json!({"maxSurfaces":1001}),
        json!({"maxSourceBytes":536870913}),
        json!({"max_files":-1}),
        json!({"headBytes":"invalid"}),
        json!({"model":"openai:unused"}),
        json!({"systems_context":{}}),
        json!({"maxFindings":1}),
        json!({"SYSTEMS_TRIGGER_PROMPT":"unused"}),
        json!({"inventedOption":true}),
    ] {
        assert!(
            dispatch(root.path(), input.clone(), None).is_err(),
            "{input}"
        );
    }
    assert!(!root.path().join(".kuzushi/systems-hunt").exists());
}

#[test]
fn evidence_and_pack_sites_are_capped_during_collection() {
    let root = tempfile::tempdir().unwrap();
    let text = "// parser packet length shared guard\n".repeat(50);
    source(root.path(), "a.c", &text);
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(receipt(&result)["evidenceLimitedFiles"], 1);
    assert_eq!(receipt(&result)["siteLimitedPacks"], 1);
    assert_eq!(
        result["data"]["surfaces"][0]["evidence"]
            .as_array()
            .unwrap()
            .len(),
        12
    );
    assert_eq!(
        result["data"]["surfacePacks"][0]["inputSites"]
            .as_array()
            .unwrap()
            .len(),
        12
    );
    assert_eq!(fs::read_to_string(root.path().join("a.c")).unwrap(), text);
}

#[test]
fn unicode_signal_lines_are_not_sliced_at_byte_boundaries() {
    let root = tempfile::tempdir().unwrap();
    source(
        root.path(),
        "unicode.rs",
        &format!("// guard {} parser", "é".repeat(240)),
    );
    let result = dispatch(root.path(), json!({}), None).unwrap();
    let evidence = result["data"]["surfaces"][0]["evidence"][0]["lineContent"]
        .as_str()
        .unwrap();
    assert_eq!(evidence.chars().count(), 240);
}

#[test]
fn actual_lean_handoff_preserves_coverage_and_source_markers() {
    let root = tempfile::tempdir().unwrap();
    source(root.path(), "src/parser.c", "// packet length parser\n");
    let result = dispatch(root.path(), json!({"headBytes":12}), None).unwrap();
    let context: SystemsContextOutput = serde_json::from_value(result["data"].clone()).unwrap();
    let payload: Value = serde_json::from_str(&lean_prompt_payload(&context).unwrap()).unwrap();
    assert_eq!(payload["metadata"]["inspection"], *receipt(&result));
    assert_eq!(payload["surfaces"][0]["filePath"], "src/parser.c");
    assert_eq!(payload["surfaces"][0]["evidence"][0]["lineNumber"], 1);
    assert!(payload.get("surfacePacks").is_none());
    assert!(payload["surfaces"][0]["evidence"][0]
        .get("lineContent")
        .is_none());
}

#[test]
fn legacy_context_without_inspection_still_deserializes() {
    let value = json!({"surfaces":[],"surfacePacks":[],"metadata":{
        "codeqlAvailable":false,"bashProbingUsed":false,"systemsSourceFiles":0}});
    let context: SystemsContextOutput = serde_json::from_value(value).unwrap();
    assert!(context.metadata.inspection.is_none());
}

#[test]
fn cancellation_does_not_start_an_index_or_create_context_artifacts() {
    let root = tempfile::tempdir().unwrap();
    source(root.path(), "parser.c", "// parser packet\n");
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    assert!(dispatch(root.path(), json!({}), Some(&cancellation)).is_err());
    assert!(!root.path().join(".kuzushi/cpg-rs").exists());
    assert!(!root.path().join(".kuzushi/systems-hunt").exists());
}

#[cfg(unix)]
#[test]
fn deep_tree_and_symlink_cycle_preserve_loose_files_without_following_links() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    source(outside.path(), "outside.c", "// outside parser\n");
    source(root.path(), "loose.c", "// parser packet\n");
    let nested = format!("{}deep.c", "d/".repeat(120));
    source(root.path(), &nested, "// parser length\n");
    symlink(root.path(), root.path().join("cycle")).unwrap();
    symlink(
        outside.path().join("outside.c"),
        root.path().join("outside.c"),
    )
    .unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["data"]["metadata"]["systemsSourceFiles"], 2);
    assert!(result["data"]["surfaces"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["filePath"] == nested));
}

#[test]
fn binary_omission_is_partial_instead_of_an_empty_success() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("binary.c"), b"\0parser packet").unwrap();
    let result = dispatch(root.path(), json!({}), None).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(receipt(&result)["omittedSourceFiles"], 1);
    assert_eq!(result["data"]["metadata"]["systemsSourceFiles"], 0);
    assert_eq!(result["data"]["surfaces"], json!([]));
}

#[test]
fn explicit_child_target_cannot_escape_the_prepared_workspace() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    source(root.path(), "child/parser.c", "// child parser packet\n");
    source(root.path(), "parent.c", "// parent parser packet\n");
    let child = dispatch(root.path(), json!({"target":"child"}), None).unwrap();
    assert_eq!(child["data"]["metadata"]["systemsSourceFiles"], 1);
    assert_eq!(child["data"]["surfaces"][0]["filePath"], "parser.c");
    assert!(dispatch(root.path(), json!({"target":outside.path()}), None).is_err());
    assert!(dispatch(root.path(), json!({"target":"../outside"}), None).is_err());
}

#[test]
fn ranking_observes_cancellation_between_inspected_files() {
    let prefixes = crate::workspace::inventory::SourcePrefixes {
        files: vec![SourcePrefix {
            relative: "parser.c".into(),
            text: "// parser packet\n".into(),
        }],
        coverage: json!({}),
    };
    let error = ranking::context_output(prefixes, 1, &|| true).unwrap_err();
    assert!(error.to_string().contains("canceled"));
}
