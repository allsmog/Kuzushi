use super::*;

fn catalog_from_source(
    text: &str,
) -> (
    tempfile::TempDir,
    crate::capabilities::entry_points::EntryPointCatalog,
) {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("lib.rs"), text).unwrap();
    crate::modules::context::build_context_snapshot_for_root(target.path(), 20).unwrap();
    let (catalog, _) =
        crate::capabilities::entry_points::refresh_entry_point_catalog(target.path()).unwrap();
    (target, catalog)
}

#[test]
fn real_descriptor_unit_examples_are_absent_from_catalog_and_prompt_grounding() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../kuzushi-descriptor/src/tool_phase.rs"
    ));
    assert!(source.contains("serde_normalizes_legacy_phase_aliases"));
    let (target, catalog) = catalog_from_source(source);
    assert_eq!(catalog.total, 0, "{:#?}", catalog.entry_points);
    let (selected, count) = prompt_grounding_surfaces(target.path(), 30, Some(&catalog)).unwrap();
    assert_eq!(count, 0);
    assert!(!selected
        .iter()
        .any(|row| row.kind == AttackSurfaceKind::DeserializationPoint));
    let snapshot =
        std::fs::read_to_string(crate::context::context_snapshot_path(target.path())).unwrap();
    let snapshot: Value = serde_json::from_str(&snapshot).unwrap();
    assert!(crate::context::context_snapshot_freshness(target.path(), &snapshot).is_current());
}

#[test]
fn production_parser_survives_the_same_context_catalog_and_grounding_boundaries() {
    let (target, catalog) = catalog_from_source(
        r#"
fn parse_request(input: &str) { serde_json::from_str::<String>(input); }
#[cfg(test)] mod tests { fn example() { serde_json::from_str::<String>("example"); } }
"#,
    );
    assert_eq!(catalog.total, 1);
    let (selected, count) = prompt_grounding_surfaces(target.path(), 30, Some(&catalog)).unwrap();
    assert_eq!(count, 1);
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].id, catalog.entry_points[0].surface.id);
    assert_eq!(selected[0].line, Some(2));
    assert!(selected[0].evidence.contains("parse_request"));
    assert_eq!(selected[0].metadata["sourcePolicy"], "rust-test-scopes-v1");
}
