use super::*;

fn map_for(text: &str) -> AttackSurfaceMap {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("lib.rs"), text).unwrap();
    build_attack_surface_map(root.path()).unwrap()
}

#[test]
fn rust_unit_test_parsers_do_not_become_production_surfaces() {
    let map = map_for(
        r#"
fn decode(input: &str) { serde_json::from_str::<String>(input); }
#[cfg(test)]
mod tests {
    #[test]
    fn serde_normalizes_legacy_phase_aliases() {
        serde_json::from_str::<ToolPhase>("\"hunt\"").unwrap();
        serde_json::from_str::<ToolPhase>("\"confirm\"").unwrap();
    }
}
#[test] fn another_example() { serde_yaml::from_str::<String>("literal"); }
"#,
    );
    let parsers: Vec<_> = map
        .surfaces
        .iter()
        .filter(|row| row.kind == AttackSurfaceKind::DeserializationPoint)
        .collect();
    assert_eq!(parsers.len(), 1, "{parsers:#?}");
    assert_eq!(parsers[0].line, Some(2));
    assert!(parsers[0].evidence.contains("(input)"));
}

#[test]
fn rust_test_only_routes_are_excluded_from_inventory_and_surface_map() {
    let text = r#"
use rocket::get;
#[get("/production")]
fn production() {}
#[cfg(test)] mod tests {
    #[get("/test-only")]
    fn test_route() {}
}
"#;
    let map = map_for(text);
    assert!(map
        .surfaces
        .iter()
        .any(|row| row.route.as_deref() == Some("/production")));
    assert!(!map
        .surfaces
        .iter()
        .any(|row| row.route.as_deref() == Some("/test-only")));
}

#[test]
fn rust_test_only_tauri_commands_do_not_enter_the_catalog() {
    let map = map_for(
        r#"
#[tauri::command] fn production() {}
#[cfg(test)] mod tests {
    #[tauri::command] fn test_command() {}
    fn run() { tauri::Builder::default().invoke_handler(tauri::generate_handler![test_command]); }
}

fn run() { tauri::Builder::default().invoke_handler(tauri::generate_handler![production]); }
"#,
    );
    let commands: Vec<_> = map
        .surfaces
        .iter()
        .filter(|row| row.metadata["detector"] == "rust.tauri-command")
        .collect();
    assert_eq!(commands.len(), 1, "{commands:#?}");
    assert!(commands[0].evidence.contains("production"));
}

#[test]
fn extraction_policy_does_not_rename_an_unchanged_production_surface() {
    let map = map_for("fn decode(input: &str) { serde_json::from_str::<String>(input); }");
    let mut row = map.surfaces[0].clone();
    let id = attack_surface_id(&row);
    row.metadata.as_object_mut().unwrap().remove("sourcePolicy");
    assert_eq!(attack_surface_id(&row), id);
    row.metadata["detector"] = json!("different-detector");
    assert_ne!(attack_surface_id(&row), id);
}

#[test]
fn nonobject_metadata_keeps_identity_and_cannot_claim_current_rust_extraction() {
    for metadata in [Value::Null, json!("legacy metadata")] {
        let mut row = map_for("fn decode() { serde_json::from_str::<String>(input); }")
            .surfaces
            .remove(0);
        row.metadata = metadata.clone();
        row.id = attack_surface_id(&row);
        let mut builder = AttackSurfaceBuilder::default();
        builder.surfaces.insert(row.id.clone(), row.clone());
        let finished = builder.finish("source".to_string());
        assert_eq!(finished.surfaces[0].metadata, metadata);
        assert_eq!(
            finished.surfaces[0].id,
            attack_surface_id(&finished.surfaces[0])
        );
        assert!(
            crate::workspace::rust_surface_policy::has_legacy_rust_surface(
                "Rust", "lib.rs", &metadata
            )
        );
    }
}
