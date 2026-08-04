use super::*;

#[test]
fn associates_tauri_attributes_with_async_and_visible_function_symbols() {
    let commands = tauri_command_functions(
        r#"#[tauri::command]
pub async fn load_packet(id: String) -> Result<(), String> { Ok(()) }

#[tauri::command(rename_all = "snake_case")]
pub(crate) fn save_packet() {}
"#,
    );

    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].name, "load_packet");
    assert_eq!(commands[0].function_line, 2);
    assert_eq!(commands[1].name, "save_packet");
    assert_eq!(commands[1].function_line, 5);
}

#[test]
fn associates_bounded_multiline_headers_and_same_line_attributes() {
    let commands = tauri_command_functions(
        r#"#[tauri::command]
pub async
fn load_packet(id: String) {}

#[tauri::command] pub(crate) unsafe fn save_packet() {}
"#,
    );

    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].name, "load_packet");
    assert_eq!(commands[0].function_line, 3);
    assert_eq!(commands[0].evidence, "fn load_packet(id: String) {}");
    assert_eq!(commands[1].name, "save_packet");
    assert_eq!(commands[1].function_line, 5);
}

#[test]
fn preserves_cfg_exclusive_implementation_identity() {
    let source = r#"#[tauri::command]
#[cfg(debug_assertions)]
pub fn credential_status() {}

#[cfg(feature = "packaged")]
#[tauri::command]
pub fn credential_status() {}

fn setup() {
    tauri::Builder::default().invoke_handler(
        tauri::generate_handler![credential_status],
    );
}
"#;
    let commands = tauri_command_functions(source);

    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].name, commands[1].name);
    assert_eq!(commands[0].cfg_predicates, ["debug_assertions"]);
    assert_eq!(commands[1].cfg_predicates, ["feature = \"packaged\""]);
    assert!(commands[0].evidence.contains("[cfg: debug_assertions]"));
    assert!(commands[1]
        .evidence
        .contains("[cfg: feature = \"packaged\"]"));

    let source_file = InventorySourceFile {
        path: "src/lib.rs".to_string(),
        language: "Rust".to_string(),
    };
    let mut catalog = TauriCommandCatalog::default();
    inspect_rust_tauri_commands(&source_file, source, &mut catalog);
    let mut builder = AttackSurfaceBuilder::default();
    catalog.add_registered_surfaces(&mut builder);
    let map = builder.finish("fixture".to_string());
    let first = &map.surfaces[0];
    let second = &map.surfaces[1];
    assert_ne!(first.id, second.id);
    assert_eq!(first.metadata["cfgPredicates"], json!(["debug_assertions"]));
    assert_eq!(
        second.metadata["cfgPredicates"],
        json!(["feature = \"packaged\""])
    );
}

#[test]
fn extracts_multiline_qualified_and_bare_handler_registrations() {
    let handlers = registered_tauri_handlers(
        r#"fn setup() {
    tauri::Builder::default().invoke_handler(
        tauri::generate_handler![
            crate::commands::load_packet,
            local_status,
        ],
    );
}"#,
    );

    assert_eq!(handlers.len(), 2);
    assert_eq!(handlers[0].path, "crate::commands::load_packet");
    assert_eq!(handlers[0].logical_name, "load_packet");
    assert_eq!(handlers[0].line, 4);
    assert_eq!(handlers[1].path, "local_status");
    assert_eq!(handlers[1].line, 5);
}

#[test]
fn ignores_generate_handler_macros_not_directly_used_by_invoke_handler() {
    let handlers = registered_tauri_handlers(
        r####"const EXAMPLE: &str = "invoke_handler(tauri::generate_handler![string_only])";
// builder.invoke_handler(tauri::generate_handler![comment_only]);
let handler = tauri::generate_handler![indirect];
builder.invoke_handler(handler);
builder.invoke_handler(wrap(tauri::generate_handler![nested]));
"####,
    );

    assert!(handlers.is_empty());
}

#[test]
fn registration_reference_limit_fails_closed() {
    let entries = (0..=registration::MAX_REGISTRATION_REFERENCES_PER_FILE)
        .map(|index| format!("handler_{index}"))
        .collect::<Vec<_>>()
        .join(",");
    let source = format!(
        "builder.invoke_handler(tauri::generate_handler![{entries}]);"
    );

    assert!(registered_tauri_handlers(&source).is_empty());
}

#[test]
fn skips_multiline_attributes_comments_and_additional_attributes() {
    let commands = tauri_command_functions(
        r#"#[tauri::command(
    rename_all = "snake_case"
)]
/// Loads a packet from native state.
#[tracing::instrument(skip(state))]
// The command remains grounded on this declaration.
pub(super) async fn load_packet(state: State) {}
"#,
    );

    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].attribute_line, 1);
    assert_eq!(commands[0].function_line, 7);
    assert_eq!(commands[0].name, "load_packet");
}

#[test]
fn orphan_tauri_attribute_does_not_bind_past_another_item() {
    let commands = tauri_command_functions(
        r#"#[tauri::command]
const COMMAND_NAME: &str = "orphan";

fn helper() {}
"#,
    );

    assert!(commands.is_empty());
}

#[test]
fn similarly_prefixed_attributes_are_not_tauri_commands() {
    let commands = tauri_command_functions(
        r#"#[tauri::commanding]
fn commanding() {}

#[tauri::command_helper]
fn helper() {}
"#,
    );

    assert!(commands.is_empty());
}

#[test]
fn raw_identifier_spelling_is_preserved_as_the_grounded_symbol() {
    let commands = tauri_command_functions(
        r#"#[tauri::command]
pub fn r#type() {}
"#,
    );

    assert_eq!(commands[0].name, "r#type");
}

#[test]
fn ignores_tauri_command_examples_inside_strings_and_block_comments() {
    let commands = tauri_command_functions(
        r####"const RAW_FIXTURE: &str = r#"
#[tauri::command]
fn raw_fixture() {}
"#;

const STRING_FIXTURE: &str = "
#[tauri::command]
fn string_fixture() {}
";

/*
#[tauri::command]
fn commented_fixture() {}
*/

#[tauri::command]
fn real_command() {}
"####,
    );

    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].name, "real_command");
    assert_eq!(commands[0].function_line, 17);
}

#[test]
fn quote_char_literals_do_not_mask_following_commands() {
    let commands = tauri_command_functions(
        r####"const QUOTE: char = '"';
const BYTE_QUOTE: u8 = b'"';
const ESCAPED_QUOTE: char = '\'';

#[tauri::command]
fn real_command() {}
"####,
    );

    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].name, "real_command");
    assert_eq!(commands[0].function_line, 6);
}

#[test]
fn item_header_scan_is_bounded_before_a_later_function() {
    let padding = "\n".repeat(ITEM_HEADER_LINE_LIMIT + 1);
    let source = format!("#[tauri::command]{padding}fn too_far() {{}}");

    assert!(tauri_command_functions(&source).is_empty());
}
