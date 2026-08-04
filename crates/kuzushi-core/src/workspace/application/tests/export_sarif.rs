use super::*;
use crate::findings::Severity;

fn located_record(
    file: &str,
    start_line: u32,
    end_line: Option<u32>,
) -> WorkspaceFindingExportRecord {
    let finding = Finding::new_tool(
        "burp-har",
        "http-evidence",
        file,
        start_line,
        end_line,
        Severity::Info,
        "imported capture",
    );
    workspace_finding_export_records_with_reviews(&[finding], &[]).remove(0)
}

fn physical_location_of(file: &str, start_line: u32, end_line: Option<u32>) -> serde_json::Value {
    let record = located_record(file, start_line, end_line);
    sarif_result(&record)["locations"][0]["physicalLocation"].clone()
}

#[test]
fn absolute_url_location_drops_uri_base_id_and_unknown_line_region() {
    let physical = physical_location_of("https://api.lab.test/orders", 0, None);

    assert_eq!(
        physical["artifactLocation"]["uri"],
        "https://api.lab.test/orders"
    );
    assert!(physical["artifactLocation"].get("uriBaseId").is_none());
    assert!(physical.get("region").is_none());
}

#[test]
fn absolute_url_location_with_known_line_keeps_region_but_drops_uri_base_id() {
    let physical = physical_location_of("https://api.lab.test/orders", 7, None);

    assert_eq!(
        physical["artifactLocation"]["uri"],
        "https://api.lab.test/orders"
    );
    assert!(physical["artifactLocation"].get("uriBaseId").is_none());
    assert_eq!(physical["region"], json!({ "startLine": 7 }));
}

#[test]
fn relative_path_without_line_keeps_workspace_root_and_omits_region() {
    let physical = physical_location_of("Cargo.toml", 0, None);

    assert_eq!(physical["artifactLocation"]["uri"], "Cargo.toml");
    assert_eq!(physical["artifactLocation"]["uriBaseId"], "WORKSPACE_ROOT");
    assert!(physical.get("region").is_none());
}

#[test]
fn end_line_before_start_line_is_clamped_to_the_reported_start() {
    let physical = physical_location_of("src/app.ts", 5, Some(2));

    assert_eq!(physical["region"], json!({ "startLine": 5, "endLine": 5 }));
}

#[test]
fn zero_start_and_end_lines_emit_no_region_instead_of_an_inverted_one() {
    let physical = physical_location_of("src/app.ts", 0, Some(0));

    assert!(physical.get("region").is_none());
}

#[test]
fn known_line_range_keeps_region_and_workspace_root() {
    let physical = physical_location_of("src/app.ts", 10, Some(13));

    assert_eq!(physical["artifactLocation"]["uriBaseId"], "WORKSPACE_ROOT");
    assert_eq!(
        physical["region"],
        json!({ "startLine": 10, "endLine": 13 })
    );
}

#[test]
fn uri_scheme_detection_ignores_relative_and_windows_paths() {
    assert!(has_uri_scheme("https://api.lab.test/orders"));
    assert!(has_uri_scheme("ws://localhost:8080/socket"));
    assert!(!has_uri_scheme("src/main.rs"));
    assert!(!has_uri_scheme("C:\\Users\\dev\\app.rs"));
    assert!(!has_uri_scheme("C://Users/dev/app.rs"));
    assert!(!has_uri_scheme("docs/notes?q=a://b"));
}
