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
fn opaque_absolute_uri_drops_uri_base_id() {
    let physical = physical_location_of("urn:cwe:79", 0, None);

    assert_eq!(physical["artifactLocation"]["uri"], "urn:cwe:79");
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
fn uri_scheme_detection_accepts_hierarchical_and_opaque_uris() {
    assert!(has_uri_scheme("https://api.lab.test/orders"));
    assert!(has_uri_scheme("ws://localhost:8080/socket"));
    assert!(has_uri_scheme("urn:cwe:79"));
    assert!(has_uri_scheme("data:text/plain,hello"));
    assert!(has_uri_scheme("file:/tmp/report"));
    assert!(has_uri_scheme("x:opaque"));
}

#[test]
fn uri_scheme_detection_ignores_relative_invalid_and_windows_paths() {
    assert!(!has_uri_scheme("src/main.rs"));
    assert!(!has_uri_scheme("C:\\Users\\dev\\app.rs"));
    assert!(!has_uri_scheme("C://Users/dev/app.rs"));
    assert!(!has_uri_scheme("C:/Users/dev/app.rs"));
    assert!(!has_uri_scheme("C:Users\\dev\\app.rs"));
    assert!(!has_uri_scheme("docs/notes?q=a://b"));
    assert!(!has_uri_scheme("1bad:value"));
    assert!(!has_uri_scheme(":missing"));
    assert!(!has_uri_scheme("bad_scheme:value"));
}

#[test]
fn ordinary_relative_paths_reach_sarif_unchanged() {
    // The encoder must not churn the paths every existing export already emits.
    assert_eq!(relative_uri_reference("src/main.rs"), "src/main.rs");
    assert_eq!(
        relative_uri_reference("crates/kuzushi-core/src/lib.rs"),
        "crates/kuzushi-core/src/lib.rs"
    );
}

#[test]
fn relative_paths_needing_escapes_become_valid_uri_references() {
    assert_eq!(
        relative_uri_reference("docs/My Notes.md"),
        "docs/My%20Notes.md"
    );
    assert_eq!(relative_uri_reference("src/a#b%c.rs"), "src/a%23b%25c.rs");
    assert_eq!(relative_uri_reference("src/caf\u{e9}.rs"), "src/caf%C3%A9.rs");
    assert_eq!(relative_uri_reference("src?q=1.rs"), "src%3Fq%3D1.rs");
}

#[test]
fn a_backslash_is_escaped_rather_than_read_as_a_separator() {
    // On Unix `\` is an ordinary filename character and `secret_relative_path`
    // preserves it verbatim, so splitting on it would aim the consumer at a
    // path that does not exist. `%5C` decodes back to the reported name.
    assert_eq!(relative_uri_reference(r"src/a\b.rs"), "src/a%5Cb.rs");
    assert_eq!(
        relative_uri_reference(r"src\app\main.rs"),
        "src%5Capp%5Cmain.rs"
    );
    // A drive-letter path is not a URI scheme (`has_uri_scheme` rejects it), so
    // the colon is escaped rather than left to look like one.
    assert_eq!(
        relative_uri_reference(r"C:\work dir\a.rs"),
        "C%3A%5Cwork%20dir%5Ca.rs"
    );
}

#[test]
fn a_space_in_a_path_survives_the_full_result_location() {
    let physical = physical_location_of("docs/My Notes.md", 3, None);

    assert_eq!(physical["artifactLocation"]["uri"], "docs/My%20Notes.md");
    assert_eq!(physical["artifactLocation"]["uriBaseId"], "WORKSPACE_ROOT");
}

#[test]
fn absolute_uri_locations_are_not_re_encoded() {
    let physical = physical_location_of("https://api.lab.test/orders?id=1#f", 0, None);

    assert_eq!(
        physical["artifactLocation"]["uri"],
        "https://api.lab.test/orders?id=1#f"
    );
}

#[test]
fn workspace_root_base_uri_is_an_encoded_file_uri_with_a_trailing_slash() {
    let temp = tempfile::Builder::new()
        .prefix("kuzushi export ")
        .tempdir()
        .unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();

    let uri = workspace_root_uri(&workspace).unwrap();

    assert!(uri.starts_with("file:///"), "unexpected base uri: {uri}");
    assert!(uri.ends_with('/'), "base uri must be a directory: {uri}");
    assert!(
        uri.contains("kuzushi%20export%20"),
        "space must be percent-encoded: {uri}"
    );
    assert!(!uri.contains(' '), "base uri must contain no raw space: {uri}");
}

fn sarif_record(rule_id: &str, severity: &str, fingerprint: &str) -> WorkspaceFindingExportRecord {
    WorkspaceFindingExportRecord {
        rule_id: rule_id.to_string(),
        severity: severity.to_string(),
        fingerprint: fingerprint.to_string(),
        title: format!("{rule_id} title"),
        message: format!("{rule_id} result"),
        triage_state: "needs_review".to_string(),
        ..Default::default()
    }
}

#[test]
fn security_rules_carry_stable_help_tags_and_distinct_security_severity() {
    let critical = sarif_record("demo.critical", "critical", "fp-critical");
    let high = sarif_record("demo.high", "high", "fp-high");
    let unknown = sarif_record("demo.unknown", "unknown", "fp-unknown");
    let rules = sarif_rules(&[&critical, &high, &unknown]);

    let rule = |id: &str| rules.iter().find(|rule| rule["id"] == id).unwrap();
    assert_eq!(
        rule("demo.critical")["properties"]["security-severity"],
        "9.1"
    );
    assert_eq!(
        rule("demo.high")["properties"]["security-severity"],
        "8.0"
    );
    assert!(rule("demo.unknown")["properties"]
        .get("security-severity")
        .is_none());
    assert_eq!(
        rule("demo.high")["properties"]["tags"],
        json!(["security"])
    );
    assert_eq!(
        rule("demo.high")["help"]["text"],
        "Inspect the result message, proof band, evidence properties, and recommended change before remediation."
    );
}

#[test]
fn duplicate_rule_uses_maximum_severity_independent_of_input_order() {
    let low = sarif_record("demo.shared", "low", "fp-low");
    let mut critical = sarif_record("demo.shared", "critical", "fp-critical");
    critical.cwe = Some("CWE-89".to_string());

    let forward = sarif_rules(&[&low, &critical]);
    let reverse = sarif_rules(&[&critical, &low]);

    assert_eq!(forward, reverse);
    assert_eq!(forward[0]["defaultConfiguration"]["level"], "error");
    assert_eq!(forward[0]["properties"]["security-severity"], "9.1");
    assert_eq!(
        forward[0]["properties"]["tags"],
        json!(["security", "CWE-89"])
    );
}

#[test]
fn finding_specific_guidance_stays_on_results_not_shared_rules() {
    let mut record = sarif_record("demo.guidance", "high", "fp-guidance");
    record.recommendation = Some("Use a parameterized query".to_string());
    record.impact = Some("Private rows can be read".to_string());
    record.exploit_scenario = Some("A crafted id reaches SQL".to_string());
    record.category = Some("injection".to_string());
    record.preconditions = vec!["attacker can call GET /orders".to_string()];

    let rule = &sarif_rules(&[&record])[0];
    let result = sarif_result(&record);

    assert!(!rule["help"]["text"]
        .as_str()
        .unwrap()
        .contains("parameterized query"));
    assert_eq!(
        result["properties"]["kuzushiRecommendation"],
        "Use a parameterized query"
    );
    assert_eq!(result["properties"]["kuzushiImpact"], "Private rows can be read");
    assert_eq!(result["properties"]["kuzushiCategory"], "injection");
    assert_eq!(
        result["properties"]["kuzushiPreconditions"],
        json!(["attacker can call GET /orders"])
    );

    let sparse = sarif_result(&sarif_record("demo.sparse", "low", "fp-sparse"));
    assert!(sparse["properties"].get("kuzushiRecommendation").is_none());
}
