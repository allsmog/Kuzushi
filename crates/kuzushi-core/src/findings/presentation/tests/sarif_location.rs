use super::*;

#[test]
fn a_location_without_a_reported_line_has_no_region() {
    // HAR/Burp `http-request` findings are built with line 0 against a URL.
    assert_eq!(sarif_region(0, None), None);
    assert_eq!(sarif_region(0, Some(9)), None);
}

#[test]
fn a_reported_line_becomes_a_region_that_never_ends_before_it_starts() {
    assert_eq!(sarif_region(12, None), Some(json!({ "startLine": 12 })));
    assert_eq!(
        sarif_region(12, Some(14)),
        Some(json!({ "startLine": 12, "endLine": 14 }))
    );
    assert_eq!(
        sarif_region(12, Some(4)),
        Some(json!({ "startLine": 12, "endLine": 12 }))
    );
}

#[test]
fn a_relative_path_resolves_against_the_declared_workspace_base() {
    assert_eq!(
        sarif_artifact_location("src/main.rs"),
        json!({ "uri": "src/main.rs", "uriBaseId": "WORKSPACE_ROOT" })
    );
    assert_eq!(
        sarif_artifact_location("docs/My Notes.md"),
        json!({ "uri": "docs/My%20Notes.md", "uriBaseId": "WORKSPACE_ROOT" })
    );
}

#[test]
fn an_already_absolute_location_is_never_bound_to_the_workspace_base() {
    // §3.4.4: `uriBaseId` beside an absolute `uri` is invalid, and resolving
    // one against the root would name a file that exists nowhere.
    for file in [
        "https://api.lab.test/orders?id=1",
        "urn:cwe:79",
        "/opt/vendor/tls lib.py",
        r"C:\src\app.rs",
    ] {
        let location = sarif_artifact_location(file);
        assert!(
            location.get("uriBaseId").is_none(),
            "{file} must not carry a base id: {location}"
        );
    }
}

#[test]
fn the_run_base_declares_the_same_id_the_locations_reference() {
    let temp = tempfile::Builder::new()
        .prefix("kuzushi sarif ")
        .tempdir()
        .unwrap();

    let base_ids = sarif_original_uri_base_ids(temp.path()).unwrap();
    let uri = base_ids[WORKSPACE_ROOT_BASE_ID]["uri"].as_str().unwrap();

    assert_eq!(
        sarif_artifact_location("src/main.rs")["uriBaseId"],
        WORKSPACE_ROOT_BASE_ID
    );
    assert!(uri.starts_with("file:///"), "unexpected base uri: {uri}");
    assert!(uri.ends_with('/'), "base uri must be a directory: {uri}");
    assert!(
        uri.contains("kuzushi%20sarif%20"),
        "space must be percent-encoded: {uri}"
    );
}
