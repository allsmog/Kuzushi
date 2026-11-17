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

#[test]
fn a_relative_reference_decodes_into_the_name_it_encodes() {
    // What `relative_uri_reference` writes, and what every conformant
    // producer writes, is what this has to read back.
    for file in [
        "src/main.rs",
        "docs/My Notes.md",
        "src/café.rs",
        "data/100%.json",
        "src/a\\b.rs",
        "deep/dir name/sub dir/東京.go",
    ] {
        assert_eq!(
            reported_path_from_sarif_uri(&relative_uri_reference(file)).as_deref(),
            Some(file),
            "{file} did not survive the round trip"
        );
    }
}

#[test]
fn an_escaped_separator_byte_stays_a_filename_byte() {
    // `%5C` is what `relative_uri_reference` emits for a Unix filename holding
    // `\`; reading it as a separator would name a file that does not exist. A
    // literal `\` is the separator a Windows producer wrote itself.
    assert_eq!(
        reported_path_from_sarif_uri("src/a%5Cb.rs").as_deref(),
        Some("src/a\\b.rs")
    );
    assert_eq!(
        reported_path_from_sarif_uri(r"src\win\app.cs").as_deref(),
        Some("src/win/app.cs")
    );
}

#[test]
fn an_absolute_file_uri_is_read_relative_to_the_root_it_names() {
    assert_eq!(
        reported_path_from_sarif_uri("file:///Users/me/src%20dir/app.js").as_deref(),
        Some("Users/me/src dir/app.js")
    );
    assert_eq!(
        reported_path_from_sarif_uri("file:///C:/repo/src%2Fmain.cpp").as_deref(),
        Some("repo/src/main.cpp")
    );
}

#[test]
fn a_reference_that_names_no_readable_path_is_refused() {
    // `%E9` is not UTF-8: decoding it lossily would report U+FFFD, which names
    // a different file than the engine found, and `Finding.file_path` cannot
    // hold the real bytes.
    assert_eq!(reported_path_from_sarif_uri("src/caf%E9.rs"), None);
    assert_eq!(reported_path_from_sarif_uri("file:///"), None);
    assert_eq!(reported_path_from_sarif_uri(""), None);
    // A `%` introducing no escape is literal, so the finding keeps a name.
    assert_eq!(
        reported_path_from_sarif_uri("a%2Fb%ZZ.rs").as_deref(),
        Some("a/b%ZZ.rs")
    );
}

#[test]
fn a_non_file_uri_location_reads_back_as_the_identifier_it_names() {
    for uri in ["https://api.lab.test/orders?id=1%2F2", "urn:cwe:79"] {
        assert_eq!(
            reported_path_from_sarif_uri(uri).as_deref(),
            Some(uri),
            "{uri} must not be decoded as a path"
        );
    }
}
