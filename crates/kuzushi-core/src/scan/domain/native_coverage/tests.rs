use super::*;

#[test]
fn partial_coverage_is_engine_specific_and_retains_all_scopes_and_gaps() {
    let coverage = NativeScanCoverage {
        schema_version: 2,
        source_binding: None,
        engines: vec![
            NativeEngineCoverage {
                engine: "partial".into(),
                scope: Some("service".into()),
                findings_count: 2,
                disposition: NativeEngineDisposition::Complete,
                scan_errors: vec![
                    "unread A".into(),
                    "unread B".into(),
                    "unread C".into(),
                    "unread D".into(),
                ],
            },
            NativeEngineCoverage {
                engine: "complete".into(),
                scope: Some("other".into()),
                findings_count: 0,
                disposition: NativeEngineDisposition::Complete,
                scan_errors: Vec::new(),
            },
        ],
    };
    assert!(coverage.has_gaps());
    assert!(coverage.engine_has_gaps("partial"));
    assert!(!coverage.engine_has_gaps("complete"));
    assert!(coverage.engine_detail("complete").is_none());
    let detail = coverage.engine_detail("partial").unwrap();
    assert!(detail.contains("4 report(s)"));
    assert!(detail.contains("1 more retained in native-coverage.json"));
    assert!(detail.contains("service: unread A"));
    assert!(!detail.contains("unread D"));
    let saved = serde_json::to_value(&coverage).unwrap();
    assert_eq!(
        saved["engines"][0]["scanErrors"].as_array().unwrap().len(),
        4
    );
    assert_eq!(
        serde_json::from_value::<NativeScanCoverage>(saved).unwrap(),
        coverage
    );
}

#[test]
fn gap_preview_is_bounded_without_losing_the_original_message() {
    let error = format!("{}\nmore details", "界".repeat(1000));
    assert_eq!(bounded_gap(&error).chars().count(), 241);
    assert!(bounded_gap(&error).ends_with('…'));
    assert_eq!(bounded_gap("short\nmore details"), "short…");
    assert_eq!(NativeScanCoverage::default().schema_version, 3);
    assert!(!NativeScanCoverage::default().has_gaps());
}

#[test]
fn older_coverage_rows_keep_reported_gaps_and_default_to_completed_execution() {
    let coverage: NativeScanCoverage = serde_json::from_value(json!({
        "schemaVersion":1, "engines":[{"engine":"semgrep", "scope":null,
        "findingsCount":0, "scanErrors":["unread file"]}]
    }))
    .unwrap();
    assert_eq!(
        coverage.engines[0].disposition,
        NativeEngineDisposition::Complete
    );
    assert!(coverage.has_gaps());
}

#[test]
fn unknown_coverage_versions_are_rejected() {
    assert!(serde_json::from_value::<NativeScanCoverage>(
        json!({"schemaVersion":99, "engines":[]})
    )
    .is_err());
}

#[test]
fn an_unstarted_scope_is_visible_even_without_a_scanner_error() {
    let coverage = NativeScanCoverage {
        engines: vec![NativeEngineCoverage {
            engine: "semgrep".into(),
            scope: Some("c".into()),
            findings_count: 0,
            scan_errors: Vec::new(),
            disposition: NativeEngineDisposition::NotStarted,
        }],
        ..Default::default()
    };
    assert!(coverage.has_gaps());
    let detail = coverage.engine_detail("semgrep").unwrap();
    assert!(detail.contains("1 scope job(s) (c)"));
    assert!(detail.contains("No automatic retry"));
}

#[test]
fn source_retention_limit_is_distinct_from_scanner_coverage_and_survives_round_trip() {
    let coverage = NativeScanCoverage {
        engines: vec![NativeEngineCoverage {
            engine: "owned".into(),
            scope: None,
            findings_count: 1,
            scan_errors: Vec::new(),
            disposition: NativeEngineDisposition::Complete,
        }],
        source_binding: Some(NativeSourceBindingReceipt {
            snapshot_hash: "owned-snapshot".into(),
            tree_hash: "owned-tree".into(),
            authenticated: false,
            captured_files: 0,
            captured_bytes: 0,
            max_capture_bytes: 64,
            limitation: Some("Source capture limit exceeded".into()),
        }),
        ..Default::default()
    };
    assert!(coverage.has_gaps());
    assert!(coverage.engine_has_gaps("owned"));
    assert!(!coverage.engine_has_gaps("unselected"));
    let detail = coverage.engine_detail("owned").unwrap();
    assert!(detail.contains("source binding unavailable"));
    assert!(!detail.contains("unread"));
    assert!(coverage.engines[0].scan_errors.is_empty());
    assert!(coverage
        .require_source_binding()
        .unwrap_err()
        .to_string()
        .contains("Raw observations retained"));
    let saved = serde_json::to_value(&coverage).unwrap();
    assert_eq!(saved["schemaVersion"], 3);
    assert_eq!(
        serde_json::from_value::<NativeScanCoverage>(saved).unwrap(),
        coverage
    );
}
