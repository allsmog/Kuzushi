use super::*;

#[test]
fn preserves_reported_symbol_and_source_position_without_promoting_proof() {
    let json = r#"{"config":{"protocol_version":"v1.0.0"}}
{"osv":{"id":"GO-2024-0001","summary":"owned scanner test signal"}}"#
        .to_string()
        + "\n"
        + r#"{"finding":{"osv":"GO-2024-0001","fixed_version":"v1.2.3","trace":[{"function":"main.run","position":{"filename":"cmd/proxy/main.go","line":42}}]}}"#;

    let findings = parse_govulncheck_json(Path::new("/repo"), &json).unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].tool, "govulncheck");
    assert_eq!(findings[0].rule_id, "govulncheck/GO-2024-0001");
    assert_eq!(findings[0].file_path, "cmd/proxy/main.go");
    assert_eq!(findings[0].start_line, 42);
    assert!(findings[0].message.contains("fixed in v1.2.3"));
    assert!(findings[0].message.contains("scanner-reported symbol"));
    assert!(!findings[0].message.contains("reachable via"));
    assert_eq!(
        findings[0].static_proof_state,
        Some(StaticProofState::SignalOnly)
    );
}

#[test]
fn rejects_malformed_or_empty_jsonl_instead_of_reporting_clean() {
    assert!(parse_govulncheck_json(Path::new("/repo"), "not-json\n").is_err());
    assert!(parse_govulncheck_json(Path::new("/repo"), "\n").is_err());
    assert!(parse_govulncheck_json(Path::new("/repo"), r#"{"finding":{}}"#).is_err());
}

fn parse(value: &str) -> Result<Vec<Finding>> {
    parse_govulncheck_json(Path::new("/repo"), value)
}

fn stream(finding: serde_json::Value) -> String {
    format!(
        "{}{}",
        serde_json::json!({"config":{"protocol_version":"v1.0.0"}}),
        serde_json::json!({"finding":finding})
    )
}

#[test]
fn parses_pretty_printed_stream_and_keeps_module_signals_unproven() {
    let output = r#"{
  "config": {"protocol_version": "v1.0.0", "scan_level": "symbol"}
}
{
  "finding": {"osv": "GO-OWNED-0001", "trace": [{"module":"owned.invalid/metadata"}]}
}"#;
    let finding = parse(output).unwrap().remove(0);
    assert!(finding
        .message
        .contains("required module; call reachability unassessed"));
    assert_eq!(
        finding.static_proof_state,
        Some(StaticProofState::SignalOnly)
    );
}

#[test]
fn protocol_config_without_findings_does_not_invent_observations() {
    let output = r#"{"config":{"protocol_version":"v1.0.0"}}{"progress":{"message":"owned protocol fixture"}}{"SBOM":{"modules":[]}}"#;
    assert!(parse(output).unwrap().is_empty());
}

#[test]
fn rejects_unrecognized_partial_and_repeated_protocol_streams() {
    for output in [
        "{}",
        r#"{"unknown":"message"}"#,
        r#"{"config":{}}"#,
        r#"{"config":{"protocol_version":"v9"}}"#,
        r#"{"config":{"protocol_version":"v1.0.0"}}{"finding":{"osv":"GO-OWNED"},"progress":{}}"#,
        r#"{"config":{"protocol_version":"v1.0.0"}}{"config":{"protocol_version":"v1.0.0"}}"#,
        r#"{"config":{"protocol_version":"v1.0.0"}}{"finding":"#,
    ] {
        assert!(parse(output).is_err(), "{output}");
    }
}

#[test]
fn rejects_excessive_bytes_and_event_counts() {
    assert!(parse(&" ".repeat(16 * 1024 * 1024 + 1)).is_err());
    let output = format!(
        "{}{}",
        serde_json::json!({"config":{"protocol_version":"v1.0.0"}}),
        r#"{"progress":{}}"#.repeat(100_000)
    );
    assert!(parse(&output).is_err());
}

#[test]
fn package_and_missing_positions_remain_signal_only() {
    for trace in [
        serde_json::json!([{"package":"owned.invalid/package"}]),
        serde_json::json!([{"function":"owned", "position":{"filename":"go.mod", "line":0}}]),
        serde_json::json!([]),
    ] {
        let finding = parse(&stream(serde_json::json!({"osv":"GO-OWNED","trace":trace})))
            .unwrap()
            .remove(0);
        assert_eq!(
            finding.static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert_eq!(finding.start_line, 1);
        assert!(!finding.message.contains("reachable via"));
    }
}
