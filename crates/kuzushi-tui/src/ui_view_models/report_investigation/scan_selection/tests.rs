use super::*;

fn selection(case: Option<&str>, parameters: Value) -> InvestigationScanSelection {
    InvestigationScanSelection {
        case_id: case.map(str::to_owned),
        parameters: serde_json::from_value(parameters).unwrap(),
    }
}

#[test]
fn identical_case_requests_group_without_losing_any_case_or_literal_source() {
    let source = " owned \\\"λ\\\"\n\u{001b}[31m.yaml ";
    let parameters = json!({"tasks":["semgrep"],"semgrepConfig":[source],"semgrepJobs":1});
    let records: Vec<_> = ["billing", "gateway", "root files"]
        .into_iter()
        .map(|id| selection(Some(id), parameters.clone()))
        .collect();
    let overview = lines(&records, false).join("\n");
    assert!(overview.contains("1 selection across 3 plan cases"));
    assert_eq!(overview.matches("Requested tasks:").count(), 1);
    assert!(overview.contains("Semgrep sources: 1 requested"));
    assert!(overview.contains("3 plan cases"));
    assert!(!overview.contains("3 requests"));
    let details = lines(&records, true).join("\n");
    assert!(details.contains(&json!(source).to_string()));
    assert!(details.contains("[\"billing\",\"gateway\",\"root files\"]"));
    assert!(details.contains("Rule-source contents are not pinned"));
    assert!(details.contains("p overview"));
    assert!(!details.contains("p details"));
    assert!(!details.contains('\u{001b}'));
    assert!(!details.contains("Engine details:"));
}

#[test]
fn whole_study_keeps_allowance_coverage_and_model_ahead_of_requested_settings() {
    use kuzushi_core::capabilities::campaign::{
        compile_scan_batch_plan, ScanBatchGatePolicy, ScanBatchPlanSpec,
    };
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("owned.txt"),
        "Owned report fixture, never executed.\n",
    )
    .unwrap();
    let config = kuzushi_core::V2Config::default();
    let registry = kuzushi_core::modules::ModuleRegistry::with_v2_builtins();
    compile_scan_batch_plan(ScanBatchPlanSpec {
        root: root.path(), batch_id: Some("settings-order".into()), trials: 3,
        requested_workers: 1, gate_policy: ScanBatchGatePolicy::default(),
        prepared_input: json!({"taskMode":"manual","tasks":["secret-scan"],"semgrepConfig":["p/recorded"]}),
        config: &config, registry: &registry,
    }).unwrap();
    let workspace = kuzushi_core::WorkspaceTarget::new(root.path()).unwrap();
    let document =
        kuzushi_core::workspace::load_investigation_report_document(&workspace, "settings-order")
            .unwrap();
    let app = crate::app::ShellApp::new(config, Some(&workspace));
    let lines = super::super::selected_document_lines(&app, &document);
    let position = |prefix: &str| {
        lines
            .iter()
            .position(|line| line.starts_with(prefix))
            .unwrap()
    };
    assert!(position("Allowance:") < position("Planned scan settings:"));
    assert!(position("Coverage:") < position("Planned scan settings:"));
    assert!(position("Model:") < position("Planned scan settings:"));
    assert!(document.summary().attempts.is_empty());
    assert!(!lines.join("\n").contains("Engine details:"));
}

#[test]
fn varying_requests_stay_distinct_instead_of_using_the_baseline() {
    let records = vec![
        selection(
            Some("baseline"),
            json!({"tasks":["semgrep"],"semgrepConfig":["p/base"]}),
        ),
        selection(
            Some("variant"),
            json!({"tasks":["semgrep"],"semgrepConfig":["p/variant"]}),
        ),
    ];
    let text = lines(&records, true).join("\n");
    assert!(text.contains("2 selections across 2 plan cases"));
    for literal in ["baseline", "variant", "p/base", "p/variant"] {
        assert!(text.contains(literal), "{text}");
    }
}

#[test]
fn incomplete_and_invalid_rule_requests_never_assert_zero_enabled_rules() {
    assert!(lines(&[], false)[0].contains("not recorded"));
    for parameters in [
        json!({}),
        json!({"semgrepConfig":null}),
        json!({"semgrepConfig":[]}),
        json!({"semgrepConfig":[42]}),
        json!({"semgrepConfig":{"wrong":"shape"}}),
    ] {
        let text = lines(&[selection(None, parameters.clone())], true).join("\n");
        assert!(!text.contains("0 requested"));
        assert!(!text.contains("0 rules"));
        assert!(text.contains("do not establish enabled-rule coverage"));
        if let Some(value) = parameters.get("semgrepConfig") {
            assert!(text.contains(&format!("semgrepConfig: {value}")), "{text}");
        }
    }
}
