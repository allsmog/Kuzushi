use super::adapters::{load_catalog_from_path, parse_catalog_str};
use super::application::dispatch::{plan_for_entry, DispatchPlan};
use super::domain::{CatalogSeverity, HuntKind};
use std::path::Path;
use tempfile::tempdir;

#[test]
fn parses_minimal_uaf_hunt_entry() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "redis-cve-test-uaf"
cves = ["CVE-9999-9999"]
title = "test UAF"
cwe = "CWE-416"
severity = "critical"
hunt = "uaf-hunt"

[entry.uaf_hunt]
alloc_free_pairs = [
    { alloc = "createClient", free = "freeClient" },
]
"#;
    let entries = parse_catalog_str(toml, Path::new("test.toml")).unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.id, "redis-cve-test-uaf");
    assert_eq!(entry.cves, vec!["CVE-9999-9999"]);
    assert_eq!(entry.cwe, "CWE-416");
    assert_eq!(entry.severity, CatalogSeverity::Critical);
    assert_eq!(entry.hunt, HuntKind::UafHunt);
    assert!(entry.hunt_config.contains_key("uaf_hunt"));
}

#[test]
fn unknown_schema_version_bails() {
    let toml = r#"
schema_version = "99"

[[entry]]
id = "x"
cwe = "CWE-416"
severity = "high"
hunt = "uaf-hunt"
"#;
    let err = parse_catalog_str(toml, Path::new("future.toml")).unwrap_err();
    let chain = format!("{err:#}");
    assert!(chain.contains("schema_version"), "bail must name field: {chain}");
    assert!(chain.contains("\"99\""), "bail must echo the bad value: {chain}");
}

#[test]
fn duplicate_ids_in_one_catalog_bail() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "dupe"
cwe = "CWE-416"
severity = "high"
hunt = "uaf-hunt"

[[entry]]
id = "dupe"
cwe = "CWE-415"
severity = "high"
hunt = "uaf-hunt"
"#;
    let err = parse_catalog_str(toml, Path::new("dupe.toml")).unwrap_err();
    let chain = format!("{err:#}");
    assert!(chain.contains("duplicate"), "bail mention duplicate: {chain}");
    assert!(chain.contains("dupe"), "bail must name id: {chain}");
}

#[test]
fn unknown_severity_bails_with_helpful_message() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "x"
cwe = "CWE-416"
severity = "very-high"
hunt = "uaf-hunt"
"#;
    let err = parse_catalog_str(toml, Path::new("bad-sev.toml")).unwrap_err();
    let chain = format!("{err:#}");
    assert!(chain.contains("severity"), "bail must mention severity: {chain}");
    assert!(
        chain.contains("critical") && chain.contains("high"),
        "bail must list valid values: {chain}"
    );
}

#[test]
fn unknown_hunt_dispatches_with_skipped_plan_naming_supported_values() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "x"
cwe = "CWE-416"
severity = "high"
hunt = "ml-finetune"
"#;
    let entries = parse_catalog_str(toml, Path::new("future.toml")).unwrap();
    let plan = plan_for_entry(&entries[0]);
    match plan {
        DispatchPlan::Skipped { reason } => {
            assert!(reason.contains("ml-finetune"), "skip reason names hunt: {reason}");
            assert!(
                reason.contains("uaf-hunt") && reason.contains("taint-iris-next"),
                "skip reason lists supported hunts: {reason}"
            );
        }
        DispatchPlan::Dispatched { .. } => panic!("unknown hunt must skip, not dispatch"),
    }
}

#[test]
fn uaf_hunt_entry_dispatches_with_alloc_free_pairs_input() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "redis-cve-uaf"
cwe = "CWE-416"
severity = "critical"
hunt = "uaf-hunt"

[entry.uaf_hunt]
alloc_free_pairs = [
    { alloc = "createClient", free = "freeClient" },
    { alloc = "scriptingInit", free = "scriptingRelease" },
]
max_findings = 8
max_agent_steps = 150
"#;
    let entries = parse_catalog_str(toml, Path::new("redis.toml")).unwrap();
    let plan = plan_for_entry(&entries[0]);
    match plan {
        DispatchPlan::Dispatched { tool_name, input } => {
            assert_eq!(tool_name, "uaf-hunt:hunt");
            let pairs = input["allocFreePairs"].as_array().expect("array");
            assert_eq!(pairs.len(), 2);
            assert_eq!(pairs[0]["alloc"], "createClient");
            assert_eq!(pairs[0]["free"], "freeClient");
            assert_eq!(input["maxFindings"], 8);
            assert_eq!(input["maxAgentSteps"], 150);
        }
        DispatchPlan::Skipped { reason } => panic!("uaf-hunt entry must dispatch: {reason}"),
    }
}

#[test]
fn uaf_hunt_entry_missing_alloc_free_pairs_skips_with_reason() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "redis-cve-uaf-empty"
cwe = "CWE-416"
severity = "critical"
hunt = "uaf-hunt"
"#;
    let entries = parse_catalog_str(toml, Path::new("empty.toml")).unwrap();
    let plan = plan_for_entry(&entries[0]);
    match plan {
        DispatchPlan::Skipped { reason } => {
            assert!(reason.contains("alloc_free_pairs"), "reason names field: {reason}");
        }
        DispatchPlan::Dispatched { .. } => {
            panic!("entry without alloc_free_pairs must skip — empty pair list is dispatch-time \
                    nonsense, not a reason to silently scan everything")
        }
    }
}

#[test]
fn taint_iris_next_entries_skip_with_followup_pointer() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "redis-cve-tn"
cwe = "CWE-190"
severity = "high"
hunt = "taint-iris-next"

[entry.taint_iris_next]
taint_class = "integer-overflow"
source_signals = ["external input"]
sink_signals = ["zmalloc(count * sizeof(...))"]
"#;
    let entries = parse_catalog_str(toml, Path::new("redis.toml")).unwrap();
    let plan = plan_for_entry(&entries[0]);
    match plan {
        DispatchPlan::Skipped { reason } => {
            assert!(
                reason.contains("taint-iris-next") && reason.contains("catalog"),
                "skip reason must name the missing wiring: {reason}"
            );
            assert!(
                reason.contains("Follow-up") || reason.contains("follow-up"),
                "skip reason should name the follow-up surface area: {reason}"
            );
        }
        DispatchPlan::Dispatched { .. } => panic!("taint-iris-next not yet wired; must skip"),
    }
}

#[test]
fn loads_catalog_from_disk_with_multiple_entries() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("redis.toml");
    std::fs::write(
        &path,
        r#"
schema_version = "1"

[[entry]]
id = "a"
cwe = "CWE-416"
severity = "critical"
hunt = "uaf-hunt"

[entry.uaf_hunt]
alloc_free_pairs = [ { alloc = "malloc", free = "free" } ]

[[entry]]
id = "b"
cwe = "CWE-190"
severity = "high"
hunt = "taint-iris-next"
"#,
    )
    .unwrap();
    let entries = load_catalog_from_path(&path).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].id, "a");
    assert_eq!(entries[0].hunt, HuntKind::UafHunt);
    assert_eq!(entries[1].id, "b");
    assert_eq!(entries[1].hunt, HuntKind::TaintIrisNext);
}
