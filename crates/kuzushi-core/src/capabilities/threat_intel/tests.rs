use super::adapters::execute_threat_intel_tool;
use super::adapters::{load_catalog_from_path, parse_catalog_str};
use super::application::apply_threat_intel_catalog;
use super::application::dispatch::{plan_for_entry, DispatchPlan};
use super::domain::{CatalogSeverity, HuntKind};
use crate::config::V2Config;
use crate::modules::ToolExecutionContext;
use serde_json::json;
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
    assert!(
        chain.contains("schema_version"),
        "bail must name field: {chain}"
    );
    assert!(
        chain.contains("\"99\""),
        "bail must echo the bad value: {chain}"
    );
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
    assert!(
        chain.contains("duplicate"),
        "bail mention duplicate: {chain}"
    );
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
    assert!(
        chain.contains("severity"),
        "bail must mention severity: {chain}"
    );
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
            assert!(
                reason.contains("ml-finetune"),
                "skip reason names hunt: {reason}"
            );
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
            assert!(
                reason.contains("alloc_free_pairs"),
                "reason names field: {reason}"
            );
        }
        DispatchPlan::Dispatched { .. } => {
            panic!(
                "entry without alloc_free_pairs must skip — empty pair list is dispatch-time \
                    nonsense, not a reason to silently scan everything"
            )
        }
    }
}

#[test]
fn taint_iris_next_entries_dispatch_with_extra_catalog_entries_input() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "redis-cve-tn"
cwe = "CWE-190"
severity = "high"
title = "Redis stream integer overflow"
hunt = "taint-iris-next"

[entry.taint_iris_next]
taint_class = "integer-overflow"
languages = ["c"]
source_signals = ["external input", "RESP count"]
sink_signals = ["zmalloc(count * sizeof(...))"]
sanitizer_signals = ["bounds check on count"]
structural_queries = ["XAUTOCLAIM"]
"#;
    let entries = parse_catalog_str(toml, Path::new("redis.toml")).unwrap();
    let plan = plan_for_entry(&entries[0]);
    match plan {
        DispatchPlan::Dispatched { tool_name, input } => {
            assert_eq!(tool_name, "taint-iris-next:hunt");
            assert_eq!(input["mode"], "hunt");
            let extras = input["extraCatalogEntries"].as_array().expect("array");
            assert_eq!(extras.len(), 1);
            let e = &extras[0];
            assert_eq!(e["cwe"], "CWE-190");
            assert_eq!(e["taintClass"], "integer-overflow");
            assert_eq!(e["name"], "Redis stream integer overflow");
            assert_eq!(e["languages"], serde_json::json!(["c"]));
            assert_eq!(
                e["sourceSignals"],
                serde_json::json!(["external input", "RESP count"])
            );
            assert_eq!(
                e["sinkSignals"],
                serde_json::json!(["zmalloc(count * sizeof(...))"])
            );
            assert_eq!(
                e["sanitizerSignals"],
                serde_json::json!(["bounds check on count"])
            );
            assert_eq!(e["structuralQueries"], serde_json::json!(["XAUTOCLAIM"]));
        }
        DispatchPlan::Skipped { reason } => {
            panic!("taint-iris-next entries with a subtable must dispatch now: {reason}")
        }
    }
}

#[test]
fn taint_iris_next_entry_without_subtable_skips_with_reason() {
    let toml = r#"
schema_version = "1"

[[entry]]
id = "tn-bare"
cwe = "CWE-190"
severity = "high"
hunt = "taint-iris-next"
"#;
    let entries = parse_catalog_str(toml, Path::new("bare.toml")).unwrap();
    let plan = plan_for_entry(&entries[0]);
    match plan {
        DispatchPlan::Skipped { reason } => {
            assert!(
                reason.contains("taint_iris_next") || reason.contains("subtable"),
                "reason should name the missing subtable: {reason}"
            );
        }
        DispatchPlan::Dispatched { .. } => panic!("bare entry must skip"),
    }
}

#[test]
fn apply_catalog_plans_dispatches_skips_and_live_counts() {
    let dir = tempdir().unwrap();
    let catalog = dir.path().join("catalog.toml");
    std::fs::write(
        &catalog,
        r#"
schema_version = "1"

[[entry]]
id = "redis-cve-tn"
cwe = "CWE-190"
severity = "high"
title = "Redis stream integer overflow"
hunt = "taint-iris-next"

[entry.taint_iris_next]
taint_class = "integer-overflow"
languages = ["c"]
source_signals = ["external input"]
sink_signals = ["zmalloc(count * sizeof(...))"]

[[entry]]
id = "future"
cwe = "CWE-999"
severity = "low"
hunt = "ml-finetune"
"#,
    )
    .unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
cancellation: None,
authorization: Default::default(),
    };

    let dry = apply_threat_intel_catalog(&catalog, &ctx, None, false, |_, _, _, _| {
        panic!("dry run must not dispatch")
    })
    .unwrap();
    assert_eq!(dry["status"], json!("completed"));
    assert_eq!(dry["data"]["summary"]["dispatched"], json!(1));
    assert_eq!(dry["data"]["summary"]["skipped"], json!(1));
    assert_eq!(dry["data"]["summary"]["dryRun"], json!(true));

    let live = apply_threat_intel_catalog(&catalog, &ctx, None, true, |name, input, _, _| {
        assert_eq!(name, "taint-iris-next:hunt");
        assert_eq!(input["mode"], json!("hunt"));
        Ok(json!({"ok": true, "summary": {"count": 2}}))
    })
    .unwrap();
    assert_eq!(live["status"], json!("completed"));
    assert_eq!(live["data"]["summary"]["totalFindings"], json!(2));
    assert_eq!(live["data"]["entries"][0]["status"], json!("dispatched"));

    let failed = apply_threat_intel_catalog(&catalog, &ctx, None, true, |_, _, _, _| {
        anyhow::bail!("boom")
    })
    .unwrap();
    assert_eq!(failed["data"]["summary"]["failed"], json!(1));
    assert_eq!(
        failed["data"]["entries"][0]["status"],
        json!("dispatch-failed")
    );
}

#[test]
fn execute_threat_intel_tool_routes_list_apply_and_unknown() {
    let dir = tempdir().unwrap();
    let catalog = dir.path().join("catalog.toml");
    std::fs::write(
        &catalog,
        r#"
schema_version = "1"

[[entry]]
id = "redis-cve-tn"
cwe = "CWE-190"
severity = "high"
title = "Redis stream integer overflow"
hunt = "taint-iris-next"

[entry.taint_iris_next]
taint_class = "integer-overflow"
languages = ["c"]
source_signals = ["external input"]
sink_signals = ["zmalloc(count * sizeof(...))"]
"#,
    )
    .unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
cancellation: None,
authorization: Default::default(),
    };
    let input = json!({"catalogPath": catalog.display().to_string()});

    let listed = execute_threat_intel_tool(
        "threat-intel:list",
        input.clone(),
        &ctx,
        None,
        |_, _, _, _| panic!("list must not dispatch"),
    )
    .unwrap();
    assert_eq!(listed["status"], json!("completed"));
    assert_eq!(listed["data"]["summary"]["totalEntries"], json!(1));

    let planned =
        execute_threat_intel_tool("threat-intel:apply", input, &ctx, None, |_, _, _, _| {
            panic!("dry apply must not dispatch")
        })
        .unwrap();
    assert_eq!(planned["data"]["summary"]["dryRun"], json!(true));

    let err =
        execute_threat_intel_tool("threat-intel:nope", json!({}), &ctx, None, |_, _, _, _| {
            Ok(json!({}))
        })
        .unwrap_err();
    assert!(err.to_string().contains("unknown tool"));
}

#[test]
fn harvest_pipeline_with_mock_dispatch_writes_catalog_and_summary() {
    use crate::capabilities::threat_intel::harvest_threat_intel_catalog;
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;
    use crate::workspace::WorkspaceTarget;
    use serde_json::json;

    let workspace_root = tempdir().unwrap();
    let workspace = WorkspaceTarget::new(workspace_root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
cancellation: None,
authorization: Default::default(),
    };

    // Canned ndiff responses: usable patterns for two CVE IDs, ok=false
    // for a third (unknown CVE).
    let dispatch = |name: &str,
                    input: serde_json::Value,
                    _ctx: &ToolExecutionContext<'_>,
                    _runtime: Option<&dyn crate::runtime::AgentRuntime>|
     -> anyhow::Result<serde_json::Value> {
        match name {
            "ndiff:fetch-cve" => {
                let cve = input
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if cve == "CVE-9999-AAAA" {
                    return Ok(json!({"ok": false, "output": "advisory not found"}));
                }
                Ok(json!({
                    "ok": true,
                    "output": "ok",
                    "data": {
                        "record": {
                            "id": cve,
                            "description": "Stream count integer overflow in Redis.",
                            "cwes": ["CWE-190"],
                            "severity": "HIGH",
                            "affectedFiles": ["src/t_stream.c"],
                        }
                    }
                }))
            }
            "ndiff:extract-fix-pattern" => Ok(json!({
                "ok": true,
                "output": "ok",
                "data": {
                    "pattern": {
                        "cwe": ["CWE-190"],
                        "languages": ["c"],
                        "vulnerableShape": "count multiplied without bounds check",
                        "fixShape": "if (count > LIMIT) return error",
                        "detectionQuery": "zmalloc(count * sizeof",
                        "keywords": ["XAUTOCLAIM", "streamID"],
                        "description": "stream count overflow",
                        "confidence": "HIGH",
                    }
                }
            })),
            other => panic!("unexpected dispatch in harvest test: {other}"),
        }
    };

    let result = harvest_threat_intel_catalog(
        &json!({"cves": ["CVE-2022-31144", "CVE-9999-AAAA"]}),
        &ctx,
        None,
        dispatch,
    )
    .unwrap();

    assert_eq!(result["status"], json!("completed"));
    assert_eq!(result["data"]["summary"]["totalCves"], 2);
    assert_eq!(result["data"]["summary"]["harvested"], 1);
    assert_eq!(result["data"]["summary"]["skipped"], 1);
    assert_eq!(result["data"]["summary"]["failed"], 0);

    let output_path = workspace_root
        .path()
        .join(".kuzushi")
        .join("catalogs")
        .join("harvested.toml");
    assert!(output_path.exists(), "harvest must write the TOML file");
    let toml_text = std::fs::read_to_string(&output_path).unwrap();
    assert!(toml_text.contains("[[entry]]"));
    assert!(toml_text.contains("CVE-2022-31144"));
    assert!(toml_text.contains("hunt = \"taint-iris-next\""));
    assert!(toml_text.contains("[entry.taint_iris_next]"));

    // Round-trip: the harvested TOML must parse through our own loader.
    let parsed = parse_catalog_str(&toml_text, &output_path).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].cwe, "CWE-190");
    assert_eq!(parsed[0].hunt, HuntKind::TaintIrisNext);

    // Second run appends rather than overwriting.
    let _ =
        harvest_threat_intel_catalog(&json!({"cves": ["CVE-2022-31145"]}), &ctx, None, dispatch)
            .unwrap();
    let after = std::fs::read_to_string(&output_path).unwrap();
    assert!(after.contains("CVE-2022-31144"));
    assert!(after.contains("CVE-2022-31145"));
}

#[test]
fn harvest_with_regression_gate_validates_and_writes_entry() {
    use crate::capabilities::threat_intel::harvest_threat_intel_catalog;
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;
    use crate::workspace::WorkspaceTarget;
    use serde_json::json;

    // Build a synthetic git repo with a real fix commit so the gate
    // can actually run.
    let temp = tempdir().unwrap();
    let repo = temp.path();
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping live harvest+gate test: git not on PATH");
        return;
    }
    let run_git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("git invocation failed")
    };
    run_git(&["init", "-q"]);
    run_git(&["config", "user.email", "t@test.invalid"]);
    run_git(&["config", "user.name", "t"]);
    run_git(&["config", "commit.gpgsign", "false"]);
    std::fs::write(repo.join("vuln.c"), "void f() { UNSAFE_OP(); }\n").unwrap();
    run_git(&["add", "vuln.c"]);
    run_git(&["commit", "-q", "-m", "pre"]);
    std::fs::write(repo.join("vuln.c"), "void f() { SAFE_OP(); }\n").unwrap();
    run_git(&["add", "vuln.c"]);
    run_git(&["commit", "-q", "-m", "fix"]);
    let sha = String::from_utf8(run_git(&["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();

    let workspace = WorkspaceTarget::new(repo).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
cancellation: None,
authorization: Default::default(),
    };

    let dispatch = |name: &str,
                    _input: serde_json::Value,
                    _ctx: &ToolExecutionContext<'_>,
                    _runtime: Option<&dyn crate::runtime::AgentRuntime>|
     -> anyhow::Result<serde_json::Value> {
        let sha = sha.clone();
        match name {
            "ndiff:fetch-cve" => Ok(json!({
                "ok": true,
                "output": "ok",
                "data": {
                    "record": {
                        "id": "CVE-TEST",
                        "description": "Synthetic test.",
                        "cwes": ["CWE-190"],
                        "severity": "HIGH",
                        "affectedFiles": ["vuln.c"],
                        "patches": [{"url": format!("https://example.com/commit/{sha}")}],
                    }
                }
            })),
            "ndiff:extract-fix-pattern" => Ok(json!({
                "ok": true,
                "output": "ok",
                "data": {
                    "pattern": {
                        "cwe": ["CWE-190"],
                        "languages": ["c"],
                        "vulnerableShape": "UNSAFE_OP",
                        "fixShape": "SAFE_OP",
                        "detectionQuery": "UNSAFE_OP",
                        "keywords": ["UNSAFE_OP"],
                        "description": "synthetic",
                        "confidence": "HIGH",
                    }
                }
            })),
            other => panic!("unexpected dispatch: {other}"),
        }
    };

    let result =
        harvest_threat_intel_catalog(&json!({"cves": ["CVE-TEST"]}), &ctx, None, dispatch).unwrap();

    assert_eq!(result["data"]["summary"]["totalCves"], 1);
    assert_eq!(result["data"]["summary"]["harvested"], 1);
    assert_eq!(result["data"]["summary"]["regressionGate"]["validated"], 1);
    assert_eq!(result["data"]["summary"]["regressionGate"]["rejected"], 0);

    let per = result["data"]["perCve"][0].clone();
    assert_eq!(per["status"], "harvested");
    assert_eq!(per["gate"]["status"], "validated");
    assert_eq!(per["gate"]["preFixHits"], 1);
    assert_eq!(per["gate"]["postFixHits"], 0);
    assert_eq!(per["gate"]["fixSha"], sha);

    let toml_text = std::fs::read_to_string(
        repo.join(".kuzushi")
            .join("catalogs")
            .join("harvested.toml"),
    )
    .unwrap();
    assert!(toml_text.contains("regression-gate=validated"));
    assert!(toml_text.contains(&sha[..12]));
}

#[test]
fn harvest_with_regression_gate_rejects_non_splitting_pattern() {
    use crate::capabilities::threat_intel::harvest_threat_intel_catalog;
    use crate::config::V2Config;
    use crate::modules::ToolExecutionContext;
    use crate::workspace::WorkspaceTarget;
    use serde_json::json;

    let temp = tempdir().unwrap();
    let repo = temp.path();
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let run_git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("git invocation failed")
    };
    run_git(&["init", "-q"]);
    run_git(&["config", "user.email", "t@test.invalid"]);
    run_git(&["config", "user.name", "t"]);
    run_git(&["config", "commit.gpgsign", "false"]);
    std::fs::write(repo.join("vuln.c"), "void f() { CALL(); }\n").unwrap();
    run_git(&["add", "vuln.c"]);
    run_git(&["commit", "-q", "-m", "pre"]);
    std::fs::write(repo.join("vuln.c"), "void f() { CALL(); CHECK(); }\n").unwrap();
    run_git(&["add", "vuln.c"]);
    run_git(&["commit", "-q", "-m", "fix"]);
    let sha = String::from_utf8(run_git(&["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string();

    let workspace = WorkspaceTarget::new(repo).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
cancellation: None,
authorization: Default::default(),
    };

    let dispatch = |name: &str,
                    _input: serde_json::Value,
                    _ctx: &ToolExecutionContext<'_>,
                    _runtime: Option<&dyn crate::runtime::AgentRuntime>|
     -> anyhow::Result<serde_json::Value> {
        let sha = sha.clone();
        match name {
            "ndiff:fetch-cve" => Ok(json!({
                "ok": true, "output": "ok",
                "data": {"record": {
                    "id": "CVE-NOSPLIT", "description": "noise pattern",
                    "cwes": ["CWE-190"], "severity": "HIGH",
                    "affectedFiles": ["vuln.c"],
                    "patches": [{"url": format!("https://example.com/commit/{sha}")}],
                }}
            })),
            // "CALL" appears in both pre-fix and post-fix — the gate
            // must reject (same hit count, doesn't distinguish).
            "ndiff:extract-fix-pattern" => Ok(json!({
                "ok": true, "output": "ok",
                "data": {"pattern": {
                    "cwe": ["CWE-190"], "languages": ["c"],
                    "vulnerableShape": "CALL", "fixShape": "CHECK",
                    "detectionQuery": "CALL", "keywords": ["CALL"],
                    "description": "noise", "confidence": "MEDIUM",
                }}
            })),
            other => panic!("unexpected dispatch: {other}"),
        }
    };

    let result =
        harvest_threat_intel_catalog(&json!({"cves": ["CVE-NOSPLIT"]}), &ctx, None, dispatch)
            .unwrap();

    assert_eq!(result["data"]["summary"]["harvested"], 0);
    assert_eq!(result["data"]["summary"]["skipped"], 1);
    assert_eq!(result["data"]["summary"]["regressionGate"]["rejected"], 1);
    assert_eq!(result["data"]["perCve"][0]["status"], "rejected-by-gate");
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
