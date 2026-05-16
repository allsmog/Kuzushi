use super::*;
use crate::config::V2Config;
use crate::modules::ToolExecutionContext;
use crate::workspace::WorkspaceTarget;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use tempfile::tempdir;

#[test]
fn recommends_installed_tools_from_combined_signals() {
    let request = RecommenderRequest {
        target: "/repo".to_string(),
        max_recommendations: 10,
        available_tools: tool_set(&[
            "context:build",
            "dep-hygiene:check",
            "secret-scan:scan",
            "semgrep:scan",
            "threat-model:build",
            "triage:run",
            "verify:finding",
        ]),
        signals: rich_signals(),
    };

    let report = build_recommendation_report(request);
    let tools = recommendation_tools(&report);

    assert!(tools.contains(&"secret-scan:scan".to_string()));
    assert!(tools.contains(&"dep-hygiene:check".to_string()));
    assert!(tools.contains(&"threat-model:build".to_string()));
    assert!(tools.contains(&"triage:run".to_string()));
    assert!(tools.contains(&"verify:finding".to_string()));
    assert!(report
        .recommendations
        .iter()
        .any(
            |recommendation| recommendation.tool == "triage:run" && recommendation.requires_runtime
        ));
    assert!(report.recommendations.iter().any(|recommendation| {
        recommendation.tool == "threat-model:build"
            && recommendation
                .signals
                .contains(&"2 high/critical attack-surface boundary/boundaries".to_string())
            && recommendation
                .signals
                .contains(&"max attack-surface risk score 92".to_string())
            && recommendation
                .signals
                .contains(&"attack-surface risk tiers: critical=1, high=1, medium=2".to_string())
    }));
}

#[test]
fn omits_deferred_ai_tools_from_default_recommendations() {
    let mut signals = rich_signals();
    signals.threat_model_present = true;
    signals.threat_signal_count = 3;
    let request = RecommenderRequest {
        target: "/repo".to_string(),
        max_recommendations: 20,
        available_tools: tool_set(&[
            "carlini-threat-hunt:run",
            "context:build",
            "taint-iris-next:hunt",
            "threat-model:build",
        ]),
        signals,
    };

    let report = build_recommendation_report(request);
    let tools = recommendation_tools(&report);

    assert!(!tools.contains(&"taint-iris-next:hunt".to_string()));
    assert!(!tools.contains(&"carlini-threat-hunt:run".to_string()));
    assert!(!report
        .capabilities
        .skipped_missing_tools
        .contains(&"taint-iris-next:hunt".to_string()));
    assert!(!report
        .capabilities
        .skipped_missing_tools
        .contains(&"carlini-threat-hunt:run".to_string()));
}

#[test]
fn omits_recommendations_for_missing_capabilities() {
    let request = RecommenderRequest {
        target: "/repo".to_string(),
        max_recommendations: 10,
        available_tools: tool_set(&["context:build", "semgrep:scan"]),
        signals: rich_signals(),
    };

    let report = build_recommendation_report(request);
    let tools = recommendation_tools(&report);

    assert_eq!(tools, vec!["semgrep:scan", "context:build"]);
    assert!(report
        .capabilities
        .skipped_missing_tools
        .contains(&"codeql:scan".to_string()));
}

#[test]
fn codeql_recommendation_mentions_threat_model_related_cwes() {
    let mut signals = rich_signals();
    signals.threat_model_present = true;
    signals.threat_model_related_cwes = BTreeMap::from([
        ("CWE-20".to_string(), 2),
        ("CWE-918".to_string(), 1),
    ]);
    let request = RecommenderRequest {
        target: "/repo".to_string(),
        max_recommendations: 10,
        available_tools: tool_set(&["codeql:scan"]),
        signals,
    };

    let report = build_recommendation_report(request);

    assert!(report.recommendations.iter().any(|recommendation| {
        recommendation.tool == "codeql:scan"
            && recommendation
                .signals
                .contains(&"threat-model related CWEs: CWE-20=2, CWE-918=1".to_string())
    }));
}

#[test]
fn executor_reads_workspace_inventory_and_visible_capabilities() {
    let temp = tempdir().unwrap();
    let src = temp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"express":"latest"}}"#,
    )
    .unwrap();
    fs::write(temp.path().join("Dockerfile"), "FROM node:22\n").unwrap();
    fs::write(
        src.join("app.ts"),
        "import express from 'express';\nconst app = express();\napp.get('/users', (_req, res) => res.send('ok'));\napp.listen(3000);\n",
    )
    .unwrap();

    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &V2Config::default(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
    };

    let output = execute_module_recommender_tool(
        json!({ "maxRecommendations": 10 }),
        &ctx,
        vec![
            "context:build".to_string(),
            "dep-hygiene:check".to_string(),
            "iac-scan:scan".to_string(),
            "secret-scan:scan".to_string(),
            "semgrep:scan".to_string(),
        ],
    )
    .unwrap();

    let tools = output["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["tool"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(tools.contains(&"secret-scan:scan".to_string()));
    assert!(tools.contains(&"dep-hygiene:check".to_string()));
    assert!(tools.contains(&"iac-scan:scan".to_string()));
    assert_eq!(output["signals"]["routes"], json!(1));
    assert_eq!(output["signals"]["attackSurfaceMaxRiskScore"], json!(65));
    assert_eq!(
        output["signals"]["attackSurfaceRiskTiers"]["medium"],
        json!(1)
    );
    assert_eq!(
        output["signals"]["contextSource"],
        json!("deterministic-workspace-inventory")
    );
    assert_eq!(
        output["signals"]["attackSurfaceSource"],
        json!("deterministic-workspace-analysis")
    );
    assert_eq!(output["signals"]["findingsSource"], json!("unavailable"));
}

fn rich_signals() -> RepositorySignals {
    RepositorySignals {
        context_source: "deterministic-workspace-inventory".to_string(),
        attack_surface_source: "deterministic-workspace-analysis".to_string(),
        threat_model_source: "not-recorded".to_string(),
        findings_source: "workspace-findings-store".to_string(),
        source_files: 12,
        languages: vec!["TypeScript".to_string()],
        codeql_languages: vec!["typescript".to_string()],
        dependency_manifests: 2,
        config_files: 1,
        iac_files: 1,
        routes: 3,
        attack_surface_total: 4,
        attack_surface_kinds: BTreeMap::new(),
        attack_surface_risk_tiers: BTreeMap::from([
            ("critical".to_string(), 1),
            ("high".to_string(), 1),
            ("medium".to_string(), 2),
        ]),
        attack_surface_high_risk: 2,
        attack_surface_max_risk_score: 92,
        threat_model_present: false,
        threat_signal_count: 0,
        threat_model_threats: 0,
        threat_model_dfd_nodes: 0,
        threat_model_dfd_flows: 0,
        threat_model_trust_boundaries: 0,
        threat_model_related_cwes: BTreeMap::new(),
        findings_available: true,
        finding_count: 3,
        high_or_critical_findings: 1,
        first_finding_fingerprint: Some("fp-low".to_string()),
        first_high_finding_fingerprint: Some("fp-high".to_string()),
    }
}

#[test]
fn executor_reads_threat_model_dfd_artifact_shape() {
    let temp = tempdir().unwrap();
    fs::create_dir_all(temp.path().join("src")).unwrap();
    fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
    fs::write(temp.path().join("src/app.ts"), "export const ok = true;\n").unwrap();
    fs::write(
        temp.path().join(".kuzushi/threat-model.json"),
        r#"{
          "document": {
            "dfd": {
              "nodes": [{"id":"app"}, {"id":"data-store"}],
              "flows": [{"id":"flow-data-store"}],
              "trustBoundaries": [{"id":"tb-public-http"}]
            },
            "threats": [
              {"id":"DTM-001", "relatedCwe":["CWE-20", "CWE-918"]},
              {"id":"DTM-002", "relatedCwe":["CWE-20"]}
            ]
          }
        }"#,
    )
    .unwrap();

    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &V2Config::default(),
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
    };

    let output = execute_module_recommender_tool(
        json!({ "maxRecommendations": 10 }),
        &ctx,
        vec!["context:build".to_string(), "threat-model:build".to_string()],
    )
    .unwrap();

    assert_eq!(
        output["signals"]["threatModelSource"],
        json!(".kuzushi/threat-model.json")
    );
    assert_eq!(output["signals"]["threatSignalCount"], json!(4));
    assert_eq!(output["signals"]["threatModelThreats"], json!(2));
    assert_eq!(output["signals"]["threatModelDfdNodes"], json!(2));
    assert_eq!(output["signals"]["threatModelDfdFlows"], json!(1));
    assert_eq!(output["signals"]["threatModelTrustBoundaries"], json!(1));
    assert_eq!(output["signals"]["threatModelRelatedCwes"]["CWE-20"], json!(2));
    assert_eq!(output["signals"]["threatModelRelatedCwes"]["CWE-918"], json!(1));
}

fn tool_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

fn recommendation_tools(report: &RecommendationReport) -> Vec<String> {
    report
        .recommendations
        .iter()
        .map(|recommendation| recommendation.tool.clone())
        .collect()
}
