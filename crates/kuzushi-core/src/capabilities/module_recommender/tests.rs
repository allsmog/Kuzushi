use super::*;
use super::threat_model_signals::{
    threat_model_dfd_count, threat_model_related_cwes, threat_signal_count,
};
use crate::config::V2Config;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::workspace::WorkspaceTarget;
use serde_json::{json, Value};
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
            "license-scan:scan",
            "sbom-scan:scan",
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
    assert!(tools.contains(&"license-scan:scan".to_string()));
    assert!(tools.contains(&"sbom-scan:scan".to_string()));
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
            && recommendation.signals.contains(
                &"attack-surface kinds: background_job=1, file_upload_parse_path=1, http_route=1, rpc_handler=1, tenant_isolation_boundary=1"
                    .to_string()
            )
            && recommendation
                .signals
                .contains(&"frameworks: Express".to_string())
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
        ("CWE-200".to_string(), 1),
        ("CWE-640".to_string(), 1),
        ("CWE-862".to_string(), 1),
        ("CWE-863".to_string(), 1),
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
                .contains(
                    &"threat-model related CWEs: CWE-20=2, CWE-200=1, CWE-640=1, CWE-862=1, CWE-863=1, CWE-918=1"
                        .to_string()
                )
    }));
}

#[test]
fn recommends_cargo_audit_for_rust_dependency_signals() {
    let mut signals = rich_signals();
    signals.languages = vec!["Rust".to_string()];
    let request = RecommenderRequest {
        target: "/repo".to_string(),
        max_recommendations: 10,
        available_tools: tool_set(&["cargo-audit:scan"]),
        signals,
    };

    let report = build_recommendation_report(request);

    assert!(report.recommendations.iter().any(|recommendation| {
        recommendation.tool == "cargo-audit:scan"
            && recommendation.signals.contains(
                &"Rust project with 2 dependency manifest(s)".to_string()
            )
    }));
}

#[test]
fn recommender_counts_threat_model_related_cwe_aliases() {
    let threat_model = json!({
        "threats": [
            {"related_cwe": ["CWE-640"]},
            {"cwe": ["CWE-434", "CWE-640"]}
        ]
    });

    let counts = threat_model_related_cwes(Some(&threat_model));

    assert_eq!(counts.get("CWE-434"), Some(&1));
    assert_eq!(counts.get("CWE-640"), Some(&2));
}

#[test]
fn recommender_reads_enveloped_threat_model_document_signals() {
    let threat_model = json!({
        "data": {
            "document": {
                "dfd": {
                    "nodes": [{"id": "app"}],
                    "flows": [{"id": "flow-parser"}],
                    "trust_boundaries": [{"id": "tb-public"}]
                },
                "threats": [{"relatedCwe": ["CWE-502"]}]
            }
        }
    });

    assert_eq!(threat_signal_count(Some(&threat_model)), 2);
    assert_eq!(threat_model_dfd_count(Some(&threat_model), "nodes"), 1);
    assert_eq!(
        threat_model_dfd_count(Some(&threat_model), "trustBoundaries"),
        1
    );
    assert_eq!(
        threat_model_related_cwes(Some(&threat_model)).get("CWE-502"),
        Some(&1)
    );
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
        None,
        vec![
            "context:build".to_string(),
            "dep-hygiene:check".to_string(),
            "iac-scan:scan".to_string(),
            "secret-scan:scan".to_string(),
            "semgrep:scan".to_string(),
        ],
    )
    .unwrap();

    assert_eq!(output["status"], json!("completed"));

    let report = &output["data"];
    let tools = report["recommendations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["tool"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(tools.contains(&"secret-scan:scan".to_string()));
    assert!(tools.contains(&"dep-hygiene:check".to_string()));
    assert!(tools.contains(&"iac-scan:scan".to_string()));
    assert_eq!(report["signals"]["routes"], json!(1));
    assert_eq!(report["signals"]["frameworks"], json!(["Express"]));
    assert_eq!(report["signals"]["attackSurfaceMaxRiskScore"], json!(65));
    assert_eq!(
        report["signals"]["attackSurfaceRiskTiers"]["medium"],
        json!(1)
    );
    assert_eq!(
        report["signals"]["contextSource"],
        json!("deterministic-workspace-inventory")
    );
    assert_eq!(
        report["signals"]["attackSurfaceSource"],
        json!("deterministic-workspace-analysis")
    );
    assert_eq!(report["signals"]["findingsSource"], json!("unavailable"));
}

#[test]
fn executor_surfaces_backend_framework_signals() {
    let temp = tempdir().unwrap();
    fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
    fs::create_dir_all(temp.path().join("src/app/api/session")).unwrap();
    fs::create_dir_all(temp.path().join("config")).unwrap();
    fs::create_dir_all(temp.path().join("routes")).unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"next":"14.0.0"}}"#,
    )
    .unwrap();
    fs::write(temp.path().join("requirements.txt"), "django\n").unwrap();
    fs::write(
        temp.path().join("build.gradle"),
        "dependencies { implementation 'org.springframework.boot:spring-boot-starter-web' }\n",
    )
    .unwrap();
    fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
    fs::write(
        temp.path().join("composer.json"),
        r#"{"require":{"laravel/framework":"^10"}}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("Web.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src/main/java/app/UserController.java"),
        "@GetMapping(\"/users\")\nvoid users() {}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("config/routes.rb"),
        "Rails.application.routes.draw do\npost '/admin/invite', to: 'admin#invite'\nend\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("routes/web.php"),
        "<?php\nRoute::get('/users', [UserController::class, 'index']);\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("urls.py"),
        "from django.urls import path\nurlpatterns = [path('billing/api-keys/', views.keys)]\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("src/app/api/session/route.ts"),
        "import { NextRequest, NextResponse } from 'next/server';\nexport async function POST(request: NextRequest) { const sid = request.cookies.get('sid'); return NextResponse.json({ sid }); }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Program.cs"),
        "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.MapPost(\"/admin/invite\", Invite);\n",
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
        json!({ "maxRecommendations": 5 }),
        &ctx,
        None,
        vec!["context:build".to_string(), "threat-model:build".to_string()],
    )
    .unwrap();

    let report = &output["data"];
    assert_eq!(
        report["signals"]["frameworks"],
        json!(["ASP.NET Core", "Django", "Laravel", "Next.js", "Rails", "Spring"])
    );
    assert_eq!(report["signals"]["routes"], json!(7));
    assert!(report["recommendations"].as_array().unwrap().iter().any(|item| {
        item["tool"] == json!("context:build")
            && item["signals"]
                .as_array()
                .unwrap()
                .contains(&json!("frameworks: ASP.NET Core, Django, Laravel, Next.js, Rails, Spring"))
    }));
}

#[test]
fn executor_surfaces_grpc_rpc_handler_signals() {
    let temp = tempdir().unwrap();
    fs::create_dir_all(temp.path().join("svc")).unwrap();
    fs::write(
        temp.path().join("go.mod"),
        "module example.com/svc\nrequire google.golang.org/grpc v1.60.0\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        "[dependencies]\ntonic = \"0.11\"\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("svc/main.go"),
        "package main\nfunc main() { server := grpc.NewServer(); pb.RegisterGreeterGrpcServer(server, handler) }\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("svc/server.rs"),
        "async fn serve() { tonic::transport::Server::builder().add_service(GreeterServer::new(handler)); }\n",
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
        json!({ "maxRecommendations": 5 }),
        &ctx,
        None,
        vec!["context:build".to_string(), "threat-model:build".to_string()],
    )
    .unwrap();

    let report = &output["data"];
    assert_eq!(report["signals"]["frameworks"], json!(["Tonic", "gRPC"]));
    assert_eq!(report["signals"]["attackSurfaceKinds"]["rpc_handler"], json!(2));
    assert!(report["recommendations"].as_array().unwrap().iter().any(|item| {
        item["tool"] == json!("threat-model:build")
            && signal_contains(item, "rpc_handler=2")
    }));
}

#[test]
fn executor_surfaces_file_upload_attack_surface_signals() {
    let temp = tempdir().unwrap();
    fs::create_dir_all(temp.path().join("svc")).unwrap();
    fs::write(temp.path().join("requirements.txt"), "fastapi\n").unwrap();
    fs::write(
        temp.path().join("svc/main.py"),
        "from fastapi import FastAPI, File, UploadFile\napp = FastAPI()\n@app.post('/imports/file')\ndef upload(file: UploadFile = File(...)): pass\n",
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
        json!({ "maxRecommendations": 5 }),
        &ctx,
        None,
        vec!["context:build".to_string(), "threat-model:build".to_string()],
    )
    .unwrap();

    let report = &output["data"];
    assert_eq!(
        report["signals"]["attackSurfaceKinds"]["file_upload_parse_path"],
        json!(1)
    );
    assert!(report["recommendations"].as_array().unwrap().iter().any(|item| {
        item["tool"] == json!("threat-model:build")
            && signal_contains(item, "file_upload_parse_path=1")
    }));
}

#[test]
fn executor_surfaces_python_framework_signals_on_threat_model_recommendation() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("requirements.txt"),
        "falcon\nlitestar\nsanic\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("app.py"),
        "from falcon import App\nfrom litestar import post\nfrom sanic import Sanic\napp = App()\nclass Resource: pass\napp.add_route('/imports', Resource())\n@post('/orders')\ndef orders() -> None: pass\napi = Sanic('api')\n@api.post('/uploads')\ndef uploads(request): pass\n",
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
        json!({ "maxRecommendations": 5 }),
        &ctx,
        None,
        vec!["context:build".to_string(), "threat-model:build".to_string()],
    )
    .unwrap();

    let report = &output["data"];
    assert_eq!(
        report["signals"]["frameworks"],
        json!(["Falcon", "Litestar", "Sanic"])
    );
    assert_eq!(report["signals"]["routes"], json!(3));
    assert!(report["recommendations"].as_array().unwrap().iter().any(|item| {
        item["tool"] == json!("threat-model:build")
            && signal_contains(item, "frameworks: Falcon, Litestar, Sanic")
    }));
}

fn signal_contains(item: &Value, needle: &str) -> bool {
    item["signals"]
        .as_array()
        .is_some_and(|signals| signals.iter().any(|signal| signal_text_contains(signal, needle)))
}

fn signal_text_contains(signal: &Value, needle: &str) -> bool {
    signal
        .as_str()
        .is_some_and(|text| text.contains(needle))
}

fn rich_signals() -> RepositorySignals {
    RepositorySignals {
        context_source: "deterministic-workspace-inventory".to_string(),
        attack_surface_source: "deterministic-workspace-analysis".to_string(),
        threat_model_source: "not-recorded".to_string(),
        findings_source: "workspace-findings-store".to_string(),
        source_files: 12,
        languages: vec!["TypeScript".to_string()],
        frameworks: vec!["Express".to_string()],
        codeql_languages: vec!["typescript".to_string()],
        dependency_manifests: 2,
        config_files: 1,
        iac_files: 1,
        routes: 3,
        attack_surface_total: 4,
        attack_surface_kinds: BTreeMap::from([
            ("background_job".to_string(), 1),
            ("file_upload_parse_path".to_string(), 1),
            ("http_route".to_string(), 1),
            ("rpc_handler".to_string(), 1),
            ("tenant_isolation_boundary".to_string(), 1),
        ]),
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
    fs::create_dir_all(crate::workspace::workspace_state_root(temp.path())).unwrap();
    fs::write(temp.path().join("src/app.ts"), "export const ok = true;\n").unwrap();
    fs::write(
        crate::capabilities::persistent_threat_model_path(temp.path()),
        r#"{
          "document": {
            "dfd": {
              "nodes": [{"id":"app"}, {"id":"data-store"}],
              "flows": [{"id":"flow-data-store"}],
              "trustBoundaries": [{"id":"tb-public-http"}]
            },
            "threats": [
              {"id":"DTM-001", "relatedCwe":["CWE-20", "CWE-918"]},
              {"id":"DTM-002", "relatedCwe":["CWE-20"]},
              {"id":"DTM-003", "relatedCwe":["CWE-862", "CWE-863"]}
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
        None,
        vec!["context:build".to_string(), "threat-model:build".to_string()],
    )
    .unwrap();

    let report = &output["data"];
    let threat_model_source = crate::capabilities::persistent_threat_model_path(workspace.root())
        .strip_prefix(workspace.root())
        .unwrap()
        .display()
        .to_string();

    assert_eq!(
        report["signals"]["threatModelSource"],
        json!(threat_model_source)
    );
    assert_eq!(report["signals"]["threatSignalCount"], json!(5));
    assert_eq!(report["signals"]["threatModelThreats"], json!(3));
    assert_eq!(report["signals"]["threatModelDfdNodes"], json!(2));
    assert_eq!(report["signals"]["threatModelDfdFlows"], json!(1));
    assert_eq!(report["signals"]["threatModelTrustBoundaries"], json!(1));
    assert_eq!(report["signals"]["threatModelRelatedCwes"]["CWE-20"], json!(2));
    assert_eq!(
        report["signals"]["threatModelRelatedCwes"]["CWE-862"],
        json!(1)
    );
    assert_eq!(
        report["signals"]["threatModelRelatedCwes"]["CWE-863"],
        json!(1)
    );
    assert_eq!(report["signals"]["threatModelRelatedCwes"]["CWE-918"], json!(1));
}

#[test]
fn registry_recommender_returns_completed_result_envelope() {
    let temp = tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"express":"latest"}}"#,
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
    };
    let result = ModuleRegistry::with_v2_builtins()
        .execute_tool(
            "module-recommender:recommend",
            json!({"maxRecommendations": 5}),
            &ctx,
        )
        .unwrap();

    assert_eq!(result.get("status").and_then(Value::as_str), Some("completed"));
    assert!(result
        .get("summary")
        .and_then(Value::as_str)
        .is_some_and(|summary| summary.starts_with("Recommended ")));
    assert!(result
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty));
    assert!(result
        .pointer("/data/recommendations")
        .and_then(Value::as_array)
        .is_some());
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
