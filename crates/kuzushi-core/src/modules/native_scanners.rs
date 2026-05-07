use std::path::Path;

use anyhow::Result;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::findings::{Finding, StaticProofState};
use crate::iac_scan::{scan_iac, IacScanOptions};
use crate::scan::{
    index_codeql_sarif_as_static_evidence, CodeqlPersistedRun, CodeqlScanReport, CodeqlScanner,
    ScanCancellation, SemgrepPersistedRun, SemgrepScanReport, SemgrepScanner,
};
use crate::whitebox_static::{mark_whitebox_static_findings, whitebox_static_profile_requested};

use super::{
    binary_option, builtin_module, dag, opt, resolve_tool_target, target_option, tool_with_options,
    BuiltinModule, ModuleKind, ModuleRegistry, OptionType, ToolExecutionContext,
};

pub(super) fn register_modules(registry: &mut ModuleRegistry) {
    registry.register(semgrep_module());
    registry.register(codeql_module());
    registry.register(iac_scan_module());
}

pub(super) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    match name {
        "semgrep:scan" => run_semgrep_scan(input, ctx),
        "codeql:scan" => run_codeql_scan(input, ctx),
        "iac-scan:scan" => run_iac_scan(input, ctx),
        other => anyhow::bail!("native scanner tool {other:?} has no executor mapping"),
    }
}

fn run_semgrep_scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = SemgrepScanner::from_tool_input(&input)?;
    let mut findings = scanner.scan_with_cancel(&target, &ScanCancellation::default())?;
    let index_static_evidence = whitebox_static_profile_requested(&input)?;
    if index_static_evidence {
        mark_whitebox_static_findings(&mut findings, StaticProofState::SignalOnly)?;
    }
    let persisted = persist_semgrep_findings(&target, &findings, ctx, index_static_evidence)?;
    Ok(SemgrepScanReport::new(target.display().to_string(), findings, persisted).to_tool_json())
}

fn run_codeql_scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let scanner = CodeqlScanner::from_tool_input(&input)?;
    let mut output = scanner.scan_with_artifacts(&target, &ScanCancellation::default())?;
    let index_static_evidence = whitebox_static_profile_requested(&input)?;
    if index_static_evidence {
        mark_whitebox_static_findings(&mut output.findings, StaticProofState::SignalOnly)?;
    }
    let persisted = persist_codeql_findings(
        &target,
        &output.findings,
        ctx,
        &output.codeql_sarif_documents,
        index_static_evidence,
    )?;
    Ok(
        CodeqlScanReport::new(target.display().to_string(), output.findings, persisted)
            .to_tool_json(),
    )
}

fn run_iac_scan(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let options = IacScanOptions::from_tool_input(&input)?;
    let report = scan_iac(&target, &options, &ScanCancellation::default())?;
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding())
        .collect::<Vec<_>>();
    let persisted = persist_iac_findings(&target, &findings, ctx)?;
    let mut output = report.to_tool_json();
    if let Some(persisted) = persisted {
        output["data"]["persisted"] = json!(persisted);
    }
    Ok(output)
}

fn persist_semgrep_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    index_static_evidence: bool,
) -> Result<Option<SemgrepPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let static_evidence = if index_static_evidence {
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(workspace)?;
        Some(
            crate::static_evidence::index_semgrep_findings_as_static_evidence(
                &evidence_store,
                workspace.root(),
                findings,
            )?,
        )
    } else {
        None
    };

    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(SemgrepPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        static_evidence,
    }))
}

fn persist_codeql_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
    sarif_documents: &[String],
    index_static_evidence: bool,
) -> Result<Option<CodeqlPersistedRun>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let static_evidence = if index_static_evidence {
        let evidence_store = crate::static_evidence::StaticEvidenceStore::open(workspace)?;
        let mut combined = crate::static_evidence::StaticEvidenceIndexReport {
            db_path: evidence_store.db_path().to_string(),
            findings_indexed: 0,
            nodes_indexed: 0,
            edges_indexed: 0,
            node_ids: Vec::new(),
            edge_ids: Vec::new(),
        };
        for sarif in sarif_documents {
            let report =
                index_codeql_sarif_as_static_evidence(&evidence_store, workspace.root(), sarif)?;
            combined.findings_indexed += report.findings_indexed;
            combined.nodes_indexed += report.nodes_indexed;
            combined.edges_indexed += report.edges_indexed;
            combined.node_ids.extend(report.node_ids);
            combined.edge_ids.extend(report.edge_ids);
        }
        Some(combined)
    } else {
        None
    };

    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(CodeqlPersistedRun {
        run_id,
        findings_db: workspace.findings_db_path().display().to_string(),
        static_evidence,
    }))
}

fn persist_iac_findings(
    target: &Path,
    findings: &[Finding],
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<Value>> {
    let (Some(workspace), Some(store)) = (ctx.workspace, ctx.findings_store) else {
        return Ok(None);
    };

    workspace.ensure_state_dir()?;
    let run_id = Uuid::new_v4().to_string();
    store.insert_scan_run(&run_id, target, "running")?;
    for finding in findings {
        store.insert_finding(&run_id, finding)?;
    }
    store.complete_scan_run(&run_id, "completed", findings.len())?;

    Ok(Some(json!({
        "runId": run_id,
        "findingsDb": workspace.findings_db_path().display().to_string(),
    })))
}

fn semgrep_module() -> BuiltinModule {
    builtin_module(
        "semgrep",
        "Semgrep Scan",
        ModuleKind::Defense,
        "Native SAST path using semgrep JSON output.",
        vec![tool_with_options(
            "semgrep:scan",
            "Run semgrep and persist normalized findings.",
            vec![
                target_option(),
                binary_option("Semgrep binary path."),
                opt("config", OptionType::String, "Semgrep config name or path.")
                    .default(json!("auto")),
            ],
        )],
        vec![dag("semgrep:scan", "findings", &["context:build"])],
    )
}

fn codeql_module() -> BuiltinModule {
    builtin_module(
        "codeql",
        "CodeQL",
        ModuleKind::Defense,
        "GitHub's taint-query semantic analyzer: deeper than pattern scanners but slower.",
        vec![tool_with_options(
            "codeql:scan",
            "Run CodeQL and normalize semantic findings.",
            vec![
                target_option(),
                binary_option("CodeQL binary path."),
                opt("dbPath", OptionType::Path, "Existing CodeQL database path.").advanced(),
                opt("language", OptionType::Enum, "CodeQL language to analyze.").choices(&[
                    "javascript",
                    "python",
                    "csharp",
                    "c#",
                    "java",
                    "go",
                    "cpp",
                    "c++",
                    "c-cpp",
                    "swift",
                    "ruby",
                    "rust",
                    "typescript",
                ]),
                opt("suite", OptionType::String, "CodeQL query suite.").advanced(),
                opt("threads", OptionType::Int, "CodeQL worker thread count.").advanced(),
                opt("ram", OptionType::Int, "CodeQL RAM budget in MB.").advanced(),
                opt(
                    "multiLanguage",
                    OptionType::Bool,
                    "Analyze all detected CodeQL languages.",
                )
                .default(json!(false)),
            ],
        )],
        vec![dag("codeql:scan", "findings", &["context:build"])],
    )
}

fn iac_scan_module() -> BuiltinModule {
    builtin_module(
        "iac-scan",
        "IaC Scan",
        ModuleKind::Defense,
        "Scan IaC manifests for security misconfigurations.",
        vec![tool_with_options(
            "iac-scan:scan",
            "Scan Terraform, Kubernetes, and related IaC manifests.",
            vec![
                target_option(),
                opt("kind", OptionType::Enum, "IaC file family to scan.")
                    .choices(&[
                        "all",
                        "dockerfile",
                        "docker",
                        "github-actions",
                        "github_actions",
                        "actions",
                        "terraform",
                        "tf",
                    ])
                    .default(json!("all")),
                opt(
                    "maxFileBytes",
                    OptionType::Int,
                    "Maximum file size to scan.",
                )
                .default(json!(524288)),
            ],
        )],
        vec![dag("iac-scan:scan", "findings", &["context:build"])],
    )
}
