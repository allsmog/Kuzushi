use super::*;

impl ModuleRegistry {
    pub(in crate::modules) fn dispatch_catalog_tool(&self, name: &str) -> ToolDispatchResult {
        match name {
            "catalog:modules" => Some(Ok(json!(self
                .discoverable_modules()
                .map(|builtin| builtin.metadata())
                .collect::<Vec<_>>()))),
            "catalog:tools" => Some(Ok(json!(self.discoverable_tools().collect::<Vec<_>>()))),
            _ => None,
        }
    }

    pub(in crate::modules) fn dispatch_module_recommender_tool(
        &self,
        name: &str,
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
        runtime: Option<&dyn AgentRuntime>,
    ) -> ToolDispatchResult {
        match name {
            "module-recommender:recommend" => Some(
                crate::capabilities::module_recommender::execute_module_recommender_tool(
                    input.clone(),
                    ctx,
                    runtime,
                    visible_tool_names(self),
                ),
            ),
            _ => None,
        }
    }
}

fn visible_tool_names(registry: &ModuleRegistry) -> Vec<String> {
    registry
        .discoverable_tools()
        .filter(|tool| !matches!(tool.phase, ToolPhase::Prove | ToolPhase::Fix))
        .map(|tool| tool.name.clone())
        .collect()
}

pub(in crate::modules) fn dispatch_context_workspace_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "context:build" | "context-lite:index" => {
            dispatch_context_snapshot_tool(name, input, ctx, runtime)
        }
        "findings:lesson-generate" => Some(crate::capabilities::finding_lessons::execute_generate(
            input, ctx, runtime,
        )),
        "config:show" => Some(Ok(config_show_json(ctx))),
        "router:show" => Some(router_show_tool(input.clone(), ctx)),
        "workspace:status" => Some(Ok(workspace_status_json(ctx))),
        "coverage:sweep" => Some(run_coverage_sweep(input, ctx)),
        "coverage:baselines" => Some(run_coverage_baselines(ctx)),
        "coverage:recommend" => Some(run_coverage_recommend(input, ctx)),
        "worklist:rank" => Some(run_worklist_rank(input, ctx)),
        name if name.starts_with("fleet:") => dispatch_fleet_tool(name, input),
        "workspace:export-findings" => Some(export_workspace_findings_tool(input.clone(), ctx)),
        "workspace:import-findings" => Some(workspace_import_findings_tool(input, ctx)),
        name if name.starts_with("campaign:") => dispatch_campaign_tool(name, input, ctx),
        "engagement:aim" => Some(engagement_aim_tool(input, ctx)),
        "bounty:import-har" => Some(bounty_import_har_tool(input, ctx)),
        "bounty:import-burp" => Some(bounty_import_burp_tool(input, ctx)),
        name if name.starts_with("pack:") => dispatch_pack_tool(name, input, ctx, runtime),
        "entry-points:extract" => Some(run_entry_points_extract(input, ctx)),
        _ => dispatch_finding_ledger_tool(name, input, ctx),
    }
}

fn dispatch_pack_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "pack:lint" => Some(crate::capabilities::pack_lint::execute_pack_lint(
            input, ctx,
        )),
        "pack:suggest-shards" => Some(crate::capabilities::shard_suggest::execute_suggest_shards(
            input, ctx,
        )),
        "pack:scopes" => Some(super::super::pack_module::scopes::execute(input, ctx)),
        "pack:suggest-scopes" => Some(super::super::pack_module::suggest_scopes::execute(
            input, ctx, runtime,
        )),
        _ => None,
    }
}

fn dispatch_context_snapshot_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    let enricher = context_enrichment_adapter::RuntimeContextEnrichment::new(runtime);
    Some(context::build_context_snapshot(
        name,
        input.clone(),
        ctx,
        Some(&enricher),
    ))
}

fn dispatch_fleet_tool(name: &str, input: &Value) -> ToolDispatchResult {
    match name {
        "fleet:register" => Some(run_fleet_register(input)),
        "fleet:ingest" => Some(run_fleet_ingest()),
        "fleet:status" => Some(run_fleet_status()),
        "fleet:findings" => Some(run_fleet_findings(input)),
        "fleet:diff-findings" => Some(run_fleet_diff_findings(input)),
        _ => None,
    }
}

fn dispatch_campaign_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> ToolDispatchResult {
    use crate::capabilities::campaign;
    match name {
        "campaign:plan" => Some(campaign::execute_campaign_plan(input, ctx)),
        "campaign:status" => Some(campaign::execute_campaign_status(input, ctx)),
        "campaign:coverage" => Some(campaign::execute_campaign_coverage(input, ctx)),
        "campaign:approve-allowance" => Some(campaign::execute_approve_allowance(input, ctx)),
        "campaign:brief" => Some(campaign::execute_brief(input, ctx)),
        "campaign:study" => Some(campaign::execute_study_plan(input, ctx)),
        "campaign:context-study" => Some(campaign::execute_context_study(input, ctx)),
        "campaign:review-study" => Some(campaign::execute_review_study(input, ctx)),
        "campaign:context-map" => Some(campaign::execute_context_map(input, ctx)),
        "campaign:allowance" => Some(campaign::execute_allowance_status(input, ctx)),
        _ => None,
    }
}

fn dispatch_finding_ledger_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> ToolDispatchResult {
    match name {
        "findings:list" => Some(list_findings_tool(input, ctx)),
        "findings:goals" | "findings:goal-assess" => {
            Some(super::super::findings_goals::execute(name, input, ctx))
        }
        "findings:lessons" | "findings:lesson-save" | "findings:lesson-review" => {
            Some(super::super::findings_lessons::execute(name, input, ctx))
        }
        "findings:groups" => Some(super::super::findings_groups::execute(input, ctx)),
        "findings:dismiss" => Some(dismiss_finding_tool(input, ctx)),
        "findings:review-source" => Some(super::super::findings_source_review::execute(input, ctx)),
        "findings:relationships" | "findings:relationship" | "findings:relationship-batch" => Some(
            super::super::findings_relationships::execute_finding_relationship_tool(
                name, input, ctx,
            ),
        ),
        "findings:chains" => Some(crate::capabilities::chains::execute_findings_chains(
            input, ctx,
        )),
        "findings:ground" => {
            Some(crate::capabilities::findings_ground::execute_findings_ground(input, ctx))
        }
        "suppress:add" => Some(run_suppress_add(input, ctx)),
        "suppress:list" => Some(run_suppress_list(input, ctx)),
        "suppress:remove" => Some(run_suppress_remove(input, ctx)),
        _ => None,
    }
}

fn engagement_aim_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("engagement:aim requires an active workspace target")?;
    let request = crate::engagement::EngagementHarnessRequest {
        focus: string_input_any(input, &["focus"]),
        engines: string_array_or_csv_input(input, &["engines"]).unwrap_or_default(),
        budget_usd: optional_f64_input(input, &["budget", "budgetUsd", "budget_usd"])?,
    };
    let report = crate::engagement::write_engagement_harness(workspace, request)?;
    let output = format!(
        "engagement:aim wrote {}\nLegacy metadata only. Recorded budget is not enforced; no scan work is approved. Use campaign:study to review finite work and approve an allowance.",
        report.path.display()
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "path": report.path.display().to_string(),
            "harness": report.harness,
            "compatibility": {
                "budgetEnforced": false,
                "workApproved": false,
                "replacementTool": "campaign:study",
            },
        }),
    ))
}

fn optional_f64_input(input: &Value, keys: &[&str]) -> Result<Option<f64>> {
    for key in keys {
        let Some(value) = input.get(*key) else {
            continue;
        };
        if let Some(number) = value.as_f64() {
            return Ok(Some(number));
        }
        if let Some(raw) = value.as_str() {
            return raw
                .trim()
                .parse::<f64>()
                .map(Some)
                .with_context(|| format!("{key} must be a number"));
        }
        anyhow::bail!("{key} must be a number");
    }
    Ok(None)
}

pub(in crate::modules) fn config_show_json(ctx: &ToolExecutionContext<'_>) -> Value {
    let output = format!(
        "Effective configuration\nRuntime: {:?}\nModel: {}\nReasoning: {}\nCredential variable: {} (value hidden)\nInvestigation allowance: reviewed separately before model work.",
        ctx.config.runtime.kind,
        ctx.config.model.as_deref().unwrap_or("unconfigured"),
        ctx.config.runtime.thinking_level.as_deref().unwrap_or("unspecified"),
        ctx.config.runtime.api_key_env,
    );
    let data = json!({
        "config": ctx.config,
        "runtime": ctx.config.runtime.kind,
        "model": ctx.config.model,
    });
    crate::module_result::completed_output_result(output.clone(), output, data)
}

fn workspace_import_findings_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("workspace:import-findings requires an active workspace target")?;
    let path = bounty_import_path(input, "workspace:import-findings")?;
    let tool_label =
        string_input_any(input, &["tool"]).unwrap_or_else(|| "external-ledger".to_string());
    let summary = crate::findings::import::import_ledger_jsonl(workspace, &path, &tool_label)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "workspace:import-findings imported {} finding(s) ({} row(s) skipped) from {}",
            summary.imported, summary.skipped_rows, summary.source_path,
        ),
        "data": summary,
    }))
}

fn bounty_import_har_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("bounty:import-har requires an active workspace target")?;
    let path = bounty_import_path(input, "bounty:import-har")?;
    let summary = crate::findings::import::import_har(workspace, &path)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "bounty:import-har imported {} finding(s){} from {}",
            summary.imported,
            capture_skip_suffix(summary.skipped_out_of_scope, summary.skipped_unusable),
            summary.source_path,
        ),
        "data": summary,
    }))
}

fn bounty_import_burp_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("bounty:import-burp requires an active workspace target")?;
    let path = bounty_import_path(input, "bounty:import-burp")?;
    let summary = crate::findings::import::import_burp_xml(workspace, &path)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "bounty:import-burp imported {} finding(s){} from {}",
            summary.imported,
            capture_skip_suffix(summary.skipped_out_of_scope, summary.skipped_unusable),
            summary.source_path,
        ),
        "data": summary,
    }))
}

fn bounty_import_path(input: &Value, tool: &str) -> Result<std::path::PathBuf> {
    let raw = input
        .get("path")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("{tool} requires path=<file>"))?;
    Ok(std::path::PathBuf::from(raw))
}

/// Name every entry the capture carried that did not become a finding. A
/// silent drop would leave the operator comparing the import count against
/// their capture with no explanation for the difference.
fn capture_skip_suffix(out_of_scope: usize, unusable: usize) -> String {
    crate::findings::import::capture_skip_phrase(out_of_scope, unusable)
        .map(|phrase| format!(" ({phrase})"))
        .unwrap_or_default()
}

pub(in crate::modules) fn workspace_status_json(ctx: &ToolExecutionContext<'_>) -> Value {
    let output = workspace_status_output(ctx);
    let pending_checkpoints = ctx
        .workspace
        .map(|workspace| crate::run_artifacts::pending_stage_checkpoints(workspace.root()))
        .unwrap_or_default();
    let data = json!({
        "active": ctx.workspace.is_some(),
        "root": ctx.workspace.map(|workspace| workspace.root().display().to_string()),
        "stateDir": ctx.workspace.map(|workspace| workspace.state_dir().display().to_string()),
        "findingsDb": ctx.workspace.map(|workspace| workspace.findings_db_path().display().to_string()),
        "runtime": ctx.config.runtime.kind,
        "model": ctx.config.model,
        "pendingStageCheckpoints": pending_checkpoints.iter().map(|checkpoint| json!({
            "tool": checkpoint.tool,
            "sourceRunId": checkpoint.source_run_id,
            "completedStages": checkpoint.completed_stages,
            "currentStage": checkpoint.current_stage,
            "modifiedAtUnix": checkpoint.modified_at_unix,
            "reuseEligible": checkpoint.reuse_eligible,
        })).collect::<Vec<_>>(),
    });
    crate::module_result::completed_output_result(output.clone(), output, data)
}

pub(in crate::modules) fn list_findings_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let filter = FindingListFilter::from_tool_input(input)?;
    let request = crate::findings::FindingPageRequest::from_tool_input(input)?;
    let store = ctx
        .findings_store
        .context("findings:list requires a findings store")?;
    let workspace = ctx
        .workspace
        .context("findings:list requires an active workspace")?;
    let requested_workspace = crate::WorkspaceTarget::new(findings_provenance_target(input, ctx)?)?;
    anyhow::ensure!(
        requested_workspace.root() == workspace.root(),
        "findings:list target differs from the active workspace; switch target explicitly"
    );
    let page = crate::findings::read_finding_page(
        store,
        workspace,
        &filter,
        crate::findings::IdentityFoldPolicy::Legacy,
        &request,
    )?;
    let mut result = page.to_tool_json();
    result["data"]["batchId"] = serde_json::json!(filter.batch_id);
    Ok(result)
}

pub(in crate::modules) fn dismiss_finding_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let store = ctx
        .findings_store
        .context("findings:dismiss requires a findings store")?;
    let reference = string_input_any(input, &["fingerprint", "finding", "reference", "id"])
        .context("findings:dismiss requires fingerprint=<ref>")?;
    let reason_raw = string_input_any(input, &["reason"])
        .context("findings:dismiss requires reason=<false_positive|acceptable_risk|wont_fix|used_in_tests|no_time_to_fix>")?;
    let reason = crate::findings::DismissReason::from_str(&reason_raw)
        .with_context(|| format!("unknown dismissal reason {reason_raw:?}"))?;
    let note =
        string_input_any(input, &["note"]).context("findings:dismiss requires note=<text>")?;
    let author = string_input_any(input, &["author"]).unwrap_or_else(|| "operator".to_string());
    let finding = resolve_dismiss_target(store, &reference)?;
    let finding_id = finding
        .id
        .context("dismiss target has no persisted finding id")?;
    let decision_id = store.append_dismissal(finding_id, reason, &note, &author)?;
    let output = format!(
        "dismissed {} as {} (decision #{decision_id})",
        finding.fingerprint,
        reason.as_str(),
    );
    Ok(crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "decisionId": decision_id,
            "findingId": finding_id,
            "fingerprint": finding.fingerprint,
            "identityId": finding.identity_id,
            "reason": reason.as_str(),
            "note": note,
            "dismissedBy": author,
        }),
    ))
}

fn resolve_dismiss_target(
    store: &crate::findings::FindingStore,
    reference: &str,
) -> Result<crate::findings::Finding> {
    store
        .get_finding_by_operator_reference(reference)?
        .with_context(|| format!("no finding found for {reference:?}"))
}

fn findings_provenance_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<std::path::PathBuf> {
    if let Some(target) = input.get("target").and_then(Value::as_str) {
        let trimmed = target.trim();
        if trimmed.is_empty() {
            anyhow::bail!("findings:list provenance filters require a non-empty target");
        }
        let candidate = std::path::PathBuf::from(trimmed);
        return Ok(if candidate.is_absolute() {
            candidate
        } else {
            ctx.workspace
                .map(|workspace| workspace.root().join(candidate))
                .context("findings:list provenance filters require an active workspace")?
        });
    }
    ctx.workspace
        .map(|workspace| workspace.root().to_path_buf())
        .context("findings:list provenance filters require an active workspace or target")
}

pub(in crate::modules) fn dispatch_native_security_tool(
    registry: &ModuleRegistry,
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    if native_scanner_tool(name) {
        return Some(native_scanners::execute_tool(
            name,
            input.clone(),
            ctx,
            runtime,
        ));
    }
    match name {
        "dep-hygiene:check" => Some(run_dep_hygiene_tool(input, ctx)),
        "secret-scan:scan" => Some(run_secret_scan_tool(input, ctx)),
        "sast:scan" => Some(run_sast_scan_with_registry(
            registry,
            input.clone(),
            ctx,
            runtime,
        )),
        "cpg:build" => Some(run_cpg_build(input, ctx)),
        "codeql:create-db" => Some(run_codeql_create_db(input, ctx)),
        "fuzz:run" => Some(run_fuzz_run(input, ctx)),
        "fuzz:author" => Some(run_fuzz_author(input, ctx, runtime)),
        "fuzz:import" => Some(run_fuzz_import(input, ctx)),
        "fuzz:prove" => Some(run_fuzz_prove(input, ctx)),
        "fuzz:sweep" => Some(run_fuzz_sweep(input, ctx)),
        "fuzz:differential" => Some(run_fuzz_differential(input, ctx)),
        "fuzz:status" => Some(run_fuzz_status(input, ctx)),
        _ => None,
    }
}

fn native_scanner_tool(name: &str) -> bool {
    matches!(
        name,
        "semgrep:scan"
            | "codeql:scan"
            | "iac-scan:scan"
            | "cargo-audit:scan"
            | "govulncheck:scan"
            | "license-scan:scan"
            | "sbom-scan:scan"
            | "exploit-chain:scan"
            | "android-apk:check-env"
            | "android-apk:prepare"
            | "android-apk:manifest-scan"
            | "android-apk:network-security-config"
            | "android-apk:fileprovider-scan"
            | "android-apk:code-scan"
            | "android-apk:sast-handoff"
            | "android-apk:native-libs"
            | "android-apk:hybrid-detect"
            | "android-apk:scan"
    )
}

pub(in crate::modules) fn run_dep_hygiene_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "dep-hygiene:check",
        &target,
        || run_dep_hygiene_inspection(ctx, &target),
    )
}

fn run_dep_hygiene_inspection(
    ctx: &ToolExecutionContext<'_>,
    target: &std::path::Path,
) -> Result<Value> {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "check",
                format!("dep-hygiene start · target={}", target.display()),
            )
            .emit();
    }
    let inspection = match ctx.with_cancellation(|cancel| {
        crate::scan::engines::dep_hygiene::inspect_dependency_hygiene(target, cancel)
    }) {
        Ok(report) => report,
        Err(error) => return Ok(failed_tool_output("dep-hygiene:check", &target, error)),
    };
    let store_result = store_dep_hygiene_findings(&inspection.report, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step("done", "check", "dep-hygiene inspection finished")
            .emit();
    }
    Ok(output_with_core_findings(
        inspection.to_tool_json(),
        store_result,
    ))
}

pub(in crate::modules) fn run_secret_scan_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "scan",
                format!("secret-scan start · target={}", target.display()),
            )
            .emit();
    }
    let options = SecretScanOptions::from_tool_input(input)?;
    let report = match ctx.with_cancellation(|cancel| scan_for_secrets(&target, &options, cancel)) {
        Ok(report) => report,
        Err(error) => return Ok(failed_tool_output("secret-scan:scan", &target, error)),
    };
    let store_result = store_secret_scan_findings(&report, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace.step("done", "scan", "secret-scan finished").emit();
    }
    Ok(output_with_core_findings(
        report.to_tool_json(),
        store_result,
    ))
}

struct StoredCoreFindings {
    core_findings: Vec<crate::findings::Finding>,
    persisted: Option<crate::findings::GenericPersistedRun>,
}

fn store_dep_hygiene_findings(
    report: &crate::dep_hygiene::DepHygieneReport,
    ctx: &ToolExecutionContext<'_>,
) -> Result<StoredCoreFindings> {
    let target = std::path::Path::new(&report.target);
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding(target))
        .collect::<Vec<_>>();
    let persisted = crate::findings::persist_tool_findings(ctx, target, &findings)?;
    let core_findings = output_core_findings(findings, &persisted, ctx.findings_store)?;
    Ok(StoredCoreFindings {
        core_findings,
        persisted,
    })
}

fn store_secret_scan_findings(
    report: &crate::secret_scan::SecretScanReport,
    ctx: &ToolExecutionContext<'_>,
) -> Result<StoredCoreFindings> {
    let target = std::path::Path::new(&report.target);
    let findings = report
        .findings
        .iter()
        .map(|finding| finding.to_core_finding())
        .collect::<Vec<_>>();
    let persisted = crate::findings::persist_tool_findings(ctx, target, &findings)?;
    let core_findings = output_core_findings(findings, &persisted, ctx.findings_store)?;
    Ok(StoredCoreFindings {
        core_findings,
        persisted,
    })
}

fn output_core_findings(
    findings: Vec<crate::findings::Finding>,
    persisted: &Option<crate::findings::GenericPersistedRun>,
    store: Option<&crate::findings::FindingStore>,
) -> Result<Vec<crate::findings::Finding>> {
    let Some(persisted) = persisted else {
        return Ok(findings);
    };
    let Some(store) = store else {
        return Ok(findings);
    };
    let stored = store.list_findings_for_scan_id(&persisted.run_id)?;
    Ok(if stored.is_empty() { findings } else { stored })
}

fn output_with_core_findings(mut output: Value, store_result: StoredCoreFindings) -> Value {
    output["data"]["coreFindings"] = json!(store_result.core_findings);
    if let Some(persisted) = store_result.persisted {
        output["data"]["persisted"] = json!(persisted);
    }
    output
}

pub(in crate::modules) fn dispatch_agentic_security_tool(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> ToolDispatchResult {
    match name {
        "agentic-sast:scan" if agentic_sast_chunked_strategy(input) => {
            Some(run_chunked_agentic_sast_tool(input, ctx, runtime))
        }
        "agentic-sast:scan" => Some(run_agentic_sast_tool(input, ctx, runtime)),
        "variant:lift-pattern" => Some(run_variant_lift_pattern(input.clone(), ctx, runtime)),
        "variant:hunt" => Some(run_variant_hunt(input.clone(), ctx, runtime)),
        "ndiff:fetch-cve" => Some(run_ndiff_fetch_cve(input.clone())),
        "ndiff:extract-fix-pattern" => {
            Some(run_ndiff_extract_fix_pattern(input.clone(), ctx, runtime))
        }
        "ndiff:hunt-variants" => Some(run_ndiff_hunt_variants(input.clone(), ctx, runtime)),
        "carlini-threat-hunt:run" | "offense-review:threat-hunt" => {
            Some(run_carlini_threat_hunt(input.clone(), ctx, runtime))
        }
        "pipeline:taint-cwe-select" => Some(run_taint_cwe_select(input.clone(), ctx, runtime)),
        "taint-iris:hunt" => Some(run_taint_iris_tool(input, ctx, runtime)),
        name if name.starts_with("taint-iris-next:") => {
            dispatch_taint_next(name, input, ctx, runtime)
        }
        _ => None,
    }
}

fn agentic_sast_chunked_strategy(input: &Value) -> bool {
    input
        .get("strategy")
        .and_then(Value::as_str)
        .is_some_and(|strategy| strategy.trim().eq_ignore_ascii_case("chunked"))
}

fn run_chunked_agentic_sast_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    run_full_mode_hunt_tool(input.clone(), ctx, runtime)
}

pub(in crate::modules) fn run_agentic_sast_tool(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    crate::workspace::source_snapshot::run_source_bound_tool(
        ctx,
        "agentic-sast:scan",
        &target,
        || Ok(run_agentic_sast_report(input, ctx, runtime)?.to_tool_json()),
    )
}

fn dispatch_taint_next(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Option<Result<Value>> {
    match name {
        "taint-iris-next:hunt" => Some(run_taint_iris_next_tool(input, ctx, runtime)),
        "taint-iris-next:dataflow-plan" => Some(run_taint_iris_next_plan_tool(input, ctx)),
        "taint-iris-next:source-sink-trace" => Some(run_taint_iris_next_trace_tool(input, ctx)),
        "taint-iris-next:finding-review" => {
            Some(run_taint_iris_next_review_tool(input, ctx, runtime))
        }
        "taint-iris-next:catalog" => Some(run_taint_iris_next_catalog_tool(input, ctx, runtime)),
        "taint-iris-next:catalog-read" => Some(
            crate::capabilities::taint_iris_next::read_catalog_draft(input, ctx),
        ),
        "taint-iris-next:catalog-accept" => Some(
            crate::capabilities::taint_iris_next::accept_catalog_draft(input, ctx),
        ),
        "taint-iris-next:import-sinks" => Some(run_taint_iris_next_import_sinks_tool(input, ctx)),
        "taint-iris-next:codeql-db" => {
            Some(run_taint_iris_next_codeql_db_tool(input, ctx, runtime))
        }
        _ => None,
    }
}
