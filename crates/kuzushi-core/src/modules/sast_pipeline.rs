use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::carlini_threat_hunt::{run_carlini_threat_hunt_report, CarliniThreatHuntReport};
use crate::findings::StaticProofState;
use crate::patch::run_patch_finding;
use crate::runtime::AgentRuntime;
use crate::scan::{
    run_scan_engines_with_options, scan_engines_for_tasks, ScanEngine, ScanRun, ScanRunOptions,
};
use crate::systems_hunt::{run_systems_hunt_report, SystemsHuntReport};
use crate::whitebox_static::{apply_whitebox_static_sast_policy, WhiteboxStaticPolicy};

use super::agentic_sast::{run_agentic_sast_report, split_agentic_sast_tasks, AgenticSastReport};
use super::input::{bool_input, parse_sast_severity_filter, parse_sast_tasks, string_input_any};
use super::sast_run::{
    fingerprints_for_sast_runs, sast_patch_input, true_positive_fingerprints_for_sast_runs,
    write_candidate_semgrep_rules_json, write_patch_jsonl, write_sast_scan_input,
    write_sast_summary, write_static_narratives_json, write_static_ranking_json,
    write_static_variants_json, write_triage_jsonl, write_verify_jsonl,
    write_whitebox_diff_scope_json, write_whitebox_suppressions_json, SastRunArtifacts, SastRunIds,
};
use super::taint_iris::{run_taint_iris_report, TaintIrisReport};
use super::taint_iris_next::{run_taint_iris_next_report, TaintIrisNextReport};
use super::triage::run_triage;
use super::verify::run_verify_finding;
use super::ToolExecutionContext;

struct SastPipelineReports {
    native: Option<ScanRun>,
    agentic: Option<AgenticSastReport>,
    carlini: Option<CarliniThreatHuntReport>,
    taint_iris: Option<TaintIrisReport>,
    taint_iris_next: Option<TaintIrisNextReport>,
    systems_hunt: Option<SystemsHuntReport>,
    engine_ids: Vec<&'static str>,
}

impl SastPipelineReports {
    fn findings_count(&self) -> usize {
        self.native.as_ref().map_or(0, |run| run.findings_count)
            + self.agentic.as_ref().map_or(0, |report| report.count)
            + self.carlini.as_ref().map_or(0, |report| report.count)
            + self.taint_iris.as_ref().map_or(0, |report| report.count)
            + self
                .taint_iris_next
                .as_ref()
                .map_or(0, |report| report.count)
            + self.systems_hunt.as_ref().map_or(0, |report| report.count)
    }

    fn primary_run_id(&self) -> Result<String> {
        self.native_run_id()
            .or_else(|| self.agentic_run_id())
            .or_else(|| self.carlini_run_id())
            .or_else(|| self.taint_iris_run_id())
            .or_else(|| self.taint_iris_next_run_id())
            .or_else(|| self.systems_hunt_run_id())
            .context("sast:scan completed without a persisted run id")
    }

    fn run_ids(&self, primary: String) -> SastRunIds {
        SastRunIds {
            primary,
            native: self.native_run_id(),
            agentic: self.agentic_run_id(),
            carlini: self.carlini_run_id(),
            taint_iris: self.taint_iris_run_id(),
            taint_iris_next: self.taint_iris_next_run_id(),
            systems_hunt: self.systems_hunt_run_id(),
        }
    }

    fn native_run_id(&self) -> Option<String> {
        self.native.as_ref().map(|run| run.id.clone())
    }

    fn agentic_run_id(&self) -> Option<String> {
        self.agentic
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    fn carlini_run_id(&self) -> Option<String> {
        self.carlini
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    fn taint_iris_run_id(&self) -> Option<String> {
        self.taint_iris
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    fn taint_iris_next_run_id(&self) -> Option<String> {
        self.taint_iris_next
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }

    fn systems_hunt_run_id(&self) -> Option<String> {
        self.systems_hunt
            .as_ref()
            .and_then(|report| report.persisted.as_ref())
            .map(|persisted| persisted.run_id.clone())
    }
}

fn run_sast_pipeline_reports(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    workspace: &crate::workspace::WorkspaceTarget,
    store: &crate::findings::FindingStore,
    options: &ScanRunOptions,
) -> Result<SastPipelineReports> {
    let tasks = parse_sast_tasks(input)?;
    let selected = SastTaskSelection::from_tasks(tasks)?;
    selected.ensure_non_empty()?;
    let mut reports = SastPipelineReports {
        native: selected.run_native(workspace, store, options)?,
        agentic: None,
        carlini: None,
        taint_iris: None,
        taint_iris_next: None,
        systems_hunt: None,
        engine_ids: selected.engine_ids.clone(),
    };
    fill_agentic_reports(&mut reports, &selected, input, ctx, runtime)?;
    Ok(reports)
}

struct SastTaskSelection {
    scanners: Vec<Box<dyn ScanEngine>>,
    run_agentic: bool,
    run_carlini: bool,
    run_taint_iris: bool,
    run_taint_iris_next: bool,
    run_systems_hunt: bool,
    engine_ids: Vec<&'static str>,
}

impl SastTaskSelection {
    fn from_tasks(tasks: Vec<String>) -> Result<Self> {
        let (
            native_tasks,
            run_agentic,
            run_carlini,
            run_taint_iris,
            run_taint_iris_next,
            run_systems_hunt,
        ) = split_agentic_sast_tasks(tasks);
        let scanners = selected_native_scanners(
            &native_tasks,
            run_agentic || run_carlini || run_taint_iris || run_taint_iris_next || run_systems_hunt,
        )?;
        let engine_ids = scanners
            .iter()
            .map(|scanner| scanner.id())
            .collect::<Vec<_>>();
        Ok(Self {
            scanners,
            run_agentic,
            run_carlini,
            run_taint_iris,
            run_taint_iris_next,
            run_systems_hunt,
            engine_ids,
        })
    }

    fn ensure_non_empty(&self) -> Result<()> {
        if self.scanners.is_empty() && !self.has_agentic_task() {
            anyhow::bail!("sast:scan selected no scan engines");
        }
        Ok(())
    }

    fn has_agentic_task(&self) -> bool {
        self.run_agentic
            || self.run_carlini
            || self.run_taint_iris
            || self.run_taint_iris_next
            || self.run_systems_hunt
    }

    fn run_native(
        &self,
        workspace: &crate::workspace::WorkspaceTarget,
        store: &crate::findings::FindingStore,
        options: &ScanRunOptions,
    ) -> Result<Option<ScanRun>> {
        if self.scanners.is_empty() {
            Ok(None)
        } else {
            Ok(Some(run_scan_engines_with_options(
                workspace,
                store,
                &self.scanners,
                options,
            )?))
        }
    }
}

fn selected_native_scanners(
    native_tasks: &[String],
    only_agentic_tasks: bool,
) -> Result<Vec<Box<dyn ScanEngine>>> {
    if native_tasks.is_empty() && only_agentic_tasks {
        Ok(Vec::new())
    } else {
        scan_engines_for_tasks(native_tasks)
    }
}

fn fill_agentic_reports(
    reports: &mut SastPipelineReports,
    selected: &SastTaskSelection,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<()> {
    if selected.run_agentic {
        reports.engine_ids.push("agentic");
        reports.agentic = Some(run_agentic_sast_report(input, ctx, runtime)?);
    }
    if selected.run_carlini {
        reports.engine_ids.push("carlini-threat-hunt");
        reports.carlini = Some(run_carlini_threat_hunt_report(input, ctx, runtime)?);
    }
    if selected.run_taint_iris {
        reports.engine_ids.push("taint-iris");
        reports.taint_iris = Some(run_taint_iris_report(input, ctx, runtime)?);
    }
    if selected.run_taint_iris_next {
        reports.engine_ids.push("taint-iris-next");
        reports.taint_iris_next = Some(run_taint_iris_next_report(
            &taint_iris_next_hunt_input(input),
            ctx,
            runtime,
        )?);
    }
    if selected.run_systems_hunt {
        reports.engine_ids.push("systems-hunt");
        reports.systems_hunt = Some(run_systems_hunt_report(input, ctx, runtime)?);
    }
    Ok(())
}

fn taint_iris_next_hunt_input(input: &Value) -> Value {
    let mut next_input = input.clone();
    if let Value::Object(object) = &mut next_input {
        if should_force_taint_iris_next_hunt_mode(object.get("mode")) {
            object.insert("mode".to_string(), json!("hunt"));
        }
    }
    next_input
}

fn should_force_taint_iris_next_hunt_mode(mode: Option<&Value>) -> bool {
    mode.and_then(Value::as_str)
        .map(str::trim)
        .map(|mode| matches!(mode, "standard" | "whitebox-static"))
        .unwrap_or(true)
}

struct SastScanRequests {
    verify: bool,
    auto_patch: bool,
    triage: bool,
}

impl SastScanRequests {
    fn from_input(input: &Value) -> Result<Self> {
        let verify = bool_input(input, &["verify"])?;
        let auto_patch = bool_input(input, &["autoPatch", "auto_patch"])?;
        let triage =
            bool_input(input, &["triage", "aiTriage", "ai_triage"])? || verify || auto_patch;
        Ok(Self {
            verify,
            auto_patch,
            triage,
        })
    }

    fn needs_verification(&self) -> bool {
        self.verify || self.auto_patch
    }
}

fn sast_scan_options(input: &Value, whitebox_static: bool) -> Result<ScanRunOptions> {
    Ok(ScanRunOptions {
        severity: parse_sast_severity_filter(input)?,
        tasks: None,
        static_proof_state: whitebox_static.then_some(StaticProofState::SignalOnly),
        index_static_evidence: whitebox_static,
    })
}

#[derive(Default)]
struct WhiteboxArtifacts {
    static_ranking: Option<Value>,
    static_narratives: Option<Value>,
    static_variants: Option<Value>,
    candidate_semgrep_rules: Option<Value>,
    whitebox_suppressions: Option<Value>,
    whitebox_diff: Option<Value>,
}

impl WhiteboxArtifacts {
    fn write(
        enabled: bool,
        input: &Value,
        workspace: &crate::workspace::WorkspaceTarget,
        store: &crate::findings::FindingStore,
        run_ids: &SastRunIds,
        artifacts: &SastRunArtifacts,
    ) -> Result<Self> {
        if !enabled {
            return Ok(Self::default());
        }

        let static_ranking = Some(write_static_ranking_json(
            workspace, store, run_ids, artifacts,
        )?);
        let static_narratives = Some(write_static_narratives_json(
            store,
            run_ids,
            artifacts,
            static_ranking.as_ref(),
        )?);
        let whitebox_diff = match string_input_any(input, &["diffBase", "diff_base"]) {
            Some(diff_base) => Some(write_whitebox_diff_scope_json(
                workspace, store, run_ids, artifacts, &diff_base,
            )?),
            None => None,
        };

        Ok(Self {
            static_ranking,
            static_narratives,
            static_variants: Some(write_static_variants_json(
                workspace, store, run_ids, artifacts,
            )?),
            candidate_semgrep_rules: Some(write_candidate_semgrep_rules_json(
                workspace, store, run_ids, artifacts,
            )?),
            whitebox_suppressions: Some(write_whitebox_suppressions_json(
                workspace, store, run_ids, artifacts,
            )?),
            whitebox_diff,
        })
    }

    fn append_output_lines(&self, lines: &mut Vec<String>) {
        lines.push(
            "  Mode: whitebox-static (static-only; verify, dynamic analysis, PoC, and patch disabled)"
                .to_string(),
        );
        self.append_static_ranking_line(lines);
        self.append_static_narrative_line(lines);
        self.append_static_variants_line(lines);
        self.append_candidate_rule_line(lines);
        self.append_suppression_line(lines);
        self.append_diff_line(lines);
    }

    fn append_static_ranking_line(&self, lines: &mut Vec<String>) {
        let Some(top) = self
            .static_ranking
            .as_ref()
            .and_then(|ranking| ranking.pointer("/ranked/0"))
        else {
            return;
        };
        let score = top
            .pointer("/impact/total")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        let title = top
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("top static-impact finding");
        lines.push(format!("  Static ranking: top score {score} · {title}"));
    }

    fn append_static_narrative_line(&self, lines: &mut Vec<String>) {
        let Some(top) = self
            .static_narratives
            .as_ref()
            .and_then(|narratives| narratives.pointer("/narratives/0"))
        else {
            return;
        };
        let location = top
            .get("location")
            .and_then(Value::as_str)
            .unwrap_or("top static finding");
        lines.push(format!(
            "  Static narrative: trigger path summarized for {location}"
        ));
    }

    fn append_static_variants_line(&self, lines: &mut Vec<String>) {
        let Some(count) = optional_positive_count(&self.static_variants, "count") else {
            return;
        };
        lines.push(format!(
            "  Static variants: {count} code-cited candidate(s), none confirmed by inheritance"
        ));
    }

    fn append_candidate_rule_line(&self, lines: &mut Vec<String>) {
        let Some(count) = optional_positive_count(&self.candidate_semgrep_rules, "count") else {
            return;
        };
        let validated = self
            .candidate_semgrep_rules
            .as_ref()
            .and_then(|rules| rules.get("validationPassed"))
            .and_then(Value::as_u64)
            .unwrap_or_default();
        lines.push(format!(
            "  Candidate Semgrep rules: {count} disabled candidate(s), {validated} fixture-validated"
        ));
    }

    fn append_suppression_line(&self, lines: &mut Vec<String>) {
        let Some(suppression_report) = self.whitebox_suppressions.as_ref() else {
            return;
        };
        let suppressed = json_u64(suppression_report, "suppressedCount");
        let stale = json_u64(suppression_report, "staleCount");
        if suppressed > 0 || stale > 0 {
            lines.push(format!(
                "  False-positive memory: {suppressed} active suppression match(es), {stale} stale; findings remain visible in audit/report output"
            ));
        }
    }

    fn append_diff_line(&self, lines: &mut Vec<String>) {
        let Some(diff_report) = self.whitebox_diff.as_ref() else {
            return;
        };
        let changed_files = json_pointer_u64(diff_report, "/summary/changedFiles");
        let new_findings = json_pointer_u64(diff_report, "/summary/newFindings");
        let changed_context = json_pointer_u64(diff_report, "/summary/changedContextFindings");
        let fixed = json_pointer_u64(diff_report, "/summary/fixedFindings");
        lines.push(format!(
            "  Diff scope: {changed_files} changed file(s), {new_findings} new, {changed_context} changed-context, {fixed} fixed"
        ));
    }

    fn artifact_paths(&self, artifacts: &SastRunArtifacts) -> WhiteboxArtifactPaths {
        WhiteboxArtifactPaths {
            static_narratives: artifact_path_if_present(
                &self.static_narratives,
                artifacts,
                "static-narratives.json",
            ),
            static_variants: artifact_path_if_present(
                &self.static_variants,
                artifacts,
                "static-variants.json",
            ),
            candidate_semgrep_rules: artifact_path_if_present(
                &self.candidate_semgrep_rules,
                artifacts,
                "candidate-semgrep-rules.json",
            ),
            whitebox_suppressions: artifact_path_if_present(
                &self.whitebox_suppressions,
                artifacts,
                "whitebox-suppressions.json",
            ),
            whitebox_diff: artifact_path_if_present(
                &self.whitebox_diff,
                artifacts,
                "whitebox-diff-scope.json",
            ),
        }
    }
}

struct WhiteboxArtifactPaths {
    static_narratives: Option<String>,
    static_variants: Option<String>,
    candidate_semgrep_rules: Option<String>,
    whitebox_suppressions: Option<String>,
    whitebox_diff: Option<String>,
}

fn optional_positive_count(value: &Option<Value>, key: &str) -> Option<u64> {
    value
        .as_ref()
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
        .filter(|count| *count > 0)
}

fn json_u64(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or_default()
}

fn json_pointer_u64(value: &Value, pointer: &str) -> u64 {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .unwrap_or_default()
}

fn artifact_path_if_present(
    value: &Option<Value>,
    artifacts: &SastRunArtifacts,
    filename: &str,
) -> Option<String> {
    value
        .as_ref()
        .map(|_| artifacts.dir.join(filename).display().to_string())
}

struct SastPostProcessing {
    triage: Option<Value>,
    verification_results: Vec<Value>,
    patch_results: Vec<Value>,
}

fn run_sast_post_processing(
    requests: &SastScanRequests,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<SastPostProcessing> {
    let triage = if requests.triage {
        Some(run_sast_triage(ctx, runtime, store, run_ids, artifacts)?)
    } else {
        None
    };
    let (verification_results, patch_results) = if requests.needs_verification() {
        run_sast_verification_and_patch(input, ctx, runtime, store, run_ids, artifacts, requests)?
    } else {
        (Vec::new(), Vec::new())
    };

    Ok(SastPostProcessing {
        triage,
        verification_results,
        patch_results,
    })
}

fn run_sast_triage(
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
) -> Result<Value> {
    let fingerprints = fingerprints_for_sast_runs(store, run_ids)?;
    let triage_input = if fingerprints.is_empty() {
        json!({ "scanId": run_ids.primary.clone() })
    } else {
        json!({ "fingerprints": fingerprints })
    };
    let output = run_triage(triage_input, ctx, runtime)?;
    write_triage_jsonl(artifacts, &output)?;
    Ok(output)
}

fn run_sast_verification_and_patch(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    store: &crate::findings::FindingStore,
    run_ids: &SastRunIds,
    artifacts: &SastRunArtifacts,
    requests: &SastScanRequests,
) -> Result<(Vec<Value>, Vec<Value>)> {
    let mut verification_results = Vec::new();
    let mut patch_results = Vec::new();
    for fingerprint in true_positive_fingerprints_for_sast_runs(store, run_ids)? {
        let fingerprint_for_patch = fingerprint.clone();
        let verification = run_verify_finding(json!({ "fingerprint": fingerprint }), ctx, runtime)?;
        write_verify_jsonl(artifacts, &verification)?;
        let exploitable = verification
            .pointer("/data/exploitable")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        verification_results.push(verification);

        if requests.auto_patch && exploitable {
            let patch = run_patch_finding(
                sast_patch_input(input, &fingerprint_for_patch),
                ctx,
                runtime,
            )?;
            write_patch_jsonl(artifacts, &fingerprint_for_patch, &patch)?;
            patch_results.push(patch);
        }
    }
    Ok((verification_results, patch_results))
}

fn sast_output_lines(
    primary_run_id: &str,
    findings_count: usize,
    workspace: &crate::workspace::WorkspaceTarget,
    reports: &SastPipelineReports,
    whitebox_enabled: bool,
    whitebox_artifacts: &WhiteboxArtifacts,
    post_processing: &SastPostProcessing,
    requests: &SastScanRequests,
) -> Vec<String> {
    let mut lines = vec![format!(
        "sast:scan {} completed: {} finding(s), db {}",
        primary_run_id,
        findings_count,
        workspace.findings_db_path().display()
    )];
    if whitebox_enabled {
        whitebox_artifacts.append_output_lines(&mut lines);
    }
    lines.push(format!("  Engines: {}", reports.engine_ids.join(", ")));
    append_triage_output_line(&mut lines, post_processing.triage.as_ref());
    if requests.needs_verification() {
        lines.push(format!(
            "      verified={} patched={}",
            post_processing.verification_results.len(),
            post_processing.patch_results.len()
        ));
    }
    lines
}

fn append_triage_output_line(lines: &mut Vec<String>, triage: Option<&Value>) {
    if let Some(triage_output) = triage
        .and_then(|value| value.get("output"))
        .and_then(Value::as_str)
    {
        lines.push(triage_output.to_string());
    }
}

fn whitebox_mode_label(whitebox_static: Option<&WhiteboxStaticPolicy>) -> &str {
    whitebox_static.map_or("standard", |policy| policy.mode.as_str())
}

pub(in crate::modules) fn run_sast_scan(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let (input, whitebox_static) = apply_whitebox_static_sast_policy(input)?;
    let workspace = ctx
        .workspace
        .context("sast:scan requires a workspace target; pass --target <repo> or start the shell with --target <repo>")?;
    let store = ctx
        .findings_store
        .context("sast:scan requires a findings store")?;
    let requests = SastScanRequests::from_input(&input)?;
    let options = sast_scan_options(&input, whitebox_static.is_some())?;

    let reports = run_sast_pipeline_reports(&input, ctx, runtime, workspace, store, &options)?;
    let findings_count = reports.findings_count();
    let primary_run_id = reports.primary_run_id()?;
    let run_ids = reports.run_ids(primary_run_id.clone());
    let artifacts = SastRunArtifacts::create(workspace, &primary_run_id)?;
    write_sast_scan_input(&artifacts, &input)?;
    let whitebox_artifacts = WhiteboxArtifacts::write(
        whitebox_static.is_some(),
        &input,
        workspace,
        store,
        &run_ids,
        &artifacts,
    )?;
    let post_processing =
        run_sast_post_processing(&requests, &input, ctx, runtime, store, &run_ids, &artifacts)?;
    let lines = sast_output_lines(
        &primary_run_id,
        findings_count,
        workspace,
        &reports,
        whitebox_static.is_some(),
        &whitebox_artifacts,
        &post_processing,
        &requests,
    );
    let whitebox_artifact_paths = whitebox_artifacts.artifact_paths(&artifacts);

    let result = json!({
        "ok": true,
        "output": lines.join("\n"),
        "data": {
            "runId": primary_run_id,
            "runIds": {
                "native": run_ids.native,
                "agentic": run_ids.agentic,
                "carlini": run_ids.carlini,
                "taintIris": run_ids.taint_iris,
                "taintIrisNext": run_ids.taint_iris_next,
                "systemsHunt": run_ids.systems_hunt,
            },
            "target": workspace.root().display().to_string(),
            "mode": whitebox_mode_label(whitebox_static.as_ref()),
            "whiteboxStatic": whitebox_static.as_ref().map(|policy| policy.to_json()),
            "findingsCount": findings_count,
            "db": workspace.findings_db_path().display().to_string(),
            "engines": reports.engine_ids,
            "agentic": reports.agentic.as_ref().map(|report| json!(report)),
            "carliniThreatHunt": reports.carlini.as_ref().map(|report| json!(report)),
            "taintIris": reports.taint_iris.as_ref().map(|report| json!(report)),
            "taintIrisNext": reports.taint_iris_next.as_ref().map(|report| json!(report)),
            "systemsHunt": reports.systems_hunt.as_ref().map(|report| json!(report)),
            "staticRanking": whitebox_artifacts.static_ranking,
            "staticNarratives": whitebox_artifacts.static_narratives,
            "staticVariants": whitebox_artifacts.static_variants,
            "candidateSemgrepRules": whitebox_artifacts.candidate_semgrep_rules,
            "whiteboxSuppressions": whitebox_artifacts.whitebox_suppressions,
            "whiteboxDiff": whitebox_artifacts.whitebox_diff,
            "triage": post_processing.triage.as_ref().and_then(|value| value.get("data")).cloned(),
            "verification": {
                "verified": post_processing.verification_results.len(),
                "results": post_processing.verification_results
                    .iter()
                    .filter_map(|value| value.get("data").cloned())
                    .collect::<Vec<_>>(),
            },
            "patch": {
                "patched": post_processing.patch_results.len(),
                "results": post_processing.patch_results
                    .iter()
                    .filter_map(|value| value.get("data").cloned())
                    .collect::<Vec<_>>(),
            },
            "artifacts": {
                "dir": artifacts.dir.display().to_string(),
                "summary": artifacts.summary.display().to_string(),
                "staticNarratives": whitebox_artifact_paths.static_narratives,
                "staticVariants": whitebox_artifact_paths.static_variants,
                "candidateSemgrepRules": whitebox_artifact_paths.candidate_semgrep_rules,
                "whiteboxSuppressions": whitebox_artifact_paths.whitebox_suppressions,
                "whiteboxDiff": whitebox_artifact_paths.whitebox_diff,
                "triageJsonl": artifacts.triage_jsonl.display().to_string(),
                "verifyJsonl": artifacts.verify_jsonl.display().to_string(),
            },
        },
    });
    write_sast_summary(&artifacts, &result)?;

    Ok(result)
}
