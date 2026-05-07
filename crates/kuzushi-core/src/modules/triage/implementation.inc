use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::findings::{
    Finding, FindingListFilter, FindingStore, Severity, TriageOutcome, TriageVerdict,
};
use crate::runtime::{AgentRuntime, ModelTier, TriageRequest};
use crate::workspace::WorkspaceTarget;

use super::input::{optional_nonempty_string, resolve_prompt_override};
use super::ToolExecutionContext;

#[derive(Debug, Clone)]
struct TriageRunInput {
    fingerprints: Option<Vec<String>>,
    batch_size: usize,
    prompt_template: Option<String>,
    scan_id: Option<String>,
    concurrency: usize,
    cost_cap_usd: Option<f64>,
    prefilter_threshold: i64,
    stage2_tier: ModelTier,
}

impl TriageRunInput {
    fn from_tool_input(input: &Value, cwd: &Path) -> Result<Self> {
        Ok(Self {
            fingerprints: parse_triage_fingerprints(input)?,
            batch_size: parse_triage_batch_size(input)?,
            prompt_template: parse_triage_prompt_template(input, cwd)?,
            scan_id: parse_triage_scan_id(input)?,
            concurrency: parse_triage_concurrency(input)?,
            cost_cap_usd: parse_triage_cost_cap_usd(input)?,
            prefilter_threshold: parse_triage_prefilter_threshold(input),
            stage2_tier: parse_triage_stage2_tier(input)?,
        })
    }
}

fn parse_triage_fingerprints(input: &Value) -> Result<Option<Vec<String>>> {
    let mut fingerprints = Vec::new();
    push_primary_fingerprint(input, &mut fingerprints)?;
    extend_fingerprint_array(input, &mut fingerprints)?;
    Ok(nonempty_fingerprints(fingerprints))
}

fn push_primary_fingerprint(input: &Value, fingerprints: &mut Vec<String>) -> Result<()> {
    if let Some(fingerprint) = optional_nonempty_string(input, "fingerprint")? {
        fingerprints.push(fingerprint);
    }
    Ok(())
}

fn extend_fingerprint_array(input: &Value, fingerprints: &mut Vec<String>) -> Result<()> {
    let Some(values) = input.get("fingerprints") else {
        return Ok(());
    };
    let Value::Array(items) = values else {
        anyhow::bail!("triage:run fingerprints must be an array of strings");
    };
    for item in items {
        fingerprints.push(parse_fingerprint_entry(item)?);
    }
    Ok(())
}

fn parse_fingerprint_entry(item: &Value) -> Result<String> {
    let Some(value) = item
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        anyhow::bail!("triage:run fingerprints entries must be non-empty strings");
    };
    Ok(value.to_string())
}

fn nonempty_fingerprints(fingerprints: Vec<String>) -> Option<Vec<String>> {
    if fingerprints.is_empty() {
        None
    } else {
        Some(fingerprints)
    }
}

fn parse_triage_batch_size(input: &Value) -> Result<usize> {
    match input.get("batchSize").or_else(|| input.get("batch_size")) {
        Some(Value::Number(number)) => clamp_triage_batch_size(
            number
                .as_u64()
                .context("triage:run batchSize must be a positive integer")? as usize,
        ),
        Some(Value::String(value)) => clamp_triage_batch_size(
            value
                .parse::<usize>()
                .context("triage:run batchSize must be a positive integer")?,
        ),
        Some(_) => anyhow::bail!("triage:run batchSize must be a positive integer"),
        None => Ok(5),
    }
}

fn clamp_triage_batch_size(value: usize) -> Result<usize> {
    if value == 0 {
        anyhow::bail!("triage:run batchSize must be a positive integer");
    }
    Ok(value.min(500))
}

fn parse_triage_prompt_template(input: &Value, cwd: &Path) -> Result<Option<String>> {
    optional_nonempty_string(input, "TRIAGE_PROMPT")?
        .map(|value| resolve_prompt_override(&value, cwd))
        .transpose()
}

fn parse_triage_scan_id(input: &Value) -> Result<Option<String>> {
    Ok(optional_nonempty_string(input, "scanId")?.or(optional_nonempty_string(input, "scan_id")?))
}

fn parse_triage_concurrency(input: &Value) -> Result<usize> {
    match input.get("concurrency") {
        Some(Value::Number(n)) => Ok(n.as_u64().unwrap_or(8).clamp(1, 64) as usize),
        None => Ok(8),
        Some(_) => anyhow::bail!("triage:run concurrency must be a positive integer"),
    }
}

fn parse_triage_cost_cap_usd(input: &Value) -> Result<Option<f64>> {
    match input
        .get("costCapUsd")
        .or_else(|| input.get("cost_cap_usd"))
    {
        Some(Value::Number(n)) => Ok(n.as_f64()),
        None => Ok(cost_cap_from_env()),
        Some(_) => anyhow::bail!("triage:run costCapUsd must be a number"),
    }
}

fn cost_cap_from_env() -> Option<f64> {
    std::env::var("KUZUSHI_COST_CAP_USD")
        .ok()
        .and_then(|s| s.trim().parse::<f64>().ok())
}

fn parse_triage_prefilter_threshold(input: &Value) -> i64 {
    input
        .get("prefilterThreshold")
        .or_else(|| input.get("prefilter_threshold"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn parse_triage_stage2_tier(input: &Value) -> Result<ModelTier> {
    match input
        .get("stage2Tier")
        .or_else(|| input.get("stage2_tier"))
        .and_then(Value::as_str)
    {
        Some("cheap") | None => Ok(ModelTier::Cheap),
        Some("mid") => Ok(ModelTier::Mid),
        Some("deep") => Ok(ModelTier::Deep),
        Some(other) => {
            anyhow::bail!("triage:run stage2Tier must be one of cheap|mid|deep (got {other:?})")
        }
    }
}

fn prefilter_score(finding: &Finding) -> i64 {
    let mut score: i64 = match finding.severity {
        Severity::Critical => 8,
        Severity::High => 5,
        Severity::Medium => 3,
        Severity::Low | Severity::Info | Severity::Unknown => 1,
    };
    let msg = finding.message.to_ascii_lowercase();
    for keyword in [
        "attacker",
        "untrusted",
        "user-controlled",
        "user controlled",
        "out-of-bounds",
        "use-after-free",
        "race condition",
        "buffer overflow",
        "integer overflow",
        "memory corruption",
        "command injection",
        "sql injection",
    ] {
        if msg.contains(keyword) {
            score += 2;
        }
    }
    match finding.tool.as_str() {
        "codeql" | "cargo-audit" | "iac-scan" | "secret-scan" => score += 2,
        "semgrep" => score += 1,
        _ => {}
    }
    score
}

pub(in crate::modules) fn run_triage(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let workspace = require_triage_workspace(ctx)?;
    let store = require_triage_store(ctx)?;
    let input = TriageRunInput::from_tool_input(&input, workspace.root())?;
    let (findings, missing_fingerprints) = select_triage_findings(store, &input)?;
    if findings.is_empty() {
        return Ok(empty_triage_response(&input, missing_fingerprints));
    }

    let runtime = require_triage_runtime(runtime)?;
    let stage2_model = resolve_triage_model(ctx, runtime, input.stage2_tier)?;
    let mut stage1 = prefilter_triage_findings(findings, input.prefilter_threshold);
    let config = TriageExecutionConfig::new(workspace.root().to_path_buf(), stage2_model);
    let kept = std::mem::take(&mut stage1.kept);
    let stats = run_triage_stage2(store, runtime, &input, &config, kept)?;
    Ok(triage_response(
        &input,
        &config,
        &stage1,
        &stats,
        missing_fingerprints,
    ))
}

fn require_triage_workspace<'a>(ctx: &'a ToolExecutionContext<'_>) -> Result<&'a WorkspaceTarget> {
    ctx.workspace.context(
        "triage:run needs an active workspace. Pass --target <repo> or start the shell with --target.",
    )
}

fn require_triage_store<'a>(ctx: &'a ToolExecutionContext<'_>) -> Result<&'a FindingStore> {
    ctx.findings_store
        .context("triage:run requires a findings store for the active workspace")
}

fn empty_triage_response(input: &TriageRunInput, missing_fingerprints: Vec<String>) -> Value {
    json!({
        "ok": false,
        "output": "[-] No findings match. Run a scanner first (`kuzushi scan <repo>`) or pass explicit fingerprints.",
        "data": {
            "triaged": 0,
            "total": 0,
            "tp": 0,
            "fp": 0,
            "needsReview": 0,
            "byDesign": 0,
            "costUsd": 0.0,
            "missingFingerprints": missing_fingerprints,
            "batchSize": input.batch_size,
        },
        "costUsd": 0.0,
    })
}

fn require_triage_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "triage:run requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn resolve_triage_model(
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    tier: ModelTier,
) -> Result<String> {
    let model_configured = ctx.config.model.clone().context(
        "triage:run requires an explicit model in config.toml or KUZUSHI_MODEL; Kuzushi will not choose a fallback model",
    )?;
    Ok(runtime.model_for_tier(tier, &model_configured))
}

struct PrefilteredTriageFindings {
    total: usize,
    kept_count: usize,
    kept: Vec<Finding>,
    dropped: usize,
}

fn prefilter_triage_findings(
    findings: Vec<Finding>,
    prefilter_threshold: i64,
) -> PrefilteredTriageFindings {
    let total = findings.len();
    let (kept, dropped): (Vec<Finding>, Vec<Finding>) = findings
        .into_iter()
        .partition(|finding| prefilter_score(finding) >= prefilter_threshold);
    let kept_count = kept.len();
    PrefilteredTriageFindings {
        total,
        kept_count,
        dropped: dropped.len(),
        kept,
    }
}

struct TriageExecutionConfig {
    cwd: PathBuf,
    stage2_model: String,
}

impl TriageExecutionConfig {
    fn new(cwd: PathBuf, stage2_model: String) -> Self {
        Self { cwd, stage2_model }
    }
}

#[derive(Default)]
struct TriageRunStats {
    tp: usize,
    fp: usize,
    needs_review: usize,
    by_design: usize,
    total_cost: f64,
    cost_cap_hit: bool,
    pending_after_cap: usize,
    results: Vec<Value>,
}

impl TriageRunStats {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            results: Vec::with_capacity(capacity),
            ..Self::default()
        }
    }

    fn triaged(&self) -> usize {
        self.results.len()
    }

    fn high_confidence_false_positive_count(&self) -> usize {
        self.results
            .iter()
            .filter(|result| high_confidence_false_positive(result))
            .count()
    }

    fn record_cost_cap_pending(&mut self) {
        self.cost_cap_hit = true;
        self.pending_after_cap += 1;
    }

    fn record_runtime_error(&mut self, finding: Finding, error: anyhow::Error) {
        self.needs_review += 1;
        self.results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": "needs_review",
            "confidence": 0.0,
            "rationale": format!("triage call failed: {error}"),
        }));
    }

    fn record_unpersisted_outcome(&mut self, finding: Finding, outcome: TriageOutcome) {
        self.results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": "finding lacked SQLite id; verdict not persisted",
        }));
    }

    fn record_persisted_outcome(&mut self, finding: Finding, outcome: TriageOutcome) {
        self.total_cost += outcome.cost_usd;
        self.record_verdict(outcome.verdict);
        self.results.push(json!({
            "fingerprint": finding.fingerprint,
            "stage": "haiku",
            "verdict": outcome.verdict.as_str(),
            "confidence": outcome.confidence,
            "rationale": outcome.rationale,
            "costUsd": outcome.cost_usd,
        }));
    }

    fn record_verdict(&mut self, verdict: TriageVerdict) {
        match verdict {
            TriageVerdict::TruePositive => self.tp += 1,
            TriageVerdict::FalsePositive => self.fp += 1,
            TriageVerdict::NeedsReview => self.needs_review += 1,
            TriageVerdict::ByDesign => self.by_design += 1,
        }
    }
}

fn run_triage_stage2(
    store: &FindingStore,
    runtime: &dyn AgentRuntime,
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    findings: Vec<Finding>,
) -> Result<TriageRunStats> {
    let mut stats = TriageRunStats::with_capacity(findings.len());
    for finding in findings {
        triage_one_finding(store, runtime, input, config, &mut stats, finding);
    }
    Ok(stats)
}

fn triage_one_finding(
    store: &FindingStore,
    runtime: &dyn AgentRuntime,
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stats: &mut TriageRunStats,
    finding: Finding,
) {
    if triage_cost_cap_reached(input.cost_cap_usd, stats.total_cost) {
        stats.record_cost_cap_pending();
        return;
    }

    let outcome = match call_triage_runtime(runtime, config, input, &finding) {
        Ok(outcome) => outcome,
        Err(error) => {
            stats.record_runtime_error(finding, error);
            return;
        }
    };
    persist_triage_outcome(store, stats, finding, outcome);
}

fn triage_cost_cap_reached(cost_cap_usd: Option<f64>, total_cost: f64) -> bool {
    cost_cap_usd.is_some_and(|cap| total_cost >= cap)
}

fn call_triage_runtime(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> Result<TriageOutcome> {
    runtime.triage_finding_blocking(TriageRequest {
        model: config.stage2_model.clone(),
        cwd: config.cwd.clone(),
        finding: finding.clone(),
        prompt_template: input.prompt_template.clone(),
    })
}

fn persist_triage_outcome(
    store: &FindingStore,
    stats: &mut TriageRunStats,
    finding: Finding,
    outcome: TriageOutcome,
) {
    let Some(finding_id) = finding.id else {
        stats.record_unpersisted_outcome(finding, outcome);
        return;
    };
    if let Err(error) = store.save_triage(finding_id, &outcome) {
        eprintln!(
            "[triage:run] could not persist triage for finding {}: {error}",
            finding.fingerprint
        );
    }
    stats.record_persisted_outcome(finding, outcome);
}

fn high_confidence_false_positive(result: &Value) -> bool {
    result.get("verdict").and_then(Value::as_str) == Some("false_positive")
        && result
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            >= 0.7
}

fn triage_response(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: Vec<String>,
) -> Value {
    let dropped_high_conf_fp = stats.high_confidence_false_positive_count();
    json!({
        "ok": true,
        "output": triage_summary(stage1, stats, &missing_fingerprints),
        "data": {
            "triaged": stats.triaged(),
            "total": stage1.total,
            "tp": stats.tp,
            "fp": stats.fp,
            "needsReview": stats.needs_review,
            "byDesign": stats.by_design,
            "costUsd": stats.total_cost,
            "missingFingerprints": missing_fingerprints,
            "batchSize": input.batch_size,
            "concurrency": input.concurrency,
            "stage2Tier": triage_tier_label(input.stage2_tier),
            "costCapUsd": input.cost_cap_usd,
            "costCapHit": stats.cost_cap_hit,
            "pendingAfterCap": stats.pending_after_cap,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "stages": triage_stages(input, config, stage1, stats, dropped_high_conf_fp),
            "results": stats.results,
        },
        "costUsd": stats.total_cost,
    })
}

fn triage_stages(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    dropped_high_conf_fp: usize,
) -> Value {
    json!([
        {
            "stage": "prefilter",
            "kept": stage1.kept_count,
            "dropped": stage1.dropped,
            "rule": format!("prefilter_score >= {}", input.prefilter_threshold),
        },
        {
            "stage": "haiku",
            "model": config.stage2_model,
            "concurrency": input.concurrency,
            "triaged": stats.triaged(),
            "tp": stats.tp,
            "fp": stats.fp,
            "needsReview": stats.needs_review,
            "byDesign": stats.by_design,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "costUsd": stats.total_cost,
            "costCapHit": stats.cost_cap_hit,
            "pendingAfterCap": stats.pending_after_cap,
        }
    ])
}

fn triage_summary(
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: &[String],
) -> String {
    let mut summary = format!(
        "[+] Triaged {} of {} findings (stage1 dropped {})\n      tp={}  fp={}  needs_review={}",
        stats.triaged(),
        stage1.total,
        stage1.dropped,
        stats.tp,
        stats.fp,
        stats.needs_review
    );
    append_by_design_summary(&mut summary, stats.by_design);
    summary.push_str(&format!("\n      cost=${:.4}", stats.total_cost));
    append_cost_cap_summary(&mut summary, stats);
    append_missing_fingerprints_summary(&mut summary, missing_fingerprints);
    summary
}

fn append_by_design_summary(summary: &mut String, by_design: usize) {
    if by_design > 0 {
        summary.push_str(&format!("  by_design={by_design}"));
    }
}

fn append_cost_cap_summary(summary: &mut String, stats: &TriageRunStats) {
    if stats.cost_cap_hit {
        summary.push_str(&format!(
            "\n[!] cost cap hit; {} finding(s) remain unevaluated",
            stats.pending_after_cap
        ));
    }
}

fn append_missing_fingerprints_summary(summary: &mut String, missing_fingerprints: &[String]) {
    if !missing_fingerprints.is_empty() {
        summary.push_str(&format!(
            "\n[!] {} requested finding(s) were not found",
            missing_fingerprints.len()
        ));
    }
}

fn triage_tier_label(tier: ModelTier) -> &'static str {
    match tier {
        ModelTier::Cheap => "cheap",
        ModelTier::Mid => "mid",
        ModelTier::Deep => "deep",
    }
}

fn select_triage_findings(
    store: &FindingStore,
    input: &TriageRunInput,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut missing = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(fingerprints) = &input.fingerprints {
        for reference in fingerprints {
            match store.get_finding_by_reference(reference)? {
                Some(finding)
                    if input
                        .scan_id
                        .as_ref()
                        .is_none_or(|scan_id| finding.scan_id.as_deref() == Some(scan_id)) =>
                {
                    if seen.insert(finding.fingerprint.clone()) {
                        findings.push(finding);
                    }
                }
                _ => missing.push(reference.clone()),
            }
        }
    } else {
        for finding in store.list_findings(FindingListFilter::MAX_LIMIT)? {
            if input
                .scan_id
                .as_ref()
                .is_some_and(|scan_id| finding.scan_id.as_deref() != Some(scan_id))
            {
                continue;
            }
            findings.push(finding);
        }
    }

    Ok((findings, missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_with(severity: Severity, tool: &str, message: &str) -> Finding {
        Finding::new_tool(tool, "rule", "src/lib.rs", 1, None, severity, message)
    }

    #[test]
    fn prefilter_score_scales_with_severity() {
        assert!(
            prefilter_score(&finding_with(Severity::Critical, "semgrep", "plain"))
                > prefilter_score(&finding_with(Severity::Low, "semgrep", "plain"))
        );
    }

    #[test]
    fn prefilter_score_bumps_for_attacker_keywords() {
        let plain = finding_with(Severity::Medium, "semgrep", "plain bug");
        let attacker = finding_with(
            Severity::Medium,
            "semgrep",
            "attacker controls SQL injection",
        );
        assert!(prefilter_score(&attacker) > prefilter_score(&plain));
    }

    #[test]
    fn prefilter_score_bumps_for_curated_tools() {
        let semgrep = finding_with(Severity::Medium, "semgrep", "plain");
        let codeql = finding_with(Severity::Medium, "codeql", "plain");
        assert!(prefilter_score(&codeql) > prefilter_score(&semgrep));
    }

    #[test]
    fn prefilter_score_unknown_severity_is_low() {
        let unknown = finding_with(Severity::Unknown, "other", "plain");
        assert_eq!(prefilter_score(&unknown), 1);
    }

    #[test]
    fn prefilter_score_is_deterministic() {
        let finding = finding_with(
            Severity::High,
            "codeql",
            "attacker controls buffer overflow",
        );
        assert_eq!(prefilter_score(&finding), prefilter_score(&finding));
    }

    #[test]
    fn triage_run_input_parses_aliases_limits_and_prompt_files() {
        let temp = tempfile::tempdir().unwrap();
        let prompt = temp.path().join("triage.md");
        std::fs::write(&prompt, "custom triage prompt").unwrap();

        let parsed = TriageRunInput::from_tool_input(
            &json!({
                "fingerprint": " fp-1 ",
                "fingerprints": ["fp-2"],
                "batch_size": "999",
                "TRIAGE_PROMPT": "./triage.md",
                "scan_id": "scan-1",
                "concurrency": 128,
                "cost_cap_usd": 1.25,
                "prefilter_threshold": 7,
                "stage2_tier": "deep"
            }),
            temp.path(),
        )
        .unwrap();

        assert_eq!(
            parsed.fingerprints,
            Some(vec!["fp-1".to_string(), "fp-2".to_string()])
        );
        assert_eq!(parsed.batch_size, 500);
        assert_eq!(
            parsed.prompt_template,
            Some("custom triage prompt".to_string())
        );
        assert_eq!(parsed.scan_id, Some("scan-1".to_string()));
        assert_eq!(parsed.concurrency, 64);
        assert_eq!(parsed.cost_cap_usd, Some(1.25));
        assert_eq!(parsed.prefilter_threshold, 7);
        assert_eq!(parsed.stage2_tier, ModelTier::Deep);
    }

    #[test]
    fn triage_run_input_rejects_invalid_shapes() {
        let cwd = Path::new(".");
        assert!(
            TriageRunInput::from_tool_input(&json!({"fingerprints": "fp"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("fingerprints must be an array")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"fingerprints": [""]}), cwd)
                .unwrap_err()
                .to_string()
                .contains("non-empty strings")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"batchSize": 0}), cwd)
                .unwrap_err()
                .to_string()
                .contains("batchSize")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"concurrency": "many"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("concurrency")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"costCapUsd": "expensive"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("costCapUsd")
        );
        assert!(
            TriageRunInput::from_tool_input(&json!({"stage2Tier": "max"}), cwd)
                .unwrap_err()
                .to_string()
                .contains("stage2Tier")
        );
    }
}
