use super::*;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, OnceLock};

const TRIAGE_RUNTIME_CACHE_CAPACITY: usize = 4096;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct TriageRuntimeCacheKey {
    model: String,
    cwd: String,
    fingerprint: String,
    prompt_hash: String,
}

#[derive(Clone)]
pub(in crate::modules) struct TriageRuntimeOutcome {
    pub(in crate::modules) outcome: TriageOutcome,
    pub(in crate::modules) cached: bool,
}

#[derive(Default)]
struct TriageRuntimeCache {
    entries: BTreeMap<TriageRuntimeCacheKey, TriageOutcome>,
    order: VecDeque<TriageRuntimeCacheKey>,
}

impl TriageRuntimeCache {
    fn get(&self, key: &TriageRuntimeCacheKey) -> Option<TriageOutcome> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: TriageRuntimeCacheKey, outcome: TriageOutcome) {
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, outcome);
        self.evict_oldest();
    }

    fn evict_oldest(&mut self) {
        while self.entries.len() > TRIAGE_RUNTIME_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

static TRIAGE_RUNTIME_CACHE: OnceLock<Mutex<TriageRuntimeCache>> = OnceLock::new();

pub(in crate::modules) fn triage_cost_cap_reached(
    cost_cap_usd: Option<f64>,
    cost: crate::runtime::RuntimeCostReport,
) -> bool {
    cost_cap_usd.is_some_and(|cap| !cost.is_complete() || cost.observed_usd() >= cap)
}

pub(in crate::modules) fn call_triage_runtime(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> Result<TriageRuntimeOutcome> {
    let request = TriageRequest {
        model: config.stage2_model.clone(),
        cwd: config.cwd.clone(),
        finding: finding.clone(),
        prompt_template: triage_prompt_with_grounding(input, finding),
    };
    let key = triage_runtime_cache_key(&request);
    if !input.retriage {
        if let Some(outcome) = cached_triage_outcome(&key) {
            return Ok(TriageRuntimeOutcome {
                outcome,
                cached: true,
            });
        }
    }
    let outcome = crate::runtime::triage_finding_blocking_checked(runtime, request)?;
    cache_triage_outcome(key, outcome.clone());
    Ok(TriageRuntimeOutcome {
        outcome,
        cached: false,
    })
}

/// One additional consensus vote. Deliberately bypasses the runtime cache in
/// both directions: reading it would replay vote #1 verbatim (defeating vote
/// independence), and writing it would let a later single-vote run pick up
/// an arbitrary vote instead of the consensus.
pub(in crate::modules) fn call_triage_runtime_uncached(
    runtime: &dyn AgentRuntime,
    config: &TriageExecutionConfig,
    input: &TriageRunInput,
    finding: &Finding,
) -> Result<TriageOutcome> {
    let request = TriageRequest {
        model: config.stage2_model.clone(),
        cwd: config.cwd.clone(),
        finding: finding.clone(),
        prompt_template: triage_prompt_with_grounding(input, finding),
    };
    crate::runtime::triage_finding_blocking_checked(runtime, request)
}

/// Imported findings with stale anchors get an honesty note appended to the
/// triage prompt so the model re-checks the citation instead of trusting it.
fn triage_prompt_with_grounding(input: &TriageRunInput, finding: &Finding) -> Option<String> {
    let Some(note) = crate::findings::grounding_prompt_note(finding) else {
        return input.prompt_template.clone();
    };
    let template = input
        .prompt_template
        .clone()
        .unwrap_or_else(|| crate::runtime::DEFAULT_TRIAGE_PROMPT.to_string());
    Some(format!("{template}\n\nGrounding note: {note}"))
}

fn cached_triage_outcome(key: &TriageRuntimeCacheKey) -> Option<TriageOutcome> {
    let cache = TRIAGE_RUNTIME_CACHE.get_or_init(|| Mutex::new(TriageRuntimeCache::default()));
    let guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
    guard.get(key)
}

fn cache_triage_outcome(key: TriageRuntimeCacheKey, outcome: TriageOutcome) {
    let cache = TRIAGE_RUNTIME_CACHE.get_or_init(|| Mutex::new(TriageRuntimeCache::default()));
    let mut guard = cache.lock().unwrap_or_else(|poison| poison.into_inner());
    guard.insert(key, outcome);
}

fn triage_runtime_cache_key(request: &TriageRequest) -> TriageRuntimeCacheKey {
    TriageRuntimeCacheKey {
        model: request.model.clone(),
        cwd: request.cwd.display().to_string(),
        fingerprint: request.finding.fingerprint.clone(),
        prompt_hash: triage_runtime_prompt_hash(request),
    }
}

fn triage_runtime_prompt_hash(request: &TriageRequest) -> String {
    stable_triage_prompt_hash(&[
        request.prompt_template.as_deref().unwrap_or(""),
        &request.finding.fingerprint,
        &request.finding.title,
        &request.finding.file_path,
    ])
}

fn stable_triage_prompt_hash(parts: &[&str]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for part in parts {
        hash = fnv1a_update(hash, part.as_bytes());
        hash = fnv1a_update(hash, &[0xff]);
    }
    format!("fnv1a64:{hash:016x}")
}

fn fnv1a_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub(in crate::modules) fn persist_triage_outcome(
    store: &FindingStore,
    stats: &mut TriageRunStats,
    finding: Finding,
    runtime_outcome: TriageRuntimeOutcome,
) -> Result<()> {
    let Some(_finding_id) = finding.id else {
        stats.record_unpersisted_outcome(finding, runtime_outcome.outcome)?;
        return Ok(());
    };
    if let Err(error) =
        store.record_auto_triage_for_fingerprint(&finding.fingerprint, &runtime_outcome.outcome)
    {
        crate::runtime_diagnostics::record_runtime_diagnostic(
            "triage:run",
            format!(
                "could not persist triage for finding {}: {error}",
                finding.fingerprint
            ),
        );
    }
    if runtime_outcome.cached {
        stats.record_cached_outcome(finding, runtime_outcome.outcome);
    } else {
        stats.record_persisted_outcome(finding, runtime_outcome.outcome)?;
    }
    Ok(())
}

/// A cluster duplicate inherits the representative's verdict without an LLM
/// call: persisted like an auto-triage, recorded with a `dedupe` stage row so
/// the operator can see the inheritance instead of a silent drop.
pub(in crate::modules) fn propagate_duplicate_outcome(
    store: &FindingStore,
    stats: &mut TriageRunStats,
    finding: Finding,
    representative_outcome: &TriageOutcome,
    representative_fingerprint: &str,
) {
    let inherited = TriageOutcome {
        rationale: duplicate_rationale(
            representative_fingerprint,
            &representative_outcome.rationale,
        ),
        cost_usd: 0.0,
        cost_usd_exact: true,
        ..representative_outcome.clone()
    };
    if let Err(error) = store.record_auto_triage_for_fingerprint(&finding.fingerprint, &inherited) {
        crate::runtime_diagnostics::record_runtime_diagnostic(
            "triage:run",
            format!(
                "could not persist inherited triage for finding {}: {error}",
                finding.fingerprint
            ),
        );
    }
    stats.record_duplicate_outcome(finding, inherited, representative_fingerprint);
}

pub(in crate::modules) fn high_confidence_false_positive(result: &Value) -> bool {
    result.get("verdict").and_then(Value::as_str) == Some("false_positive")
        && result
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            >= 0.7
}

pub(in crate::modules) fn triage_response(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: Vec<String>,
) -> Value {
    let dropped_high_conf_fp = stats.high_confidence_false_positive_count();
    let summary = triage_summary(stage1, stats, &missing_fingerprints);
    let warnings = triage_warnings(stats, &missing_fingerprints);
    let data = triage_response_data(
        input,
        config,
        stage1,
        stats,
        missing_fingerprints,
        dropped_high_conf_fp,
        &summary,
    );
    let mut result = crate::module_result::completed_output_result(summary.clone(), summary, data);
    add_triage_response_metadata(&mut result, warnings, stats.cost_report());
    result
}

fn add_triage_response_metadata(
    result: &mut Value,
    warnings: Vec<String>,
    cost: crate::runtime::RuntimeCostReport,
) {
    if let Some(object) = result.as_object_mut() {
        object.insert("warnings".to_string(), json!(warnings));
    }
    crate::module_result::apply_runtime_cost_report(result, cost);
}

fn triage_response_data(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    missing_fingerprints: Vec<String>,
    dropped_high_conf_fp: usize,
    summary: &str,
) -> Value {
    let mut data = json!({
        "summary": summary,
        "triaged": stats.triaged(),
        "total": stage1.total,
        "tp": stats.tp,
        "fp": stats.fp,
        "needsReview": stats.needs_review,
        "byDesign": stats.by_design,
        "missingFingerprints": missing_fingerprints,
        "concurrency": input.concurrency,
        "votes": input.votes,
        "stage2Tier": triage_tier_label(input.stage2_tier),
        "costCapUsd": input.cost_cap_usd,
        "costCapHit": stats.cost_cap_hit,
        "pendingAfterCap": stats.pending_after_cap,
        "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
        "stages": triage_stages(input, config, stage1, stats, dropped_high_conf_fp),
        "results": stats.results,
        "findings": stats.results,
    });
    crate::module_result::apply_runtime_cost_report(&mut data, stats.cost_report());
    data
}

fn triage_warnings(stats: &TriageRunStats, missing_fingerprints: &[String]) -> Vec<String> {
    let mut warnings = Vec::new();
    if stats.cost_cap_hit {
        warnings.push(cost_cap_warning(stats));
    }
    if !stats.cost_report().is_complete() {
        warnings.push(format!(
            "Provider spend is unresolved; observed subtotal is ${:.4}.",
            stats.cost_report().observed_usd()
        ));
    }
    if !missing_fingerprints.is_empty() {
        warnings.push(format!(
            "{} requested finding(s) were not found.",
            missing_fingerprints.len()
        ));
    }
    warnings
}

fn cost_cap_warning(stats: &TriageRunStats) -> String {
    if stats.cost_report().is_complete() {
        return format!(
            "Cost cap hit; {} finding(s) remain unevaluated.",
            stats.pending_after_cap
        );
    }
    format!(
        "Cost-cap enforcement halted on unresolved provider spend; {} finding(s) remain unevaluated.",
        stats.pending_after_cap
    )
}

pub(in crate::modules) fn triage_stages(
    input: &TriageRunInput,
    config: &TriageExecutionConfig,
    stage1: &PrefilteredTriageFindings,
    stats: &TriageRunStats,
    dropped_high_conf_fp: usize,
) -> Value {
    let mut stages = json!([
        {
            "stage": "prefilter",
            "kept": stage1.kept_count,
            "dropped": stage1.dropped,
            "rule": format!("prefilter_score >= {}", input.prefilter_threshold),
        },
        {
            "stage": "dedupe",
            "clusters": stats.clusters,
            "duplicatesInherited": stats.duplicates_inherited,
            "rule": format!(
                "same tool+rule within {} lines inherits the representative verdict",
                crate::findings::ingest_contract::CLUSTER_WINDOW_LINES
            ),
        },
        {
            "stage": "haiku",
            "model": config.stage2_model,
            "concurrency": input.concurrency,
            "votes": input.votes,
            "triaged": stats.triaged(),
            "tp": stats.tp,
            "fp": stats.fp,
            "needsReview": stats.needs_review,
            "byDesign": stats.by_design,
            "highConfidenceFalsePositivesDropped": dropped_high_conf_fp,
            "costCapHit": stats.cost_cap_hit,
            "pendingAfterCap": stats.pending_after_cap,
        }
    ]);
    if let Some(stage) = stages.get_mut(1) {
        crate::module_result::apply_runtime_cost_report(stage, stats.cost_report());
    }
    stages
}
