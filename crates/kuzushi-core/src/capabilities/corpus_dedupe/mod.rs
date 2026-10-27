//! Bounded model-assisted duplicate proposals from the findings ledger.
//!
//! `triage:dedupe` is the nondeterministic counterpart of the ingest-time
//! `dedup_key` collision merge: repeated hunts and imports word the same bug
//! differently, so fingerprints and identities diverge even though the defect
//! is one. A judge model proposes duplicate groups over the fingerprint-keyed
//! ledger, code validates every membership, low-confidence groups escalate to
//! one bounded code-reading confirmation pass. The default records reversible
//! relationship proposals without changing identities or human decisions.
//! Explicit legacyRekey retains the older linking contract for compatibility.

mod candidates;
mod dedupe_prompt;
mod dedupe_result;
mod escalate;
mod input_limits;
mod link;
mod proposals;
mod source_inputs;
#[cfg(test)]
mod tests;
mod validate;

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::findings::{Finding, FindingStore};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;

/// Rekey forwarding requires confidence >= 0.8; groups below this after
/// escalation are dropped instead of linked.
const DEDUPE_CONFIDENCE_FLOOR: f64 = 0.8;

const DEFAULT_MAX_GROUPS: usize = 16;
const DEFAULT_MAX_CANDIDATES: usize = 200;
const DEFAULT_MAX_ESCALATIONS: usize = 4;

pub fn execute_triage_dedupe(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let (runtime, workspace, store) = dedupe_context(ctx, runtime)?;
    let options = DedupeOptions::from_input(&input)?;
    ctx.ensure_active()?;
    let selected = candidates::dedupe_candidates(
        store,
        options.max_candidates,
        options.ledger_limits,
        ctx.cancellation,
    )?;
    let result =
        execute_selected_dedupe(&input, ctx, runtime, workspace, store, &options, &selected)?;
    dedupe_result::with_input_coverage(result, &selected.coverage)
}

fn execute_selected_dedupe(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: &dyn AgentRuntime,
    workspace: &crate::workspace::WorkspaceTarget,
    store: &FindingStore,
    options: &DedupeOptions,
    selected: &candidates::DedupeCandidates,
) -> Result<Value> {
    let candidates = &selected.findings;
    if candidates.len() < 2 {
        return Ok(dedupe_result::empty_dedupe_result(
            candidates.len(),
            selected.coverage.omitted_candidates,
        ));
    }
    ctx.ensure_active()?;
    let model = resolve_dedupe_model(input, ctx)?;
    validate_judge_inputs(&model, workspace.root(), candidates, options)?;
    let by_fingerprint = fingerprint_index(candidates);
    let (confirmed, cost) = judge_and_escalate(
        runtime,
        &model,
        workspace.root(),
        candidates,
        &by_fingerprint,
        options,
    )?;
    ctx.ensure_active()?;
    let report = record_dedupe_groups(store, ctx, &confirmed.groups, &by_fingerprint, options)?;
    Ok(dedupe_result::dedupe_result(
        &confirmed,
        &report,
        candidates.len(),
        cost,
    ))
}

fn record_dedupe_groups(
    store: &FindingStore,
    ctx: &ToolExecutionContext<'_>,
    groups: &[DuplicateGroup],
    findings: &BTreeMap<&str, &Finding>,
    options: &DedupeOptions,
) -> Result<link::LinkReport> {
    if options.legacy_rekey {
        return link::link_groups(
            store,
            &ctx.finding_run_id(),
            groups,
            findings,
            options.dry_run,
        );
    }
    proposals::record_groups(store, ctx, groups, findings, options.dry_run)
}

fn dedupe_context<'a>(
    ctx: &'a ToolExecutionContext<'_>,
    runtime: Option<&'a dyn AgentRuntime>,
) -> Result<(
    &'a dyn AgentRuntime,
    &'a crate::workspace::WorkspaceTarget,
    &'a crate::findings::FindingStore,
)> {
    let runtime = runtime.context(
        "triage:dedupe requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )?;
    let workspace = ctx
        .workspace
        .context(crate::workspace::active_workspace_required_message(
            "triage:dedupe",
        ))?;
    let store = ctx
        .findings_store
        .context("triage:dedupe requires the findings store")?;
    Ok((runtime, workspace, store))
}

/// One judge call handles at most this many candidate lines. A 200-line
/// corpus in one prompt made the judge return nothing on real ledgers;
/// bucket-aligned batches keep every call in the range where it actually
/// finds groups, and merging is safe because groups never cross files and
/// no file spans two batches.
const JUDGE_BATCH_MAX_CANDIDATES: usize = 60;

/// The model phases: a bucket-batched judge over the candidate lines, then
/// one bounded code-reading confirmation per low-confidence group.
fn judge_and_escalate(
    runtime: &dyn AgentRuntime,
    model: &str,
    root: &std::path::Path,
    candidates: &[Finding],
    by_fingerprint: &BTreeMap<&str, &Finding>,
    options: &DedupeOptions,
) -> Result<(ConfirmedGroups, crate::runtime::RuntimeCostReport)> {
    let mut judged = JudgedGroups {
        groups: Vec::new(),
        dropped: BTreeMap::new(),
    };
    let mut cost = crate::runtime::RuntimeCostReport::known(crate::runtime::RuntimeCost::ZERO);
    for batch in bucket_batches(candidates) {
        let remaining = options.max_groups.saturating_sub(judged.groups.len());
        if remaining == 0 {
            break;
        }
        let request =
            dedupe_prompt::dedupe_request(model, root, batch, options.max_judge_prompt_bytes)?;
        let batch_judged =
            dedupe_prompt::query_dedupe(runtime, request, remaining, by_fingerprint)?;
        cost = cost.checked_add(batch_judged.cost_report()?, "dedupe judge batch cost")?;
        let batch_value = batch_judged.value;
        judged.groups.extend(batch_value.groups);
        for (reason, count) in batch_value.dropped {
            *judged.dropped.entry(reason).or_default() += count;
        }
    }
    let confirmed = escalate::escalate_low_confidence(
        runtime,
        model,
        root,
        judged,
        by_fingerprint,
        options,
        &mut cost,
    )?;
    Ok((confirmed, cost))
}

fn validate_judge_inputs(
    model: &str,
    root: &std::path::Path,
    candidates: &[Finding],
    options: &DedupeOptions,
) -> Result<()> {
    if options.max_groups == 0 {
        return Ok(());
    }
    for batch in bucket_batches(candidates) {
        dedupe_prompt::dedupe_request(model, root, batch, options.max_judge_prompt_bytes)?;
    }
    Ok(())
}

/// Consecutive whole-file runs packed into batches of at most
/// [`JUDGE_BATCH_MAX_CANDIDATES`]. Candidates arrive bucket-contiguous from
/// selection, so splitting only on file boundaries keeps every potential
/// group inside one batch. An oversized single file becomes its own batch.
fn bucket_batches(candidates: &[Finding]) -> Vec<&[Finding]> {
    let mut batches = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    while cursor < candidates.len() {
        let file_end = end_of_file_run(candidates, cursor);
        let would_overflow = file_end - start > JUDGE_BATCH_MAX_CANDIDATES && start < cursor;
        if would_overflow {
            batches.push(&candidates[start..cursor]);
            start = cursor;
        }
        cursor = file_end;
    }
    if start < candidates.len() {
        batches.push(&candidates[start..]);
    }
    batches
}

fn end_of_file_run(candidates: &[Finding], start: usize) -> usize {
    let path = &candidates[start].file_path;
    candidates[start..]
        .iter()
        .position(|finding| &finding.file_path != path)
        .map(|offset| start + offset)
        .unwrap_or(candidates.len())
}

/// A model-proposed duplicate group whose fingerprints all resolved to real
/// eligible findings in the same file.
struct DuplicateGroup {
    canonical_fingerprint: String,
    duplicate_fingerprints: Vec<String>,
    root_cause_summary: String,
    confidence: f64,
}

/// Judge output after the honesty gate, with per-reason drop counters.
struct JudgedGroups {
    groups: Vec<DuplicateGroup>,
    dropped: BTreeMap<String, usize>,
}

/// Groups that survived the hybrid confidence policy (confident straight
/// through; low-confidence groups escalated to a code-reading confirmation).
struct ConfirmedGroups {
    groups: Vec<DuplicateGroup>,
    dropped: BTreeMap<String, usize>,
    escalated: usize,
    confirmation_inputs: Value,
    confirmation_refusals: Vec<Value>,
}

struct DedupeOptions {
    max_groups: usize,
    max_candidates: usize,
    max_escalations: usize,
    dry_run: bool,
    legacy_rekey: bool,
    ledger_limits: crate::findings::DedupeLedgerLimits,
    max_judge_prompt_bytes: usize,
    max_confirmation_bytes: usize,
}

impl DedupeOptions {
    fn from_input(input: &Value) -> Result<Self> {
        Ok(Self {
            ledger_limits: input_limits::ledger_limits(input)?,
            max_judge_prompt_bytes: input_limits::judge_prompt_limit(input)?,
            max_confirmation_bytes: input_limits::confirmation_limit(input)?,
            legacy_rekey: input
                .get("legacyRekey")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            max_groups: bounded_count(input, "maxGroups", DEFAULT_MAX_GROUPS)?,
            max_candidates: bounded_count(input, "maxCandidates", DEFAULT_MAX_CANDIDATES)?,
            max_escalations: bounded_count(input, "maxEscalations", DEFAULT_MAX_ESCALATIONS)?,
            dry_run: input
                .get("dryRun")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

fn bounded_count(input: &Value, key: &str, default: usize) -> Result<usize> {
    let Some(value) = input.get(key) else {
        return Ok(default);
    };
    let count = value
        .as_u64()
        .with_context(|| format!("triage:dedupe: {key} must be a non-negative integer"))?;
    usize::try_from(count).with_context(|| format!("triage:dedupe: {key} is too large"))
}

fn resolve_dedupe_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        "triage:dedupe",
        input
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        ctx.config.model.as_deref(),
    )
}

fn fingerprint_index(candidates: &[Finding]) -> BTreeMap<&str, &Finding> {
    candidates
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding))
        .collect()
}
