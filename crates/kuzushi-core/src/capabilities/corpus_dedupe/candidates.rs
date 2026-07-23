//! Deterministic, cost-bounded candidate selection for the dedupe judge.
//!
//! The judge only ever sees findings that could plausibly duplicate each
//! other: same normalized file, at least two members from different
//! `(tool, run)` origins (same-run same-tool near-misses are already handled
//! by ingest `dedup_key` collision and triage clustering). Settled rows —
//! suppressed, already rekeyed, already verdicted as a duplicate — and attack
//! chains never enter the pool.

use super::normalized_path;
use crate::findings::{is_attack_chain_finding, Finding, FindingStore, Severity};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn dedupe_candidates(
    store: &FindingStore,
    max_candidates: usize,
) -> Result<Vec<Finding>> {
    let rekeyed = store.rekeyed_stable_keys()?;
    let eligible = store
        .list_all_findings()?
        .into_iter()
        .filter(|finding| is_eligible(finding, &rekeyed))
        .collect();
    Ok(flatten_prioritized(
        file_buckets(collapse_by_identity(eligible)),
        max_candidates,
    ))
}

/// Rows that already share a durable identity ARE the same finding — a
/// deterministic scanner re-observed across runs, or a prior cross-run
/// identity attach. One representative per stable key keeps the judge's
/// budget for wording-divergent rediscoveries instead of settled pairs.
fn collapse_by_identity(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_key: BTreeMap<String, Finding> = BTreeMap::new();
    for finding in findings {
        by_key.entry(stable_key(&finding)).or_insert(finding);
    }
    by_key.into_values().collect()
}

fn is_eligible(finding: &Finding, rekeyed: &BTreeSet<String>) -> bool {
    !finding.suppressed
        && !is_attack_chain_finding(finding)
        && !rekeyed.contains(&stable_key(finding))
        && !already_marked_duplicate(finding)
}

pub(super) fn stable_key(finding: &Finding) -> String {
    finding
        .identity_id
        .clone()
        .unwrap_or_else(|| finding.fingerprint.clone())
}

fn already_marked_duplicate(finding: &Finding) -> bool {
    finding
        .triage
        .as_ref()
        .is_some_and(|triage| triage.rationale.contains("duplicate_of="))
}

/// Buckets keyed by normalized path, kept only when at least two members come
/// from different `(tool, run)` origins.
fn file_buckets(findings: Vec<Finding>) -> Vec<Vec<Finding>> {
    let mut buckets: BTreeMap<String, Vec<Finding>> = BTreeMap::new();
    for finding in findings {
        buckets
            .entry(normalized_path(&finding.file_path))
            .or_default()
            .push(finding);
    }
    buckets
        .into_values()
        .filter(|members| distinct_origins(members) >= 2)
        .collect()
}

fn distinct_origins(members: &[Finding]) -> usize {
    members
        .iter()
        .map(|finding| {
            (
                finding.tool.trim().to_ascii_lowercase(),
                finding.scan_id.clone().unwrap_or_default(),
            )
        })
        .collect::<BTreeSet<_>>()
        .len()
}

/// Highest-stakes buckets first, whole buckets only (a split bucket can't be
/// grouped by the judge), until the candidate cap is reached.
fn flatten_prioritized(mut buckets: Vec<Vec<Finding>>, max_candidates: usize) -> Vec<Finding> {
    buckets.sort_by(|left, right| {
        bucket_rank(right)
            .cmp(&bucket_rank(left))
            .then_with(|| left[0].file_path.cmp(&right[0].file_path))
    });
    let mut candidates = Vec::new();
    for bucket in buckets {
        if candidates.len() + bucket.len() > max_candidates.max(2) {
            continue;
        }
        candidates.extend(bucket);
    }
    candidates
}

/// Cross-tool buckets outrank same-tool ones: independent tools describing
/// one file is the classic wording-divergent duplicate shape, while a large
/// single-tool bucket is usually many distinct point facts.
fn bucket_rank(members: &[Finding]) -> (usize, u8, usize) {
    let tools = members
        .iter()
        .map(|finding| finding.tool.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .len();
    let severity = members.iter().map(severity_rank).max().unwrap_or(0);
    (tools, severity, members.len())
}

fn severity_rank(finding: &Finding) -> u8 {
    match finding.severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}
