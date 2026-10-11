//! Deterministic linking of confirmed duplicate groups.
//!
//! Event re-emission is NOT idempotent, so every write is guarded: an edge
//! already pointing at the canonical terminal is `already_linked`, an edge to
//! a different terminal is `skipped_conflict`, and a duplicate with a human
//! review decision is `skipped_human` (human verdicts always win). A linked
//! duplicate gets one `FindingRekeyed` event plus a `FalsePositive` /
//! `RefuteReason::Duplicate` verdict whose `[duplicate_of=…]` rationale
//! survives event replay.

use super::{candidates::stable_key, DuplicateGroup, Finding};
use crate::findings::{
    FindingStore, ModelRekeyRequest, RefuteReason, TriageOutcome, TriageVerdict,
};
use anyhow::Result;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct LinkReport {
    pub(super) dry_run: bool,
    pub(super) linked: usize,
    pub(super) already_linked: usize,
    pub(super) skipped_conflict: usize,
    pub(super) skipped_human: usize,
    pub(super) verdicts_recorded: usize,
    pub(super) proposed: usize,
    pub(super) relationship_ids: Vec<String>,
}

pub(super) fn link_groups(
    store: &FindingStore,
    run_id: &str,
    groups: &[DuplicateGroup],
    by_fingerprint: &BTreeMap<&str, &Finding>,
    dry_run: bool,
) -> Result<LinkReport> {
    let mut report = LinkReport {
        dry_run,
        ..LinkReport::default()
    };
    for group in groups {
        link_one_group(store, run_id, group, by_fingerprint, &mut report)?;
    }
    Ok(report)
}

fn link_one_group(
    store: &FindingStore,
    run_id: &str,
    group: &DuplicateGroup,
    by_fingerprint: &BTreeMap<&str, &Finding>,
    report: &mut LinkReport,
) -> Result<()> {
    let Some(canonical) = by_fingerprint.get(group.canonical_fingerprint.as_str()) else {
        return Ok(());
    };
    let terminal = store.resolve_rekey_target(&stable_key(canonical))?;
    for fingerprint in &group.duplicate_fingerprints {
        let Some(duplicate) = by_fingerprint.get(fingerprint.as_str()) else {
            continue;
        };
        link_one_duplicate(
            store, run_id, group, canonical, &terminal, duplicate, report,
        )?;
    }
    Ok(())
}

fn link_one_duplicate(
    store: &FindingStore,
    run_id: &str,
    group: &DuplicateGroup,
    canonical: &Finding,
    terminal: &str,
    duplicate: &Finding,
    report: &mut LinkReport,
) -> Result<()> {
    let duplicate_key = stable_key(duplicate);
    match edge_disposition(store, &duplicate_key, terminal)? {
        EdgeDisposition::AlreadyLinked => report.already_linked += 1,
        EdgeDisposition::Conflict => report.skipped_conflict += 1,
        EdgeDisposition::Free if has_human_decision(store, duplicate)? => {
            report.skipped_human += 1;
        }
        EdgeDisposition::Free if report.dry_run => report.linked += 1,
        EdgeDisposition::Free => {
            store.record_model_rekey(&rekey_request(
                group, canonical, terminal, duplicate, run_id,
            ))?;
            report.verdicts_recorded += store.record_auto_triage_for_fingerprint(
                &duplicate.fingerprint,
                &duplicate_verdict(group, canonical),
            )?;
            report.linked += 1;
        }
    }
    Ok(())
}

enum EdgeDisposition {
    AlreadyLinked,
    Conflict,
    Free,
}

fn edge_disposition(
    store: &FindingStore,
    duplicate_key: &str,
    terminal: &str,
) -> Result<EdgeDisposition> {
    if duplicate_key == terminal {
        return Ok(EdgeDisposition::AlreadyLinked);
    }
    let targets = store.rekey_targets_for(duplicate_key)?;
    if targets.iter().any(|target| target == terminal) {
        return Ok(EdgeDisposition::AlreadyLinked);
    }
    if !targets.is_empty() {
        return Ok(EdgeDisposition::Conflict);
    }
    Ok(EdgeDisposition::Free)
}

fn has_human_decision(store: &FindingStore, duplicate: &Finding) -> Result<bool> {
    let decisions =
        store.latest_review_decisions_for_findings(std::slice::from_ref(duplicate), true)?;
    Ok(!decisions.is_empty())
}

fn rekey_request(
    group: &DuplicateGroup,
    canonical: &Finding,
    terminal: &str,
    duplicate: &Finding,
    run_id: &str,
) -> ModelRekeyRequest {
    ModelRekeyRequest {
        duplicate_stable_key: stable_key(duplicate),
        canonical_stable_key: terminal.to_string(),
        duplicate_fingerprint: duplicate.fingerprint.clone(),
        canonical_fingerprint: canonical.fingerprint.clone(),
        canonical_identity_id: canonical.identity_id.clone(),
        root_cause_summary: group.root_cause_summary.clone(),
        confidence: group.confidence,
        run_id: Some(run_id.to_string()),
    }
}

fn duplicate_verdict(group: &DuplicateGroup, canonical: &Finding) -> TriageOutcome {
    TriageOutcome {
        verdict: TriageVerdict::FalsePositive,
        confidence: group.confidence as f32,
        rationale: format!(
            "[duplicate_of={}] {}",
            canonical.fingerprint, group.root_cause_summary
        ),
        refute_reason: Some(RefuteReason::Duplicate),
        ..TriageOutcome::default()
    }
}
