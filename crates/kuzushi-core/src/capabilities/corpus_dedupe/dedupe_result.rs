//! Tool-result payloads for the corpus dedupe.

use super::{link::LinkReport, ConfirmedGroups, DuplicateGroup};
use crate::runtime::RuntimeCostReport;
use serde_json::{json, Value};

pub(super) fn empty_dedupe_result(candidate_count: usize) -> Value {
    let summary = format!(
        "triage:dedupe — {candidate_count} candidate(s); need at least 2 co-located findings from different runs or tools"
    );
    crate::module_result::skipped_output_result(
        summary.clone(),
        summary.clone(),
        vec![json!(summary)],
        json!({"groups": [], "candidateCount": candidate_count}),
    )
}

pub(super) fn dedupe_result(
    confirmed: &ConfirmedGroups,
    report: &LinkReport,
    candidate_count: usize,
    cost: RuntimeCostReport,
) -> Value {
    let summary = dedupe_summary(confirmed, report, candidate_count);
    let mut data = json!({
        "summary": summary,
        "dryRun": report.dry_run,
        "candidateCount": candidate_count,
        "groups": confirmed.groups.iter().map(group_json).collect::<Vec<_>>(),
        "escalated": confirmed.escalated,
        "droppedProposals": confirmed.dropped,
        "linked": report.linked,
        "alreadyLinked": report.already_linked,
        "skippedConflict": report.skipped_conflict,
        "skippedHuman": report.skipped_human,
        "verdictsRecorded": report.verdicts_recorded,
    });
    crate::module_result::apply_runtime_cost_report(&mut data, cost);
    let mut result =
        crate::module_result::completed_output_result(summary.clone(), summary, data);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    result
}

fn dedupe_summary(
    confirmed: &ConfirmedGroups,
    report: &LinkReport,
    candidate_count: usize,
) -> String {
    let action = if report.dry_run {
        "proposed (dry run)"
    } else {
        "linked"
    };
    format!(
        "triage:dedupe — {} duplicate group(s) over {} candidate(s); {} duplicate(s) {}, {} already linked, {} conflict(s) skipped, {} human-decided skipped",
        confirmed.groups.len(),
        candidate_count,
        report.linked,
        action,
        report.already_linked,
        report.skipped_conflict,
        report.skipped_human,
    )
}

fn group_json(group: &DuplicateGroup) -> Value {
    json!({
        "canonicalFingerprint": group.canonical_fingerprint,
        "duplicateFingerprints": group.duplicate_fingerprints,
        "rootCauseSummary": group.root_cause_summary,
        "confidence": group.confidence,
    })
}
