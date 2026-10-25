//! Tool-result payloads for the corpus dedupe.

use super::{link::LinkReport, ConfirmedGroups, DuplicateGroup};
use crate::runtime::RuntimeCostReport;
use serde_json::{json, Value};

pub(super) fn with_input_coverage(
    mut result: Value,
    coverage: &super::candidates::CandidateCoverage,
) -> anyhow::Result<Value> {
    result["data"]["inputCoverage"] = serde_json::to_value(coverage)?;
    let text = format!("Ledger read: {} observations · {} encoded bytes across raw and projected input.\nJudge candidates: {} selected · {} omitted across {} file buckets.\nRead limits: maxLedgerObservations={} · maxLedgerBytes={} · maxLedgerReadMs={} (cooperative).",
        coverage.observations_read, coverage.encoded_bytes_read, coverage.selected_candidates,
        coverage.omitted_candidates, coverage.omitted_file_buckets, coverage.max_ledger_observations,
        coverage.max_ledger_bytes, coverage.max_ledger_read_ms);
    result["output"] = json!(format!(
        "{}\n\n{text}",
        result["output"].as_str().unwrap_or_default()
    ));
    Ok(result)
}

pub(super) fn empty_dedupe_result(candidate_count: usize, omitted: usize) -> Value {
    let summary = if omitted > 0 {
        format!("triage:dedupe: candidate allowance omitted {omitted} eligible observations; no judge request was made. Explicitly revise maxCandidates or use a smaller engagement.")
    } else {
        format!(
        "triage:dedupe: {candidate_count} candidate(s); need at least 2 co-located findings from different runs or tools"
    )
    };
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
        "confirmationInputs": confirmed.confirmation_inputs,
        "confirmationRefusals": confirmed.confirmation_refusals,
        "droppedProposals": confirmed.dropped,
        "linked": report.linked,
        "alreadyLinked": report.already_linked,
        "skippedConflict": report.skipped_conflict,
        "skippedHuman": report.skipped_human,
        "verdictsRecorded": report.verdicts_recorded,
        "relationshipsProposed": report.proposed,
        "relationshipIds": report.relationship_ids,
    });
    crate::module_result::apply_runtime_cost_report(&mut data, cost);
    let output = confirmation_output(dedupe_output(&summary, &confirmed.groups), confirmed);
    let mut result = crate::module_result::completed_output_result(summary, output, data);
    crate::module_result::apply_runtime_cost_report(&mut result, cost);
    result
}

fn confirmation_output(output: String, confirmed: &ConfirmedGroups) -> String {
    if confirmed.escalated == 0 {
        return output;
    }
    format!("{output}\nConfirmation attempts: {}. Current workspace source: {} / {} bytes reserved; historical source may differ. Dropped proposals: {:?}. Confirmation refusals: {}. Inspect confirmationInputs for unavailable files and unknown reads.",
        confirmed.escalated, confirmed.confirmation_inputs["reservedBytes"],
        confirmed.confirmation_inputs["maxConfirmationBytes"], confirmed.dropped,
        serde_json::to_string(&confirmed.confirmation_refusals).unwrap_or_default())
}

fn dedupe_summary(
    confirmed: &ConfirmedGroups,
    report: &LinkReport,
    candidate_count: usize,
) -> String {
    if report.proposed > 0 {
        return format!("triage:dedupe: {} duplicate relationship candidate(s); review before acceptance. Finding identities and verdicts are unchanged.",report.proposed);
    }
    let action = if report.dry_run {
        "proposed (dry run)"
    } else {
        "linked"
    };
    format!(
        "triage:dedupe: {} duplicate group(s) over {} candidate(s); {} duplicate(s) {}, {} already linked, {} conflict(s) skipped, {} human-decided skipped",
        confirmed.groups.len(),
        candidate_count,
        report.linked,
        action,
        report.already_linked,
        report.skipped_conflict,
        report.skipped_human,
    )
}

/// The summary plus one line per group, so a dry run shows what it would
/// link rather than only counting it.
fn dedupe_output(summary: &str, groups: &[DuplicateGroup]) -> String {
    let lines = groups.iter().map(|group| {
        format!(
            "  - {} ({} duplicate(s) of {}, confidence {:.2})",
            group.root_cause_summary,
            group.duplicate_fingerprints.len(),
            short_fingerprint(&group.canonical_fingerprint),
            group.confidence,
        )
    });
    std::iter::once(summary.to_string())
        .chain(lines)
        .collect::<Vec<_>>()
        .join("\n")
}

fn short_fingerprint(fingerprint: &str) -> &str {
    fingerprint.get(..12).unwrap_or(fingerprint)
}

fn group_json(group: &DuplicateGroup) -> Value {
    json!({
        "canonicalFingerprint": group.canonical_fingerprint,
        "duplicateFingerprints": group.duplicate_fingerprints,
        "rootCauseSummary": group.root_cause_summary,
        "confidence": group.confidence,
    })
}

#[cfg(test)]
mod output_tests {
    use super::*;

    #[test]
    fn the_output_lists_each_proposed_group_under_the_summary() {
        let group = DuplicateGroup {
            canonical_fingerprint: "fp3_7d29d78f31efa2e0".to_string(),
            duplicate_fingerprints: vec!["fp3_c251".to_string()],
            root_cause_summary: "SQL injection in the login route".to_string(),
            confidence: 0.95,
        };

        let output = dedupe_output("summary", &[group]);

        assert_eq!(
            output,
            "summary\n  - SQL injection in the login route (1 duplicate(s) of fp3_7d29d78f, confidence 0.95)"
        );
    }
}
