use std::collections::BTreeSet;

use crate::review_yield::domain::{
    author_bucket, classify_cutoff, is_human_author, CensusReport, CutoffQuality,
    TrainingExampleV1,
};
use crate::review_yield::persistence::DecisionRow;

/// Counts every recorded decision, including the ones the label policy
/// excludes. The census is the honest denominator for the export.
pub fn count_decisions(report: &mut CensusReport, decisions: &[DecisionRow]) {
    for decision in decisions {
        observe_decision(report, decision);
    }
}

fn observe_decision(report: &mut CensusReport, decision: &DecisionRow) {
    report.decision_events += 1;
    CensusReport::bump(&mut report.by_author, author_bucket(&decision.author));
    CensusReport::bump(&mut report.by_verdict, decision.verdict.as_str());
    for reason in decision.dismiss_reason.iter() {
        CensusReport::bump(&mut report.by_dismiss_reason, reason);
    }
    if is_human_author(&decision.author) {
        observe_human_decision(report, decision);
    }
}

fn observe_human_decision(report: &mut CensusReport, decision: &DecisionRow) {
    report.human_decision_events += 1;
    CensusReport::bump(&mut report.cutoff_quality, cutoff_quality(decision).as_str());
    if decision.identity_id.is_none() {
        report.missing_durable_identity += 1;
    }
}

fn cutoff_quality(decision: &DecisionRow) -> CutoffQuality {
    decision
        .provenance
        .as_ref()
        .map(|provenance| classify_cutoff(provenance.read_watermark, provenance.event_seq))
        .unwrap_or(CutoffQuality::Missing)
}

/// Records the label-event span and the feature diversity actually achieved by
/// the exported rows.
pub fn count_row_diversity(report: &mut CensusReport, rows: &[TrainingExampleV1]) {
    report.distinct_tool_families = distinct(rows, |row| row.features.tool_family.as_str());
    report.distinct_rule_families = distinct(rows, |row| row.features.rule_family.as_str());
    report.distinct_language_families = distinct(rows, |row| row.features.language_family.as_str());
    report.earliest_label_event_seq = rows.iter().map(|row| row.label_event.seq).min();
    report.latest_label_event_seq = rows.iter().map(|row| row.label_event.seq).max();
}

fn distinct(rows: &[TrainingExampleV1], select: fn(&TrainingExampleV1) -> &str) -> u64 {
    rows.iter().map(select).collect::<BTreeSet<&str>>().len() as u64
}
