//! Pure aggregation of every parent receipt in a selected Scan attempt.
use kuzushi_core::run_artifacts::*;
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct ScanReceiptSummary {
    pub receipt: PhaseStageReceipt,
    pub scope: String,
    pub plan: String,
}

pub(super) fn summarize(receipts: &[PhaseStageReceipt]) -> Option<ScanReceiptSummary> {
    let first = receipts.first()?;
    let scans = receipts
        .iter()
        .map(|receipt| receipt.scan.as_ref())
        .collect::<Option<Vec<_>>>()?;
    if scans
        .iter()
        .any(|scan| scan.target_snapshot != scans[0].target_snapshot)
    {
        return None;
    }
    let mut scan = scans[0].clone();
    scan.engines = combined_engines(&scans);
    scan.finding_delta = combined_delta(&scans);
    scan.severity_counts = combined_severities(&scans);
    scan.artifact_delta = combined_artifacts(&scans);
    scan.duration_ms = scans
        .iter()
        .fold(0u64, |sum, scan| sum.saturating_add(scan.duration_ms));
    scan.cost = combined_cost(&scans);
    let mut receipt = first.clone();
    receipt.run_refs = receipts
        .iter()
        .flat_map(|receipt| receipt.run_refs.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    receipt.scan = Some(scan);
    Some(ScanReceiptSummary {
        scope: combined_label(scans.iter().map(|scan| scope_label(&scan.scope)), "scopes"),
        plan: plan_label(&scans),
        receipt,
    })
}

fn combined_delta(scans: &[&ScanStageData]) -> ScanFindingDelta {
    scans
        .iter()
        .fold(ScanFindingDelta::default(), |sum, scan| ScanFindingDelta {
            added: sum.added.saturating_add(scan.finding_delta.added),
            updated: sum.updated.saturating_add(scan.finding_delta.updated),
        })
}

fn combined_engines(scans: &[&ScanStageData]) -> Vec<ScanStageEngine> {
    scans
        .iter()
        .enumerate()
        .flat_map(|(index, scan)| {
            scan.engines.iter().cloned().map(move |mut engine| {
                if scans.len() > 1 {
                    let suffix = engine
                        .detail
                        .map(|detail| format!(" · {detail}"))
                        .unwrap_or_default();
                    engine.detail =
                        Some(format!("scan run {} of {}{suffix}", index + 1, scans.len()));
                }
                engine
            })
        })
        .collect()
}

fn combined_severities(scans: &[&ScanStageData]) -> Vec<ScanSeverityCount> {
    let mut counts = BTreeMap::<_, u64>::new();
    for bucket in scans.iter().flat_map(|scan| &scan.severity_counts) {
        let count = counts.entry(bucket.severity).or_default();
        *count = count.saturating_add(bucket.count);
    }
    counts
        .into_iter()
        .rev()
        .map(|(severity, count)| ScanSeverityCount { severity, count })
        .collect()
}

fn combined_artifacts(scans: &[&ScanStageData]) -> Vec<ScanArtifactDelta> {
    scans
        .iter()
        .flat_map(|scan| &scan.artifact_delta)
        .map(|artifact| (artifact.run_ref.clone(), artifact.path.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|(run_ref, path)| ScanArtifactDelta { run_ref, path })
        .collect()
}

fn combined_cost(scans: &[&ScanStageData]) -> Option<ScanStageCost> {
    let costs = scans
        .iter()
        .filter_map(|scan| scan.cost)
        .collect::<Vec<_>>();
    if costs.is_empty() {
        return None;
    }
    Some(ScanStageCost {
        observed_usd: costs.iter().map(|cost| cost.observed_usd).sum(),
        complete: costs.len() == scans.len() && costs.iter().all(|cost| cost.complete),
    })
}

fn scope_label(scope: &ScanStageScope) -> String {
    if scope.paths.is_empty() {
        return scope.target.clone();
    }
    format!("{} · paths {}", scope.target, scope.paths.join(", "))
}

fn plan_label(scans: &[&ScanStageData]) -> String {
    let plan = combined_label(
        scans.iter().map(|scan| {
            format!(
                "{} selection · {}",
                scan.plan.selection,
                scan.plan.engines.join(", ")
            )
        }),
        "plans",
    );
    if scans.len() == 1 {
        return plan;
    }
    format!("{} scan runs · {plan}", scans.len())
}

fn combined_label(labels: impl Iterator<Item = String>, noun: &str) -> String {
    let labels = labels.collect::<BTreeSet<_>>();
    let joined = labels.iter().cloned().collect::<Vec<_>>().join("; ");
    if labels.len() == 1 {
        return joined;
    }
    format!("{} recorded {noun} · {joined}", labels.len())
}

#[cfg(test)]
mod tests;
