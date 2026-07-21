use super::domain::{ReasonTag, ScanRecommendation};
use crate::modules::WorkflowPhase;
use crate::workspace::coverage_ledger::{BaselineRow, SweepReport, SweepVerdict};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Everything the fold reads, gathered by the caller so the ranking itself
/// stays pure and testable without a workspace.
pub struct RecommenderInputs<'a> {
    /// Scope id → repo-relative path (`"."` for the root scope).
    pub scope_paths: &'a BTreeMap<String, String>,
    /// Latest baseline per scope×phase (coverage ledger).
    pub latest_baselines: &'a [BaselineRow],
    /// Every baseline row, for saturation counting.
    pub all_baselines: &'a [BaselineRow],
    pub sweep: Option<&'a SweepReport>,
    /// Repo-relative surface-bearing files → surface count.
    pub surface_files: &'a BTreeMap<String, usize>,
    /// Repo-relative files cited by at least one finding.
    pub finding_files: &'a BTreeSet<String>,
}

pub fn recommend(inputs: &RecommenderInputs<'_>) -> Vec<ScanRecommendation> {
    let mut rows = Vec::new();
    rows.extend(coverage_gap_rows(inputs));
    rows.extend(staleness_rows(inputs));
    rows.extend(sink_gap_rows(inputs));
    rows.extend(saturation_rows(inputs));
    rows.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.scope_id.cmp(&b.scope_id))
    });
    rows
}

fn coverage_gap_rows(inputs: &RecommenderInputs<'_>) -> Vec<ScanRecommendation> {
    inputs
        .scope_paths
        .keys()
        .filter_map(|scope_id| coverage_gap_row(inputs, scope_id))
        .collect()
}

fn coverage_gap_row(
    inputs: &RecommenderInputs<'_>,
    scope_id: &str,
) -> Option<ScanRecommendation> {
    if scanned(inputs, scope_id, WorkflowPhase::Scan) {
        return None;
    }
    let any_phase = inputs
        .latest_baselines
        .iter()
        .any(|row| row.scope_id == scope_id);
    Some(if any_phase {
        recommendation(
            scope_id,
            WorkflowPhase::Scan,
            ReasonTag::PhaseGap,
            0.85,
            "earlier phases ran here but scan never did".to_string(),
        )
    } else {
        recommendation(
            scope_id,
            WorkflowPhase::Scan,
            ReasonTag::NeverScanned,
            0.9,
            "no baseline recorded for any phase".to_string(),
        )
    })
}

fn scanned(inputs: &RecommenderInputs<'_>, scope_id: &str, phase: WorkflowPhase) -> bool {
    inputs
        .latest_baselines
        .iter()
        .any(|row| row.scope_id == scope_id && row.phase == phase)
}

fn staleness_rows(inputs: &RecommenderInputs<'_>) -> Vec<ScanRecommendation> {
    let Some(sweep) = inputs.sweep else {
        return Vec::new();
    };
    sweep
        .entries
        .iter()
        .filter_map(|entry| match entry.verdict {
            SweepVerdict::Changed { files } => Some(recommendation(
                &entry.scope_id,
                entry.phase,
                ReasonTag::Changed,
                changed_score(files),
                format!(
                    "{files} file(s) changed since {}",
                    short_sha(&entry.baseline_sha)
                ),
            )),
            SweepVerdict::Current | SweepVerdict::BaselineUnreachable => None,
        })
        .collect()
}

/// 0.5 base plus up to 0.3 for volume: one changed file is a nudge, forty
/// is a near-certain rescan.
fn changed_score(files: usize) -> f32 {
    0.5 + (files.min(40) as f32) / 40.0 * 0.3
}

fn sink_gap_rows(inputs: &RecommenderInputs<'_>) -> Vec<ScanRecommendation> {
    inputs
        .scope_paths
        .iter()
        .filter_map(|(scope_id, rel_path)| sink_gap_row(inputs, scope_id, rel_path))
        .collect()
}

fn sink_gap_row(
    inputs: &RecommenderInputs<'_>,
    scope_id: &str,
    rel_path: &str,
) -> Option<ScanRecommendation> {
    let (surface_files, gap_files) = surface_and_gap_counts(inputs, rel_path);
    if gap_files == 0 {
        return None;
    }
    Some(ScanRecommendation {
        suggested_mode: Some("sink-gap".to_string()),
        ..recommendation(
            scope_id,
            WorkflowPhase::Scan,
            ReasonTag::SinkGap,
            sink_gap_score(gap_files),
            format!("{gap_files} of {surface_files} surface-bearing file(s) have zero findings"),
        )
    })
}

fn surface_and_gap_counts(inputs: &RecommenderInputs<'_>, rel_path: &str) -> (usize, usize) {
    let in_scope = inputs
        .surface_files
        .keys()
        .filter(|file| file_under(file, rel_path));
    let mut surface_files = 0;
    let mut gap_files = 0;
    for file in in_scope {
        surface_files += 1;
        if !inputs.finding_files.contains(file) {
            gap_files += 1;
        }
    }
    (surface_files, gap_files)
}

fn sink_gap_score(gap_files: usize) -> f32 {
    0.4 + (gap_files.min(20) as f32) / 20.0 * 0.2
}

fn saturation_rows(inputs: &RecommenderInputs<'_>) -> Vec<ScanRecommendation> {
    let Some(head_sha) = inputs.sweep.map(|sweep| sweep.head.sha.as_str()) else {
        return Vec::new();
    };
    let mut passes_at_head: BTreeMap<&str, usize> = BTreeMap::new();
    for row in inputs.all_baselines {
        if row.phase == WorkflowPhase::Scan && row.revision.sha == head_sha {
            *passes_at_head.entry(row.scope_id.as_str()).or_default() += 1;
        }
    }
    passes_at_head
        .into_iter()
        .filter(|(_, passes)| *passes >= 2)
        .map(|(scope_id, passes)| ScanRecommendation {
            suggested_mode: Some("sink-gap".to_string()),
            ..recommendation(
                scope_id,
                WorkflowPhase::Scan,
                ReasonTag::Saturated,
                0.2,
                format!("{passes} scan pass(es) at the current revision; prefer gap-fill only"),
            )
        })
        .collect()
}

fn recommendation(
    scope_id: &str,
    phase: WorkflowPhase,
    reason: ReasonTag,
    score: f32,
    evidence: String,
) -> ScanRecommendation {
    ScanRecommendation {
        scope_id: scope_id.to_string(),
        phase,
        reason,
        score,
        evidence,
        suggested_mode: None,
    }
}

fn file_under(file: &str, rel_path: &str) -> bool {
    rel_path == "." || Path::new(file).starts_with(rel_path)
}

fn short_sha(sha: &str) -> &str {
    sha.get(..8).unwrap_or(sha)
}
