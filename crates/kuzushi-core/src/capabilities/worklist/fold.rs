//! The pure worklist fold. No IO: the caller gathers every input so ranking
//! stays deterministic and testable without a workspace.

use super::domain::{
    weight_of, Citation, Contributor, ContributorState, UnrankedFile, Worklist, WorklistRow,
};
use crate::capabilities::full_mode_multi::PrefilteredChunk;
use crate::capabilities::scan_recommender::ScanRecommendation;
use crate::capabilities::systems_hunt::RankedSystemsSurface;
use crate::workspace::AttackSurface;
use std::collections::BTreeMap;
use std::path::Path;

/// Whether the scan-coverage recommendations were actually computed for this
/// fold. An empty `recommendations` slice is ambiguous on its own — it can mean
/// "coverage is current, nothing recommended" or "the async load has not
/// arrived yet" — so the caller states which it is instead of the fold guessing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecommendationsStatus {
    /// Recommendations were computed (the slice may still be empty when
    /// coverage is current).
    Available,
    /// The recommendations input has not been hydrated yet; coverage is
    /// genuinely unknown, not "current".
    NotLoaded,
    /// The recommender or its scope map failed to load; coverage is degraded
    /// but the surface-based worklist still stands.
    Degraded(String),
}

/// Everything the fold reads. `systems`, `prefilter`, and `fan_in` are optional
/// so their absence is a distinct contributor state, never a zeroed citation.
pub struct WorklistInputs<'a> {
    pub surfaces: &'a [AttackSurface],
    pub recommendations: &'a [ScanRecommendation],
    /// Whether `recommendations` reflects a real computation, so the
    /// `ScanCoverage` contributor state stays honest.
    pub recommendations_status: RecommendationsStatus,
    /// Scope id → repo-relative path (`"."` for the root scope).
    pub scope_paths: &'a BTreeMap<String, String>,
    pub systems: Option<&'a [RankedSystemsSurface]>,
    pub prefilter: Option<&'a [PrefilteredChunk]>,
    pub fan_in: Option<&'a BTreeMap<String, usize>>,
    pub limit: usize,
}

/// One file's accumulated citations plus the line evidence needed to pick a
/// single representative row line. Rows are keyed by file path so every
/// contributor's evidence for a file folds into one row (combined glyphs), not
/// one single-glyph row per `(path, line)` pair.
#[derive(Default)]
struct FileBucket {
    citations: Vec<Citation>,
    /// The smallest line reported by an attack-surface citation, preferred as
    /// the representative line.
    surface_line: Option<u32>,
    /// The smallest line reported by any citation, the fallback when no
    /// attack-surface line exists.
    min_line: Option<u32>,
}

impl FileBucket {
    fn push_surface(&mut self, line: Option<u32>, citation: Citation) {
        self.surface_line = min_option(self.surface_line, line);
        self.min_line = min_option(self.min_line, line);
        self.citations.push(citation);
    }

    fn push_line(&mut self, line: Option<u32>, citation: Citation) {
        self.min_line = min_option(self.min_line, line);
        self.citations.push(citation);
    }

    fn representative_line(&self) -> Option<u32> {
        self.surface_line.or(self.min_line)
    }
}

fn min_option(current: Option<u32>, candidate: Option<u32>) -> Option<u32> {
    match (current, candidate) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, candidate) => candidate,
    }
}

pub fn rank(inputs: &WorklistInputs<'_>) -> Worklist {
    let (mut rows, unranked) = split_ranked(inputs, base_buckets(inputs));
    sort_rows(&mut rows);
    assign_ranks(&mut rows);
    let ranked_total = rows.len();
    rows.truncate(inputs.limit);
    let contributors = contributor_states(inputs);
    let degraded = degraded_reasons(&contributors);
    Worklist {
        rows,
        ranked_total,
        contributors,
        unranked,
        degraded,
    }
}

fn base_buckets(inputs: &WorklistInputs<'_>) -> BTreeMap<String, FileBucket> {
    let mut buckets: BTreeMap<String, FileBucket> = BTreeMap::new();
    for surface in inputs.surfaces {
        buckets
            .entry(surface.path.clone())
            .or_default()
            .push_surface(surface.line, surface_citation(surface));
    }
    if let Some(systems) = inputs.systems {
        let len = systems.len();
        for (index, surface) in systems.iter().enumerate() {
            let citation = systems_citation(surface, index, len);
            buckets
                .entry(surface.file_path.clone())
                .or_default()
                .push_line(Some(surface.start_line), citation);
        }
    }
    buckets
}

fn split_ranked(
    inputs: &WorklistInputs<'_>,
    buckets: BTreeMap<String, FileBucket>,
) -> (Vec<WorklistRow>, Vec<UnrankedFile>) {
    let mut rows = Vec::new();
    let mut unranked = Vec::new();
    for (path, bucket) in buckets {
        match ranked_row(inputs, path, bucket) {
            Ok(row) => rows.push(row),
            Err(file) => unranked.push(file),
        }
    }
    (rows, unranked)
}

fn ranked_row(
    inputs: &WorklistInputs<'_>,
    path: String,
    bucket: FileBucket,
) -> Result<WorklistRow, UnrankedFile> {
    let line = bucket.representative_line();
    let mut citations = bucket.citations;
    if combine(&citations) <= 0.0 {
        return Err(UnrankedFile {
            path,
            reason: "no live ranking signal at this revision".to_string(),
        });
    }
    let scope_id = scope_for_path(inputs.scope_paths, &path);
    if let Some(citation) = coverage_citation(inputs, scope_id.as_deref()) {
        citations.push(citation);
    }
    Ok(WorklistRow {
        score: combine(&citations),
        path,
        line,
        rank: 0,
        citations,
        scope_id,
    })
}

fn combine(citations: &[Citation]) -> f32 {
    citations
        .iter()
        .map(|citation| citation.normalized * weight_of(citation.contributor))
        .sum()
}

fn surface_citation(surface: &AttackSurface) -> Citation {
    let raw = surface.risk.score as f64;
    Citation {
        contributor: Contributor::AttackSurface,
        raw,
        raw_display: format!("{}/100", surface.risk.score),
        normalized: normalize_bounded(raw, 100.0),
        normalization: "bounded/100",
        reasons: surface.risk.reasons.clone(),
    }
}

fn systems_citation(surface: &RankedSystemsSurface, index: usize, len: usize) -> Citation {
    Citation {
        contributor: Contributor::SystemsHunt,
        raw: surface.score as f64,
        raw_display: format!("score {}", surface.score),
        normalized: normalize_unbounded_rank(index, len),
        normalization: "rank",
        reasons: surface.reasons.clone(),
    }
}

/// Coverage is a scope-level modifier: it annotates rows whose path falls under
/// a recommended scope, and never creates a row on its own.
fn coverage_citation(inputs: &WorklistInputs<'_>, scope_id: Option<&str>) -> Option<Citation> {
    let scope_id = scope_id?;
    let recommendation = inputs
        .recommendations
        .iter()
        .filter(|rec| rec.scope_id == scope_id)
        .max_by(|left, right| left.score.total_cmp(&right.score))?;
    Some(Citation {
        contributor: Contributor::ScanCoverage,
        raw: recommendation.score as f64,
        raw_display: format!(
            "{} {}",
            recommendation.phase.word(),
            recommendation.reason.label()
        ),
        normalized: recommendation.score.clamp(0.0, 1.0),
        normalization: "score",
        reasons: vec![recommendation.evidence.clone()],
    })
}

fn scope_for_path(scope_paths: &BTreeMap<String, String>, path: &str) -> Option<String> {
    scope_paths
        .iter()
        .filter(|(_, rel_path)| file_under(path, rel_path))
        .max_by_key(|(_, rel_path)| rel_path.len())
        .map(|(scope_id, _)| scope_id.clone())
}

fn file_under(file: &str, rel_path: &str) -> bool {
    rel_path == "." || Path::new(file).starts_with(rel_path)
}

fn normalize_bounded(raw: f64, max: f64) -> f32 {
    if max <= 0.0 {
        return 0.0;
    }
    (raw / max).clamp(0.0, 1.0) as f32
}

fn normalize_unbounded_rank(index: usize, len: usize) -> f32 {
    if len == 0 {
        return 0.0;
    }
    (len - index) as f32 / len as f32
}

fn sort_rows(rows: &mut [WorklistRow]) {
    rows.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.line.cmp(&right.line))
    });
}

fn assign_ranks(rows: &mut [WorklistRow]) {
    for (index, row) in rows.iter_mut().enumerate() {
        row.rank = index + 1;
    }
}

fn contributor_states(inputs: &WorklistInputs<'_>) -> BTreeMap<Contributor, ContributorState> {
    BTreeMap::from([
        (Contributor::AttackSurface, attack_surface_state(inputs)),
        (Contributor::ScanCoverage, scan_coverage_state(inputs)),
        (
            Contributor::SystemsHunt,
            requested_state(inputs.systems.is_some()),
        ),
        (Contributor::PrefilterHistory, prefilter_state(inputs)),
        (Contributor::CallGraphFanIn, fan_in_state(inputs)),
        (Contributor::Complexity, ContributorState::NotRequested),
    ])
}

fn attack_surface_state(inputs: &WorklistInputs<'_>) -> ContributorState {
    if inputs.surfaces.is_empty() {
        ContributorState::Unavailable {
            reason: "no attack-surface map — run context:build".to_string(),
        }
    } else {
        ContributorState::Live
    }
}

/// The coverage state reflects whether recommendations were actually folded,
/// never a hardcoded `Live`. An empty-but-unloaded input is `Unavailable`, a
/// load failure is `Degraded`, and a real (possibly empty) computation is
/// `Live`.
fn scan_coverage_state(inputs: &WorklistInputs<'_>) -> ContributorState {
    match &inputs.recommendations_status {
        RecommendationsStatus::Available => ContributorState::Live,
        RecommendationsStatus::NotLoaded => ContributorState::Unavailable {
            reason: "scan coverage not loaded yet".to_string(),
        },
        RecommendationsStatus::Degraded(reason) => ContributorState::Degraded {
            reason: reason.clone(),
        },
    }
}

fn requested_state(requested: bool) -> ContributorState {
    if requested {
        ContributorState::Live
    } else {
        ContributorState::NotRequested
    }
}

/// Prefilter history is a Phase-A non-feature: no history is *ever* consulted at
/// this stage, so its absence is `NotRequested`, never a false "no history
/// exists at this revision" claim about data nobody checked.
fn prefilter_state(inputs: &WorklistInputs<'_>) -> ContributorState {
    match inputs.prefilter {
        Some(_) => ContributorState::Live,
        None => ContributorState::NotRequested,
    }
}

fn fan_in_state(inputs: &WorklistInputs<'_>) -> ContributorState {
    match inputs.fan_in {
        None => ContributorState::NotRequested,
        Some(map) if map.is_empty() => ContributorState::Degraded {
            reason: "no cpg graph".to_string(),
        },
        Some(_) => ContributorState::Live,
    }
}

fn degraded_reasons(contributors: &BTreeMap<Contributor, ContributorState>) -> Vec<String> {
    contributors
        .values()
        .filter_map(|state| match state {
            ContributorState::Degraded { reason } => Some(reason.clone()),
            _ => None,
        })
        .collect()
}
