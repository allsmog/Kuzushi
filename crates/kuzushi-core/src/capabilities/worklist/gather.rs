//! The IO adapter: gather the deterministic inputs for a target and fold them
//! into a ranked worklist. Read-only. Never triggers a graph build — the
//! systems ranker used here is the Read-safe `rank_systems_surfaces_lite`, and
//! it only runs under explicit `deep=true`.

use super::domain::{Contributor, ContributorState, Worklist};
use super::fold::{rank, RecommendationsStatus, WorklistInputs};
use crate::capabilities::scan_recommender::{
    recommend_scans_for_target, scope_paths, ScanRecommendation,
};
use crate::capabilities::systems_hunt::{rank_systems_surfaces_lite, RankedSystemsSurface};
use crate::findings::FindingStore;
use crate::workspace::{load_attack_surface_map_detailed, AttackSurface, AttackSurfaceMapLoad};
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;

pub struct WorklistOptions {
    pub limit: usize,
    pub deep: bool,
    /// Unimplemented. Explicit requests are refused rather than ignored.
    pub include_fan_in: bool,
}

/// The gathered scan-coverage contributor: its recommendations, scope map, and
/// an honest status so a load failure degrades that one contributor instead of
/// hard-failing the whole worklist.
struct CoverageInput {
    recommendations: Vec<ScanRecommendation>,
    scope_paths: BTreeMap<String, String>,
    status: RecommendationsStatus,
}

pub fn rank_worklist_for_target(
    target: &Path,
    options: &WorklistOptions,
    findings_store: Option<&FindingStore>,
) -> Result<Worklist> {
    rank_worklist_observed(target, options, findings_store, &mut |_| {}, &|| false)
        .map(|report| report.worklist)
}

pub(crate) struct InspectedWorklist {
    pub worklist: Worklist,
    pub systems_inspection: Option<serde_json::Value>,
}

pub(crate) fn rank_worklist_observed(
    target: &Path,
    options: &WorklistOptions,
    findings_store: Option<&FindingStore>,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<InspectedWorklist> {
    anyhow::ensure!(!canceled(), "worklist ranking canceled");
    anyhow::ensure!(
        !options.include_fan_in,
        "call-graph fan-in is not implemented"
    );
    anyhow::ensure!(
        (1..=500).contains(&options.limit),
        "worklist limit must be between 1 and 500"
    );
    let (surfaces, surface_reason) = load_surfaces(target);
    let coverage = gather_coverage(target, findings_store);
    let systems = gather_systems(target, options, progress, canceled)?;
    let (surfaces_systems, systems_inspection) = systems.unzip();
    let mut worklist = rank(&WorklistInputs {
        surfaces: &surfaces,
        recommendations: &coverage.recommendations,
        recommendations_status: coverage.status,
        scope_paths: &coverage.scope_paths,
        systems: surfaces_systems.as_deref(),
        prefilter: None,
        fan_in: None,
        limit: options.limit,
    });
    apply_surface_degradation(&mut worklist, surface_reason);
    apply_systems_inspection(&mut worklist, systems_inspection.as_ref());
    Ok(InspectedWorklist {
        worklist,
        systems_inspection,
    })
}

/// When a context snapshot exists but its attack-surface records were
/// unreadable, the fold's default `Unavailable`/"run context:build" wording
/// misleads — a map *was* persisted. Override the `AttackSurface` contributor to
/// `Degraded` with the probed reason so the fold's "no map" state stays reserved
/// for a genuinely absent snapshot.
fn apply_surface_degradation(worklist: &mut Worklist, reason: Option<String>) {
    let Some(reason) = reason else {
        return;
    };
    worklist.contributors.insert(
        Contributor::AttackSurface,
        ContributorState::Degraded {
            reason: reason.clone(),
        },
    );
    worklist.degraded.push(reason);
}

/// Gather scan-coverage recommendations and their scope map. A recommender or
/// scope-load failure degrades the `ScanCoverage` contributor to a stated
/// reason and returns the surface-based worklist, mirroring the `Ok(None)`
/// honesty of the surface loader — it never `?`-propagates the error.
fn gather_coverage(target: &Path, findings_store: Option<&FindingStore>) -> CoverageInput {
    let scope_paths = match scope_paths(target) {
        Ok(scope_paths) => scope_paths,
        Err(error) => {
            return CoverageInput {
                recommendations: Vec::new(),
                scope_paths: BTreeMap::new(),
                status: RecommendationsStatus::Degraded(format!("scope map unavailable: {error}")),
            };
        }
    };
    match recommend_scans_for_target(target, findings_store) {
        Ok(recommendations) => CoverageInput {
            recommendations,
            scope_paths,
            status: RecommendationsStatus::Available,
        },
        Err(error) => CoverageInput {
            recommendations: Vec::new(),
            scope_paths,
            status: RecommendationsStatus::Degraded(format!("scan coverage unavailable: {error}")),
        },
    }
}

/// Probe the persisted attack-surface map, distinguishing a genuinely absent (or
/// benignly empty) map from one that was persisted but whose surface records are
/// unreadable. Returns the surfaces plus an optional degradation reason.
///
/// Honesty contract (C-1): a `Full` map — even one that honestly carries zero
/// surfaces — is NEVER degraded; it yields `(surfaces, None)` so the fold's
/// existing `Unavailable{"no attack-surface map — run context:build"}` state
/// stands for the empty case, matching the TUI deck. Only a genuine
/// `SummaryRecovered` (a malformed surfaces array that fell back to summary
/// counts) is `Degraded`. `Missing { file_present: true }` means the loader
/// actually read a snapshot file but found no readable attack-surface map (a
/// legacy/foreign snapshot lacking the key, or one the bounded reader could not
/// decode) — still a `context:build` recovery hint. `Missing { file_present:
/// false }` means no snapshot at all, the honest empty state. The presence
/// signal comes from the loader's own read attempt, so there is no separate
/// `.exists()` stat racing the reader.
fn load_surfaces(target: &Path) -> (Vec<AttackSurface>, Option<String>) {
    match load_attack_surface_map_detailed(target) {
        AttackSurfaceMapLoad::Full(map) => (map.surfaces, None),
        AttackSurfaceMapLoad::SummaryRecovered(_) => (
            Vec::new(),
            Some(
                "attack-surface map recovered summary-only — surface records unreadable; re-run context:build"
                    .into(),
            ),
        ),
        AttackSurfaceMapLoad::Missing { file_present: true } => (
            Vec::new(),
            Some(
                "context snapshot present but carries no readable attack-surface map — re-run context:build"
                    .into(),
            ),
        ),
        AttackSurfaceMapLoad::Missing {
            file_present: false,
        } => (Vec::new(), None),
    }
}

fn gather_systems(
    target: &Path,
    options: &WorklistOptions,
    progress: &mut dyn FnMut(usize),
    canceled: &dyn Fn() -> bool,
) -> Result<Option<(Vec<RankedSystemsSurface>, serde_json::Value)>> {
    if !options.deep {
        return Ok(None);
    }
    Ok(Some(rank_systems_surfaces_lite(
        target,
        options.limit,
        progress,
        canceled,
    )?))
}

fn apply_systems_inspection(worklist: &mut Worklist, receipt: Option<&serde_json::Value>) {
    let Some(receipt) = receipt else {
        return;
    };
    if receipt["status"] != "partial" {
        return;
    }
    let reason = "Deep inspection is partial; some source or evidence was omitted.".to_string();
    worklist.contributors.insert(
        Contributor::SystemsHunt,
        ContributorState::Degraded {
            reason: reason.clone(),
        },
    );
    worklist.degraded.push(reason);
}
