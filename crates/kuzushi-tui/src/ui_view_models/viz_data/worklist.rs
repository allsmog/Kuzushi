//! View model for the risk-ranked file worklist. Pure projection over the
//! shared `kuzushi_core::capabilities::worklist` fold, built from the
//! already-hydrated attack-surface artifact and cached scan recommendations —
//! no render-path disk IO.
//!
//! Two sources feed the deck. After an explicit `worklist:rank` run the tool's
//! captured output is the source of truth (it may carry the `deep`/systems `S`
//! rows the Read-safe shell fold omits), so the deck and the run receipt agree.
//! Before any run the shell folds the hydrated artifact itself — memoized by the
//! attack-surface artifact identity *and* the scan-recommendations state so
//! coverage citations appear the moment recommendations hydrate.

#[cfg(test)]
use crate::ui_view_models::attack_surface_artifact_version;
use crate::ui_view_models::{attack_surface_artifact_state, AttackSurfaceArtifactState};
use crate::{ShellApp, WorklistCacheKey};
use kuzushi_core::capabilities::scan_recommender::ScanRecommendation;
use kuzushi_core::capabilities::worklist::{
    rank, Contributor, ContributorState, RecommendationsStatus, Worklist, WorklistInputs,
    WorklistRow,
};
use kuzushi_core::workspace::AttackSurfaceMap;
use std::collections::BTreeMap;

mod context_artifact;
mod history;
mod snapshot;
pub(crate) use history::saved_worklist_run_id;

use context_artifact::worklist_artifact_state;
pub(crate) use context_artifact::worklist_artifact_version;
use snapshot::project_snapshot;

/// How many rows the fold retains for the scene deck; the Map section trims
/// this to its own top-N.
const WORKLIST_ROW_LIMIT: usize = 50;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct WorklistViewModel {
    pub rows: Vec<WorklistRowModel>,
    pub legend: Vec<LegendEntry>,
    pub degraded: Vec<String>,
    pub inspection: Vec<String>,
    pub history_notice: Option<String>,
    pub unranked_count: usize,
    /// The true ranked population before the row cap, so the Map pane reports
    /// "run worklist for all {ranked_total}" honestly instead of the capped
    /// `rows.len()`.
    pub ranked_total: usize,
    pub empty_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct WorklistRowModel {
    pub rank: usize,
    /// Glyph letters of the contributing rankers, e.g. `AC`.
    pub glyphs: String,
    pub location: String,
    /// Per-ranker raw evidence, e.g. `A 92/100  C scan sink-gap` — never a
    /// laundered normalized float.
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LegendEntry {
    pub glyph: char,
    pub label: String,
    pub state_word: Option<String>,
    pub dim: bool,
}

/// The scan-coverage recommendations plus an honest availability status, so the
/// fold's `ScanCoverage` contributor never claims `Live` on data that has not
/// hydrated (or that failed to load).
struct RecommendationsInput {
    rows: Vec<ScanRecommendation>,
    status: RecommendationsStatus,
}

pub(crate) fn worklist_model(app: &ShellApp) -> WorklistViewModel {
    // The O(1) hydration version of the loaded attack-surface artifact — read
    // once here and reused for both the snapshot staleness check and the memo
    // key, so the always-visible Map page never re-clones or re-parses the full
    // artifact per frame (New-2/New-3).
    let artifact_version = worklist_artifact_version(app);
    let recommendations = recommendations_input(app);
    // F6: an explicit `worklist:rank` run is the source of truth for the deck,
    // so the deck matches the run receipt (including deep/systems `S` rows the
    // Read-safe fold below omits by construction). New-1: the capture is only
    // trusted for the engagement it was computed for — same target root and
    // same artifact version. C-4: probe the snapshot identity in O(1) here so
    // the memo check happens BEFORE any snapshot clone+parse; the (large)
    // snapshot body is projected only on a cache miss, never per frame.
    let saved_run = match history::saved_run(app) {
        Ok(saved) => saved,
        Err(message) => return history::notice(message),
    };
    let snapshot_generation = worklist_snapshot_generation(app, artifact_version);
    let key = WorklistCacheKey::from_parts(
        artifact_version,
        recommendations_identity(&recommendations),
        snapshot_generation,
    )
    .with_saved_run(saved_run.clone());
    if let Some(cached) = app.workbench_cache().borrow().worklist(&key) {
        return cached;
    }
    // Cache miss only: project the captured snapshot (parse), or — when no
    // snapshot backs this engagement — pay the full artifact parse to fold.
    let model = worklist_snapshot_model(app, artifact_version)
        .or_else(|| {
            saved_run
                .as_ref()
                .and_then(|(id, _)| history::project_saved(app, id))
        })
        .unwrap_or_else(|| build_worklist_model(worklist_artifact_state(app), &recommendations));
    app.workbench_cache()
        .borrow_mut()
        .cache_worklist(key, model.clone());
    model
}

/// The O(1) identity of the captured `worklist:rank` snapshot for the active
/// engagement, or `None` when no snapshot backs it. Read on the render path to
/// key the memo without cloning or re-parsing the snapshot body (C-4).
fn worklist_snapshot_generation(app: &ShellApp, artifact_version: Option<u64>) -> Option<u64> {
    let target = app.target()?;
    app.domain()
        .worklist_snapshot_generation_for(target, artifact_version)
}

/// Project the captured `worklist:rank` output only when it belongs to the
/// active engagement (target root and artifact version both match).
fn worklist_snapshot_model(
    app: &ShellApp,
    artifact_version: Option<u64>,
) -> Option<WorklistViewModel> {
    let target = app.target()?;
    app.domain()
        .worklist_snapshot_for(target, artifact_version)
        .and_then(project_snapshot)
}

fn build_worklist_model(
    artifact: AttackSurfaceArtifactState,
    recommendations: &RecommendationsInput,
) -> WorklistViewModel {
    // Distinguish the three artifact dispositions the deck must handle, mirroring
    // the headless gather layer:
    //   - `Present` that parses into a map → its surfaces feed the fold.
    //   - `Present` with the wrong shape, or a `CorruptOrUnreadable` file →
    //     a map WAS persisted but is unreadable, so degrade the contributor
    //     instead of letting the fold report the "no map" `Unavailable` state.
    //   - `Absent` → no map at all; leave the fold's `Unavailable` wording.
    let (surfaces, artifact_unreadable) = match &artifact {
        AttackSurfaceArtifactState::Present(value) => match surfaces_from_artifact(value) {
            Some(surfaces) => (surfaces, false),
            None => (Vec::new(), true),
        },
        AttackSurfaceArtifactState::CorruptOrUnreadable => (Vec::new(), true),
        AttackSurfaceArtifactState::Absent => (Vec::new(), false),
    };
    let scope_paths = root_scope();
    let mut worklist = rank(&WorklistInputs {
        surfaces: &surfaces,
        recommendations: &recommendations.rows,
        recommendations_status: recommendations.status.clone(),
        scope_paths: &scope_paths,
        systems: None,
        prefilter: None,
        fan_in: None,
        limit: WORKLIST_ROW_LIMIT,
    });
    if artifact_unreadable {
        degrade_unreadable_surface(&mut worklist);
    }
    project_worklist(&worklist)
}

/// Override the `AttackSurface` contributor to `Degraded` with a persisted-map
/// reason, mirroring the core gather layer so the scene degraded banner and the
/// Map chip disclose "map present but unreadable" instead of "no map".
fn degrade_unreadable_surface(worklist: &mut Worklist) {
    let reason =
        "attack-surface artifact present but unreadable — re-run context:build".to_string();
    worklist.contributors.insert(
        Contributor::AttackSurface,
        ContributorState::Degraded {
            reason: reason.clone(),
        },
    );
    worklist.degraded.push(reason);
}

/// Parse the loaded attack-surface artifact into its surfaces. `None` means the
/// artifact value was present but did not parse — a persisted-but-unreadable
/// map, distinct from an absent artifact (which never reaches here).
fn surfaces_from_artifact(
    value: &serde_json::Value,
) -> Option<Vec<kuzushi_core::workspace::AttackSurface>> {
    serde_json::from_value::<AttackSurfaceMap>(value.clone())
        .ok()
        .map(|map| map.surfaces)
}

/// The scan-coverage recommendations with an honest status. `Ready` folds as
/// `Available`; a load failure degrades that contributor; anything not yet
/// hydrated is `NotLoaded` so the legend reads "not loaded yet", never a false
/// `Live`.
fn recommendations_input(app: &ShellApp) -> RecommendationsInput {
    use crate::app::{ScanRecommendationsState, ViewDataState};
    match app
        .workbench_cache()
        .borrow()
        .cached_scan_recommendations(app.target())
    {
        ViewDataState::Ready(ScanRecommendationsState::Ready(rows)) => RecommendationsInput {
            rows,
            status: RecommendationsStatus::Available,
        },
        ViewDataState::Ready(ScanRecommendationsState::Failed(reason)) => RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::Degraded(reason),
        },
        ViewDataState::NotRequested | ViewDataState::Loading => RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::NotLoaded,
        },
    }
}

/// A cheap identity for the recommendations input so the memo invalidates when
/// recommendations arrive, change, or fail — without hashing the artifact.
fn recommendations_identity(recommendations: &RecommendationsInput) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    match &recommendations.status {
        RecommendationsStatus::Available => 0u8.hash(&mut hasher),
        RecommendationsStatus::NotLoaded => 1u8.hash(&mut hasher),
        RecommendationsStatus::Degraded(reason) => {
            2u8.hash(&mut hasher);
            reason.hash(&mut hasher);
        }
    }
    for rec in &recommendations.rows {
        rec.scope_id.hash(&mut hasher);
        rec.score.to_bits().hash(&mut hasher);
        rec.evidence.hash(&mut hasher);
    }
    hasher.finish()
}

/// Render-path scope map: the root scope only (no nested-scope disk walk).
/// Keyed by the canonical root id so scan-coverage recommendations, which are
/// keyed the same way, annotate the rows that fall under it.
fn root_scope() -> BTreeMap<String, String> {
    BTreeMap::from([(
        kuzushi_core::workspace::ROOT_SCOPE_ID.to_string(),
        ".".to_string(),
    )])
}

fn project_worklist(worklist: &Worklist) -> WorklistViewModel {
    WorklistViewModel {
        rows: worklist.rows.iter().map(row_model).collect(),
        legend: worklist
            .contributors
            .iter()
            .map(|(contributor, state)| legend_entry(*contributor, state))
            .collect(),
        degraded: worklist.degraded.clone(),
        inspection: Vec::new(),
        history_notice: None,
        unranked_count: worklist.unranked.len(),
        ranked_total: worklist.ranked_total,
        empty_hint: empty_hint_for(
            worklist.rows.is_empty(),
            worklist.contributors.get(&Contributor::AttackSurface),
        ),
    }
}

fn row_model(row: &WorklistRow) -> WorklistRowModel {
    let display = dedupe_citations(
        row.citations
            .iter()
            .map(|c| (c.contributor.glyph(), c.raw, c.raw_display.clone())),
    );
    WorklistRowModel {
        rank: row.rank,
        glyphs: display.iter().map(|d| d.glyph).collect(),
        location: location_label(&row.path, row.line),
        summary: summary_label(&display),
    }
}

/// One contributor's collapsed display evidence: its glyph, a representative
/// (highest-raw) `raw_display`, and how many raw citations it stood in for.
struct DisplayCitation {
    glyph: char,
    raw_display: String,
    count: usize,
}

/// Collapse repeated citations from the same contributor for display (New-5). A
/// file with N attack-surface records would otherwise render glyphs `AAAA` and
/// a wall of duplicate scores — visually implying more signal than one high
/// record. Here each contributor shows one glyph carrying its highest-raw
/// evidence plus a `×N` multiplier. The stored `Worklist` keeps every raw
/// citation and the fold's additive score is unchanged; this only shapes the
/// glyph strip and summary line. First-seen contributor order is preserved.
fn dedupe_citations(citations: impl Iterator<Item = (char, f64, String)>) -> Vec<DisplayCitation> {
    let mut display: Vec<DisplayCitation> = Vec::new();
    let mut best_raw: Vec<f64> = Vec::new();
    for (glyph, raw, raw_display) in citations {
        match display.iter().position(|entry| entry.glyph == glyph) {
            Some(index) => {
                display[index].count += 1;
                if raw > best_raw[index] {
                    best_raw[index] = raw;
                    display[index].raw_display = raw_display;
                }
            }
            None => {
                display.push(DisplayCitation {
                    glyph,
                    raw_display,
                    count: 1,
                });
                best_raw.push(raw);
            }
        }
    }
    display
}

fn location_label(path: &str, line: Option<u32>) -> String {
    match line {
        Some(line) => format!("{path}:{line}"),
        None => path.to_string(),
    }
}

fn summary_label(display: &[DisplayCitation]) -> String {
    display
        .iter()
        .map(|entry| {
            if entry.count > 1 {
                format!("{} {} ×{}", entry.glyph, entry.raw_display, entry.count)
            } else {
                format!("{} {}", entry.glyph, entry.raw_display)
            }
        })
        .collect::<Vec<_>>()
        .join("  ")
}

fn legend_entry(contributor: Contributor, state: &ContributorState) -> LegendEntry {
    let (dim, state_word) = match state {
        ContributorState::Live => (false, None),
        ContributorState::Unavailable { reason } => (true, Some(reason.clone())),
        ContributorState::Degraded { reason } => (true, Some(reason.clone())),
        ContributorState::NotRequested => (true, Some(not_requested_word(contributor).to_string())),
    };
    LegendEntry {
        glyph: contributor.glyph(),
        label: contributor_label(contributor).to_string(),
        state_word,
        dim,
    }
}

/// Honest per-contributor wording for the `NotRequested` state. A bare "not
/// requested" contradicts an explicit `includeFanIn=true`, and call-graph
/// fan-in / prefilter history are unimplemented, not merely unrequested.
fn not_requested_word(contributor: Contributor) -> &'static str {
    match contributor {
        Contributor::CallGraphFanIn | Contributor::PrefilterHistory => "not supported",
        _ => "not requested",
    }
}

fn contributor_label(contributor: Contributor) -> &'static str {
    match contributor {
        Contributor::AttackSurface => "attack surface",
        Contributor::ScanCoverage => "scan coverage",
        Contributor::SystemsHunt => "systems hunt",
        Contributor::PrefilterHistory => "prefilter history",
        Contributor::CallGraphFanIn => "call-graph fan-in",
        Contributor::Complexity => "complexity",
    }
}

fn empty_hint_for(rows_empty: bool, attack_surface: Option<&ContributorState>) -> Option<String> {
    let attack_surface_unavailable =
        matches!(attack_surface, Some(ContributorState::Unavailable { .. }));
    (rows_empty && attack_surface_unavailable)
        .then(|| "no worklist yet — run `context:build`, then `worklist:rank`".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::capabilities::worklist::Citation;

    fn citation(contributor: Contributor, raw_display: &str) -> Citation {
        citation_with_raw(contributor, 92.0, raw_display)
    }

    fn citation_with_raw(contributor: Contributor, raw: f64, raw_display: &str) -> Citation {
        Citation {
            contributor,
            raw,
            raw_display: raw_display.to_string(),
            normalized: 0.9,
            normalization: "bounded/100",
            reasons: vec![],
        }
    }

    #[test]
    fn row_model_shows_glyph_and_raw_display_never_normalized() {
        let row = WorklistRow {
            path: "src/a.rs".to_string(),
            line: Some(4),
            score: 0.9,
            rank: 1,
            citations: vec![citation(Contributor::AttackSurface, "92/100")],
            scope_id: None,
        };

        let model = row_model(&row);

        assert_eq!(model.glyphs, "A");
        assert_eq!(model.location, "src/a.rs:4");
        assert!(model.summary.contains("92/100"));
        assert!(!model.summary.contains("0.9"));
    }

    #[test]
    fn row_model_dedupes_repeated_contributor_glyphs_and_marks_the_multiplier() {
        // New-5: a file with several attack-surface records shows one `A` glyph
        // carrying its highest-raw evidence and a `×N` count, not `AAAA` and a
        // wall of duplicate scores.
        let row = WorklistRow {
            path: "src/routes.rs".to_string(),
            line: Some(1),
            score: 1.5,
            rank: 1,
            citations: vec![
                citation_with_raw(Contributor::AttackSurface, 50.0, "50/100"),
                citation_with_raw(Contributor::AttackSurface, 90.0, "90/100"),
                citation_with_raw(Contributor::AttackSurface, 40.0, "40/100"),
                citation_with_raw(Contributor::ScanCoverage, 0.7, "scan sink-gap"),
            ],
            scope_id: None,
        };

        let model = row_model(&row);

        assert_eq!(model.glyphs, "AC", "one glyph per contributor");
        assert!(
            model.summary.contains("A 90/100 ×3"),
            "representative is the highest raw with a ×count, got {:?}",
            model.summary
        );
        assert!(model.summary.contains("C scan sink-gap"));
        // A single-record contributor carries no multiplier.
        assert!(!model.summary.contains("C scan sink-gap ×"));
    }

    #[test]
    fn legend_dims_non_live_with_honest_not_requested_wording() {
        let live = legend_entry(Contributor::AttackSurface, &ContributorState::Live);
        assert!(!live.dim);
        assert!(live.state_word.is_none());

        // Systems hunt is genuinely opt-in, so "not requested" is honest.
        let systems = legend_entry(Contributor::SystemsHunt, &ContributorState::NotRequested);
        assert!(systems.dim);
        assert_eq!(systems.state_word.as_deref(), Some("not requested"));

        // Fan-in / prefilter are unimplemented, not merely unrequested.
        let fan_in = legend_entry(Contributor::CallGraphFanIn, &ContributorState::NotRequested);
        assert_eq!(fan_in.state_word.as_deref(), Some("not supported"));
        let prefilter = legend_entry(
            Contributor::PrefilterHistory,
            &ContributorState::NotRequested,
        );
        assert_eq!(prefilter.state_word.as_deref(), Some("not supported"));
    }

    #[test]
    fn empty_hint_only_when_rows_empty_and_surface_unavailable() {
        let unavailable = ContributorState::Unavailable {
            reason: "no attack-surface map — run context:build".to_string(),
        };
        assert!(empty_hint_for(true, Some(&unavailable)).is_some());
        assert!(empty_hint_for(false, Some(&unavailable)).is_none());
        assert!(empty_hint_for(true, Some(&ContributorState::Live)).is_none());
    }

    #[test]
    fn recommendations_identity_changes_when_recommendations_arrive() {
        let not_loaded = RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::NotLoaded,
        };
        let ready = RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::Available,
        };

        assert_ne!(
            recommendations_identity(&not_loaded),
            recommendations_identity(&ready),
            "the memo must invalidate when recommendations hydrate"
        );
    }

    #[test]
    fn unreadable_artifact_degrades_attack_surface_not_unavailable() {
        // An attack-surface artifact value that is present but does not parse
        // into a map is a persisted-but-unreadable map, so the legend must read
        // `Degraded` (dim + reason) and the reason must surface in `degraded` —
        // never the "no map — run context:build" Unavailable wording.
        let garbage = serde_json::json!({ "surfaces": "oops" });
        let recommendations = RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::NotLoaded,
        };

        let model = build_worklist_model(
            AttackSurfaceArtifactState::Present(garbage),
            &recommendations,
        );

        let surface = model
            .legend
            .iter()
            .find(|entry| entry.glyph == Contributor::AttackSurface.glyph())
            .expect("attack-surface legend entry present");
        assert!(surface.dim, "degraded contributor renders dim");
        let word = surface.state_word.as_deref().unwrap_or_default();
        assert!(word.contains("unreadable"), "state word: {word:?}");
        assert!(
            model
                .degraded
                .iter()
                .any(|reason| reason.contains("unreadable")),
            "degraded reasons: {:?}",
            model.degraded
        );
        // A present-but-unreadable map is not the empty "no map" hint.
        assert!(model.empty_hint.is_none(), "{:?}", model.empty_hint);
    }

    #[test]
    fn parseable_empty_artifact_keeps_attack_surface_unavailable() {
        // A well-formed but surface-empty map is the honest "no surfaces yet"
        // state — the fold's `Unavailable` wording must be preserved.
        let empty = serde_json::json!({
            "rootName": "demo",
            "surfaces": [],
            "summary": {"total": 0, "byKind": {}, "byFile": {},
                        "highRisk": 0, "maxRiskScore": 0, "byRiskTier": {}}
        });
        let recommendations = RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::NotLoaded,
        };

        let model =
            build_worklist_model(AttackSurfaceArtifactState::Present(empty), &recommendations);

        let surface = model
            .legend
            .iter()
            .find(|entry| entry.glyph == Contributor::AttackSurface.glyph())
            .expect("attack-surface legend entry present");
        let word = surface.state_word.as_deref().unwrap_or_default();
        assert!(
            word.contains("no attack-surface map"),
            "state word: {word:?}"
        );
        assert!(model.degraded.is_empty(), "{:?}", model.degraded);
    }

    #[test]
    fn corrupt_or_unreadable_artifact_degrades_attack_surface_not_unavailable() {
        // New-1: a present-but-corrupt `attack-surface.json` (JsonFileState
        // Malformed/Unreadable/NonFile collapses to `CorruptOrUnreadable`) must
        // drive the same Degraded override as the core gather layer — a map WAS
        // persisted, so the legend reads a `context:build` recovery reason, never
        // the "no map" Unavailable wording.
        let recommendations = RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::NotLoaded,
        };

        let model = build_worklist_model(
            AttackSurfaceArtifactState::CorruptOrUnreadable,
            &recommendations,
        );

        let surface = model
            .legend
            .iter()
            .find(|entry| entry.glyph == Contributor::AttackSurface.glyph())
            .expect("attack-surface legend entry present");
        assert!(surface.dim, "degraded contributor renders dim");
        let word = surface.state_word.as_deref().unwrap_or_default();
        assert!(word.contains("unreadable"), "state word: {word:?}");
        assert!(
            model
                .degraded
                .iter()
                .any(|reason| reason.contains("unreadable")),
            "degraded reasons: {:?}",
            model.degraded
        );
        assert!(model.empty_hint.is_none(), "{:?}", model.empty_hint);
    }

    #[test]
    fn absent_artifact_keeps_attack_surface_unavailable_never_degraded() {
        // New-1: an absent artifact is the honest "no map" empty state — the
        // fold's Unavailable/"run context:build" wording must be preserved and
        // nothing pushed onto `degraded`, matching the headless absent case.
        let recommendations = RecommendationsInput {
            rows: Vec::new(),
            status: RecommendationsStatus::NotLoaded,
        };

        let model = build_worklist_model(AttackSurfaceArtifactState::Absent, &recommendations);

        let surface = model
            .legend
            .iter()
            .find(|entry| entry.glyph == Contributor::AttackSurface.glyph())
            .expect("attack-surface legend entry present");
        let word = surface.state_word.as_deref().unwrap_or_default();
        assert!(
            word.contains("no attack-surface map"),
            "state word: {word:?}"
        );
        assert!(model.degraded.is_empty(), "{:?}", model.degraded);
        assert!(
            model.empty_hint.is_some(),
            "absent map offers the empty hint"
        );
    }

    fn snapshot_rank_result() -> serde_json::Value {
        serde_json::json!({
            "data": {
                "rows": [{
                    "path": "src/deep.rs", "line": 12, "score": 0.8, "rank": 1,
                    "citations": [{
                        "contributor": "attackSurface", "raw": 90.0, "rawDisplay": "90/100",
                        "normalized": 0.9, "normalization": "bounded/100", "reasons": []
                    }]
                }],
                "rankedTotal": 1,
                "contributors": {"attackSurface": "live"},
                "unranked": [], "degraded": []
            }
        })
    }

    #[test]
    fn worklist_model_memoizes_the_snapshot_projection_no_reparse_per_frame() {
        // C-4 / New-5: with a captured `worklist:rank` snapshot present, the
        // first `worklist_model` call projects (parses) it once and fills the
        // memo; every later frame with the same key is a pure cache hit, so the
        // (large) snapshot body is never re-cloned+re-parsed per frame. The
        // memo KEY being stable is necessary but not sufficient — this test also
        // POISONS the captured snapshot's JSON body in place (without bumping its
        // generation, so the key is unchanged) and proves the second frame still
        // returns the ORIGINAL projection. A per-frame re-parse of the miss path
        // would instead surface the poisoned row and fail here.
        use kuzushi_core::V2Config;
        let temp = tempfile::tempdir().expect("tempdir");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.cache_tool_snapshot("worklist:rank", &snapshot_rank_result());

        let first = worklist_model(&app);
        assert_eq!(first.rows.len(), 1, "snapshot rows project");
        assert_eq!(first.rows[0].location, "src/deep.rs:12");

        // The memo is now populated under the snapshot-backed key, so the second
        // call resolves without touching the snapshot body again.
        let artifact_version = attack_surface_artifact_version(&app);
        let recommendations = recommendations_input(&app);
        let key = WorklistCacheKey::from_parts(
            artifact_version,
            recommendations_identity(&recommendations),
            worklist_snapshot_generation(&app, artifact_version),
        );
        assert!(
            app.workbench_cache().borrow().worklist(&key).is_some(),
            "the snapshot projection is memoized after the first frame"
        );
        assert!(
            worklist_snapshot_generation(&app, artifact_version).is_some(),
            "a snapshot backs this engagement"
        );

        // Poison the source JSON behind the stable memo key. A cache hit ignores
        // it; a re-parse would project `src/POISONED.rs:999`.
        app.domain_mut()
            .poison_worklist_snapshot_data_in_place(serde_json::json!({
                "rows": [{
                    "path": "src/POISONED.rs", "line": 999, "score": 0.1, "rank": 1,
                    "citations": []
                }],
                "rankedTotal": 1,
                "contributors": {},
                "unranked": [], "degraded": []
            }));
        // The memo key is unchanged, confirming the poison did not invalidate it.
        assert_eq!(
            worklist_snapshot_generation(&app, artifact_version),
            worklist_snapshot_generation(&app, artifact_version),
            "poisoning does not bump the generation"
        );

        let second = worklist_model(&app);
        assert_eq!(
            second, first,
            "the second frame returns the cached model, not a re-parse"
        );
        assert_eq!(
            second.rows[0].location, "src/deep.rs:12",
            "the poisoned row never surfaces — proving the memo was used, not a re-parse"
        );
    }

    /// New-1: end-to-end on the deck path. A present-but-corrupt cached
    /// `attack-surface.json` (invalid JSON ⇒ `JsonFileState::Malformed`) must
    /// drive the AttackSurface contributor Degraded with a `context:build`
    /// banner reason — never the "no map" Unavailable wording the fold would use
    /// for a genuinely absent artifact.
    #[test]
    fn malformed_cached_artifact_degrades_deck_matching_headless() {
        use kuzushi_core::V2Config;
        let temp = tempfile::tempdir().expect("tempdir");
        let run_id = "run-corrupt-surface";
        let summary = kuzushi_core::RunSummary::running(
            run_id,
            "tool",
            None,
            temp.path().display().to_string(),
        );
        kuzushi_core::write_run_summary(temp.path(), &summary).expect("write run summary");
        let run_dir = crate::ui_view_models::ui_run_dir(Some(temp.path()), run_id);
        std::fs::create_dir_all(&run_dir).expect("run dir");
        std::fs::write(run_dir.join("attack-surface.json"), "{ not valid json")
            .expect("write malformed artifact");

        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.set_shell_view(crate::app::ShellView::Home);
        app.hydrate_active_view_blocking();

        // The hydrated cache must classify the corrupt file as such, not absent.
        assert!(
            matches!(
                attack_surface_artifact_state(&app),
                AttackSurfaceArtifactState::CorruptOrUnreadable
            ),
            "a malformed cached artifact is CorruptOrUnreadable, not Absent"
        );

        let model = worklist_model(&app);
        let surface = model
            .legend
            .iter()
            .find(|entry| entry.glyph == Contributor::AttackSurface.glyph())
            .expect("attack-surface legend entry present");
        let word = surface.state_word.as_deref().unwrap_or_default();
        assert!(
            word.contains("unreadable"),
            "deck degrades a corrupt artifact: {word:?}"
        );
        assert!(
            !word.contains("no attack-surface map"),
            "must not claim absence: {word:?}"
        );
        assert!(
            model
                .degraded
                .iter()
                .any(|reason| reason.contains("unreadable")),
            "degraded: {:?}",
            model.degraded
        );
        assert!(model.empty_hint.is_none(), "{:?}", model.empty_hint);
    }

    #[test]
    fn snapshot_projection_renders_the_tool_rows_including_systems_glyphs() {
        let value = serde_json::json!({
            "rows": [{
                "path": "src/deep.rs",
                "line": 12,
                "score": 0.8,
                "rank": 1,
                "citations": [
                    {"contributor": "attackSurface", "raw": 90.0, "rawDisplay": "90/100",
                     "normalized": 0.9, "normalization": "bounded/100", "reasons": []},
                    {"contributor": "systemsHunt", "raw": 40.0, "rawDisplay": "score 40",
                     "normalized": 0.5, "normalization": "rank", "reasons": []}
                ]
            }],
            "contributors": {"attackSurface": "live", "systemsHunt": "live"},
            "unranked": [],
            "degraded": []
        });

        let model = project_snapshot(&value).expect("snapshot projects");

        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.rows[0].glyphs, "AS", "systems `S` row survives");
        assert_eq!(model.rows[0].location, "src/deep.rs:12");
        assert!(model.rows[0].summary.contains("score 40"));
    }
}
