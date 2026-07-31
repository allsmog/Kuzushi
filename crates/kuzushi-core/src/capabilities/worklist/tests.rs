use super::domain::{Contributor, ContributorState};
use super::fold::{rank, RecommendationsStatus, WorklistInputs};
use crate::capabilities::scan_recommender::{ReasonTag, ScanRecommendation};
use crate::capabilities::systems_hunt::RankedSystemsSurface;
use crate::modules::WorkflowPhase;
use crate::workspace::{AttackSurface, AttackSurfaceKind, AttackSurfaceRisk};
use std::collections::BTreeMap;

fn surface(path: &str, line: u32, score: u16, reasons: &[&str]) -> AttackSurface {
    AttackSurface {
        id: format!("{path}:{line}"),
        kind: AttackSurfaceKind::HttpRoute,
        path: path.to_string(),
        line: Some(line),
        language: "rust".to_string(),
        framework: None,
        title: "t".to_string(),
        evidence: "e".to_string(),
        method: None,
        route: None,
        boundary: None,
        risk: AttackSurfaceRisk {
            rank: 0,
            score,
            tier: "high".to_string(),
            reasons: reasons.iter().map(|r| r.to_string()).collect(),
        },
        metadata: serde_json::Value::Null,
    }
}

fn systems_surface(path: &str, line: u32, score: i64) -> RankedSystemsSurface {
    RankedSystemsSurface {
        id: format!("sys:{path}:{line}"),
        file_path: path.to_string(),
        start_line: line,
        display_name: path.to_string(),
        kind: "systems".to_string(),
        score,
        domains: vec!["memory".to_string()],
        reasons: vec!["unsafe block".to_string()],
        attacker_controlled_fields: vec![],
        hardening_signals: vec![],
        evidence: vec![],
    }
}

fn recommendation(scope_id: &str, score: f32) -> ScanRecommendation {
    ScanRecommendation {
        scope_id: scope_id.to_string(),
        phase: WorkflowPhase::Scan,
        reason: ReasonTag::SinkGap,
        score,
        evidence: "6 surface-bearing files, 0 findings".to_string(),
        suggested_mode: Some("sink-gap".to_string()),
    }
}

fn root_scope() -> BTreeMap<String, String> {
    BTreeMap::from([(".".to_string(), ".".to_string())])
}

fn inputs<'a>(
    surfaces: &'a [AttackSurface],
    recommendations: &'a [ScanRecommendation],
    scope_paths: &'a BTreeMap<String, String>,
) -> WorklistInputs<'a> {
    WorklistInputs {
        surfaces,
        recommendations,
        recommendations_status: RecommendationsStatus::Available,
        scope_paths,
        systems: None,
        prefilter: None,
        fan_in: None,
        limit: 20,
    }
}

#[test]
fn surface_only_fold_ranks_by_risk_score() {
    let surfaces = vec![
        surface("src/low.rs", 1, 50, &["low"]),
        surface("src/high.rs", 2, 92, &["auth boundary"]),
    ];
    let scopes = root_scope();
    let worklist = rank(&inputs(&surfaces, &[], &scopes));

    assert_eq!(worklist.rows.len(), 2);
    assert_eq!(worklist.rows[0].rank, 1);
    assert_eq!(worklist.rows[0].path, "src/high.rs");
    let citation = &worklist.rows[0].citations[0];
    assert_eq!(citation.contributor, Contributor::AttackSurface);
    assert_eq!(citation.raw, 92.0);
    assert_eq!(citation.raw_display, "92/100");
}

#[test]
fn coverage_recommendation_annotates_but_never_creates_rows() {
    // A recommendation for the root scope, but NO surface files anywhere.
    let recs = vec![recommendation(".", 0.9)];
    let scopes = root_scope();
    let worklist = rank(&inputs(&[], &recs, &scopes));

    assert!(worklist.rows.is_empty());
    assert_eq!(
        worklist.contributors[&Contributor::ScanCoverage],
        ContributorState::Live
    );
}

#[test]
fn coverage_annotates_existing_surface_rows() {
    let surfaces = vec![surface("src/a.rs", 1, 80, &["route"])];
    let recs = vec![recommendation(".", 0.9)];
    let scopes = root_scope();
    let worklist = rank(&inputs(&surfaces, &recs, &scopes));

    let contributors: Vec<Contributor> = worklist.rows[0]
        .citations
        .iter()
        .map(|c| c.contributor)
        .collect();
    assert!(contributors.contains(&Contributor::AttackSurface));
    assert!(contributors.contains(&Contributor::ScanCoverage));
}

#[test]
fn prefilter_history_absent_is_not_requested_never_a_false_history_claim() {
    // Prefilter history is a Phase-A non-feature: its absence is `NotRequested`,
    // never a fabricated "no history at this revision" fact nobody checked, and
    // it never fabricates a zeroed citation on a row.
    let surfaces = vec![surface("src/a.rs", 1, 80, &["route"])];
    let scopes = root_scope();
    let worklist = rank(&inputs(&surfaces, &[], &scopes));

    assert_eq!(
        worklist.contributors[&Contributor::PrefilterHistory],
        ContributorState::NotRequested
    );
    for row in &worklist.rows {
        assert!(row
            .citations
            .iter()
            .all(|c| c.contributor != Contributor::PrefilterHistory));
    }
}

#[test]
fn systems_not_requested_is_distinct_from_unavailable() {
    // An empty surface set makes AttackSurface genuinely `Unavailable`, which
    // stays distinct from the `NotRequested` systems contributor.
    let scopes = root_scope();
    let worklist = rank(&inputs(&[], &[], &scopes));

    assert_eq!(
        worklist.contributors[&Contributor::SystemsHunt],
        ContributorState::NotRequested
    );
    assert!(matches!(
        worklist.contributors[&Contributor::AttackSurface],
        ContributorState::Unavailable { .. }
    ));
    assert_ne!(
        worklist.contributors[&Contributor::SystemsHunt],
        worklist.contributors[&Contributor::AttackSurface]
    );
}

#[test]
fn systems_signal_produces_its_own_row() {
    let systems = vec![systems_surface("src/sys.rs", 10, 40)];
    let scopes = root_scope();
    let worklist = rank(&WorklistInputs {
        systems: Some(&systems),
        ..inputs(&[], &[], &scopes)
    });

    assert_eq!(worklist.rows.len(), 1);
    assert_eq!(worklist.rows[0].path, "src/sys.rs");
    assert_eq!(
        worklist.rows[0].citations[0].contributor,
        Contributor::SystemsHunt
    );
    assert_eq!(
        worklist.contributors[&Contributor::SystemsHunt],
        ContributorState::Live
    );
}

#[test]
fn zero_signal_files_are_reported_unranked() {
    // A surface with risk score 0 has no live signal.
    let surfaces = vec![surface("src/quiet.rs", 1, 0, &[])];
    let scopes = root_scope();
    let worklist = rank(&inputs(&surfaces, &[], &scopes));

    assert!(worklist.rows.is_empty());
    assert_eq!(worklist.unranked.len(), 1);
    assert_eq!(worklist.unranked[0].path, "src/quiet.rs");
    assert!(!worklist.unranked[0].reason.is_empty());
}

#[test]
fn ranking_is_deterministic_and_total() {
    // Two files with identical scores tie-break by path then line.
    let surfaces = vec![
        surface("src/b.rs", 5, 70, &["x"]),
        surface("src/a.rs", 9, 70, &["y"]),
    ];
    let scopes = root_scope();
    let first = rank(&inputs(&surfaces, &[], &scopes));
    let second = rank(&inputs(&surfaces, &[], &scopes));

    assert_eq!(first.rows, second.rows);
    assert_eq!(first.rows[0].path, "src/a.rs");
    assert_eq!(first.rows[1].path, "src/b.rs");
    assert_eq!(first.rows[0].rank, 1);
    assert_eq!(first.rows[1].rank, 2);
}

#[test]
fn normalization_preserves_raw_values() {
    let surfaces = vec![surface("src/a.rs", 1, 92, &["auth"])];
    let scopes = root_scope();
    let worklist = rank(&inputs(&surfaces, &[], &scopes));

    for row in &worklist.rows {
        for citation in &row.citations {
            assert_eq!(citation.raw_display, "92/100");
            assert_eq!(citation.raw, 92.0);
            assert!((0.0..=1.0).contains(&citation.normalized));
        }
    }
}

#[test]
fn degraded_reason_surfaces_and_ranks_stay_contiguous() {
    // An empty fan-in map means "requested but the graph was unavailable".
    let surfaces = vec![
        surface("src/a.rs", 1, 90, &["a"]),
        surface("src/b.rs", 2, 60, &["b"]),
    ];
    let empty_fan_in: BTreeMap<String, usize> = BTreeMap::new();
    let scopes = root_scope();
    let worklist = rank(&WorklistInputs {
        fan_in: Some(&empty_fan_in),
        ..inputs(&surfaces, &[], &scopes)
    });

    assert!(matches!(
        worklist.contributors[&Contributor::CallGraphFanIn],
        ContributorState::Degraded { .. }
    ));
    assert!(worklist.degraded.iter().any(|r| r == "no cpg graph"));
    let ranks: Vec<usize> = worklist.rows.iter().map(|r| r.rank).collect();
    assert_eq!(ranks, vec![1, 2]);
}

#[test]
fn surface_and_systems_signals_on_one_file_fold_into_a_single_row() {
    // The attack-surface signal keys at its `line`, the systems signal at its
    // `start_line`; those rarely coincide. Keying rows by FILE PATH folds both
    // into ONE row with combined glyphs instead of two double-counted rows.
    let surfaces = vec![surface("src/hot.rs", 12, 90, &["route"])];
    let systems = vec![systems_surface("src/hot.rs", 48, 40)];
    let scopes = root_scope();
    let worklist = rank(&WorklistInputs {
        systems: Some(&systems),
        ..inputs(&surfaces, &[], &scopes)
    });

    assert_eq!(worklist.rows.len(), 1, "one file must yield one row");
    let row = &worklist.rows[0];
    assert_eq!(row.path, "src/hot.rs");
    let glyphs: String = row.citations.iter().map(|c| c.contributor.glyph()).collect();
    assert_eq!(glyphs, "AS", "combined attack-surface + systems glyphs");
    // The representative line prefers the attack-surface citation's line.
    assert_eq!(row.line, Some(12));
}

#[test]
fn representative_line_falls_back_to_min_when_no_surface_line() {
    // No attack-surface citation carries a line, so the row uses the min line
    // among the (systems) citations.
    let systems = vec![
        systems_surface("src/sys.rs", 90, 40),
        systems_surface("src/sys.rs", 30, 20),
    ];
    let scopes = root_scope();
    let worklist = rank(&WorklistInputs {
        systems: Some(&systems),
        ..inputs(&[], &[], &scopes)
    });

    assert_eq!(worklist.rows.len(), 1);
    assert_eq!(worklist.rows[0].line, Some(30));
}

#[test]
fn coverage_state_is_unavailable_when_recommendations_not_loaded() {
    let surfaces = vec![surface("src/a.rs", 1, 80, &["route"])];
    let scopes = root_scope();
    let worklist = rank(&WorklistInputs {
        recommendations_status: RecommendationsStatus::NotLoaded,
        ..inputs(&surfaces, &[], &scopes)
    });

    assert!(matches!(
        worklist.contributors[&Contributor::ScanCoverage],
        ContributorState::Unavailable { .. }
    ));
}

#[test]
fn coverage_state_is_degraded_when_recommendation_load_failed() {
    let surfaces = vec![surface("src/a.rs", 1, 80, &["route"])];
    let scopes = root_scope();
    let worklist = rank(&WorklistInputs {
        recommendations_status: RecommendationsStatus::Degraded(
            "scan coverage unavailable: ledger locked".to_string(),
        ),
        ..inputs(&surfaces, &[], &scopes)
    });

    assert!(matches!(
        worklist.contributors[&Contributor::ScanCoverage],
        ContributorState::Degraded { .. }
    ));
    assert!(worklist
        .degraded
        .iter()
        .any(|reason| reason.contains("scan coverage unavailable")));
}

#[test]
fn limit_truncates_rows_without_dropping_contributor_states() {
    let surfaces = vec![
        surface("src/a.rs", 1, 90, &["a"]),
        surface("src/b.rs", 2, 80, &["b"]),
        surface("src/c.rs", 3, 70, &["c"]),
    ];
    let scopes = root_scope();
    let worklist = rank(&WorklistInputs {
        limit: 2,
        ..inputs(&surfaces, &[], &scopes)
    });

    assert_eq!(worklist.rows.len(), 2);
    // The row list is capped, but the reported ranked population is the true
    // pre-cap count so callers never understate it.
    assert_eq!(worklist.ranked_total, 3);
    assert_eq!(worklist.contributors.len(), 6);
}

// --- Item C: the gather layer distinguishes an absent snapshot from a
// persisted-but-unreadable attack-surface map. ------------------------------

use super::gather::{rank_worklist_for_target, WorklistOptions};
use std::path::Path;

fn read_safe_options() -> WorklistOptions {
    WorklistOptions {
        limit: 25,
        deep: false,
        include_fan_in: false,
    }
}

fn write_context_snapshot(root: &Path, body: &str) {
    std::fs::create_dir_all(crate::workspace::workspace_state_root(root)).unwrap();
    std::fs::write(crate::context::context_snapshot_path(root), body).unwrap();
}

fn attack_surface_state(worklist: &crate::capabilities::worklist::Worklist) -> ContributorState {
    worklist
        .contributors
        .get(&Contributor::AttackSurface)
        .cloned()
        .expect("attack-surface contributor present")
}

#[test]
fn unreadable_snapshot_degrades_attack_surface_instead_of_claiming_no_map() {
    // A persisted context snapshot that carries no readable attack-surface map
    // is a `context:build` recovery hint, never the honest "no map — run
    // context:build" Unavailable wording, which would imply nothing was built.
    let temp = tempfile::tempdir().unwrap();
    write_context_snapshot(temp.path(), "{ this is not valid json");

    let worklist =
        rank_worklist_for_target(temp.path(), &read_safe_options(), None).unwrap();

    match attack_surface_state(&worklist) {
        ContributorState::Degraded { reason } => {
            assert!(reason.contains("context snapshot present"), "{reason}");
            assert!(
                worklist.degraded.iter().any(|r| r == &reason),
                "degraded: {:?}",
                worklist.degraded
            );
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
}

#[test]
fn summary_only_snapshot_degrades_with_a_summary_recovery_reason() {
    // A well-formed snapshot whose surface records are malformed recovers a
    // summary-only map (empty surfaces). The snapshot exists, so this is a
    // Degraded "recovered summary-only" state, not Unavailable.
    let temp = tempfile::tempdir().unwrap();
    write_context_snapshot(
        temp.path(),
        r#"{"attackSurfaceMap":{
            "rootName":"demo",
            "surfaces":[{"kind":"http_route","oops":true}],
            "summary":{"total":2,"byKind":{},"byFile":{"src/a.rs":2},
                       "highRisk":0,"maxRiskScore":0,"byRiskTier":{}}
        }}"#,
    );

    let worklist =
        rank_worklist_for_target(temp.path(), &read_safe_options(), None).unwrap();

    match attack_surface_state(&worklist) {
        ContributorState::Degraded { reason } => {
            assert!(reason.contains("summary-only"), "{reason}");
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
}

#[test]
fn full_map_with_zero_surfaces_stays_unavailable_never_degraded() {
    // C-1: a fully-parseable attack-surface map that honestly carries zero
    // surfaces (a benign/tiny repo) is NOT degraded. The snapshot exists, but
    // the records are readable and simply empty, so the fold's
    // `Unavailable{"no attack-surface map — run context:build"}` state stands
    // and nothing is pushed onto `degraded`. This makes core match the TUI deck
    // (`parseable_empty_artifact_keeps_attack_surface_unavailable`).
    let temp = tempfile::tempdir().unwrap();
    write_context_snapshot(
        temp.path(),
        r#"{"attackSurfaceMap":{
            "rootName":"demo",
            "surfaces":[],
            "summary":{"total":0,"byKind":{},"byFile":{},
                       "highRisk":0,"maxRiskScore":0,"byRiskTier":{}}
        }}"#,
    );

    let worklist =
        rank_worklist_for_target(temp.path(), &read_safe_options(), None).unwrap();

    match attack_surface_state(&worklist) {
        ContributorState::Unavailable { reason } => {
            assert!(reason.contains("no attack-surface map"), "{reason}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    assert!(
        worklist.degraded.is_empty(),
        "a benign empty map is not degraded: {:?}",
        worklist.degraded
    );
}

#[test]
fn absent_snapshot_keeps_unavailable_run_context_build_wording() {
    // No snapshot at all is the genuine "no map" state — the fold's
    // Unavailable/"run context:build" wording must be preserved unchanged.
    let temp = tempfile::tempdir().unwrap();

    let worklist =
        rank_worklist_for_target(temp.path(), &read_safe_options(), None).unwrap();

    match attack_surface_state(&worklist) {
        ContributorState::Unavailable { reason } => {
            assert!(reason.contains("no attack-surface map"), "{reason}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    assert!(
        worklist.degraded.is_empty(),
        "no override reason for a genuinely absent snapshot: {:?}",
        worklist.degraded
    );
}
