//! When the advisory queue gets scored.
//!
//! Scoring used to wait for the first finding-open, so an ordering mode showed
//! the baseline order until the operator happened to open something and then
//! silently rearranged the list underneath them. These pin that the queue is
//! scored as soon as it exists, and that nothing is scored for a mode that
//! displays and orders nothing.

use super::*;

fn score_requests(effects: &[ShellEffect]) -> Vec<&ReviewYieldScoreApply> {
    effects
        .iter()
        .filter_map(|effect| match effect {
            ShellEffect::ScoreReviewYieldQueue(apply) => Some(apply),
            _ => None,
        })
        .collect()
}

/// Arming an ordering mode scores the queue that already hydrated, so the
/// first frame is the one the mode describes rather than the baseline.
#[test]
fn arming_an_ordering_mode_scores_the_queue_before_any_open() {
    let mut harness = harness(4);
    harness.app.config_mut().review_yield = ReviewYieldConfig {
        mode: ReviewYieldMode::WithinBand,
        model_path: Some(shadow_model_path()),
    };

    let effects = harness.app.arm_review_yield_from_config();

    let requests = score_requests(&effects);
    assert_eq!(requests.len(), 1, "arming must score the loaded queue");
    assert_eq!(requests[0].queue.len(), 4);
    assert_eq!(requests[0].feature_cutoff_seq, 12_000);
    assert!(
        session_starts(&effects).is_empty(),
        "scoring is not an observation of review"
    );

    EffectRuntime::execute(&mut harness.app, effects);
    assert!(
        harness.app.within_band_scores().is_some(),
        "the queue must be ordered without the operator opening anything"
    );
}

/// The learn objective is armed the same way: nothing waits for an open.
#[test]
fn arming_learn_mode_scores_the_queue_before_any_open() {
    let mut harness = harness(4);
    harness.app.config_mut().review_yield = ReviewYieldConfig {
        mode: ReviewYieldMode::Learn,
        model_path: Some(shadow_model_path()),
    };

    let effects = harness.app.arm_review_yield_from_config();

    assert_eq!(score_requests(&effects).len(), 1);
}

/// `off` does no work at all, and `shadow` neither orders nor explains, so
/// neither has a queue to keep current.
#[test]
fn modes_that_show_no_signal_request_no_scoring() {
    for mode in [ReviewYieldMode::Off, ReviewYieldMode::Shadow] {
        let mut harness = harness(4);
        harness.app.config_mut().review_yield = ReviewYieldConfig {
            mode,
            model_path: Some(shadow_model_path()),
        };

        let effects = harness.app.arm_review_yield_from_config();

        assert!(
            score_requests(&effects).is_empty(),
            "{mode:?} scored a queue"
        );
    }
}

/// Re-running the request against an unchanged generation is a no-op: the
/// memoized scores already describe this queue, so a refresh that changed
/// nothing costs nothing.
#[test]
fn scoring_the_same_generation_twice_does_no_second_pass() {
    let mut harness = harness(4);
    harness.app.config_mut().review_yield = ReviewYieldConfig {
        mode: ReviewYieldMode::WithinBand,
        model_path: Some(shadow_model_path()),
    };
    let first = harness.app.arm_review_yield_from_config();
    assert_eq!(score_requests(&first).len(), 1);
    EffectRuntime::execute(&mut harness.app, first);

    let second = harness.app.review_yield_queue_scoring_effects();

    assert!(score_requests(&second).is_empty());
}

/// A findings reload — the shape a completed scan takes — re-requests scoring
/// for the generation it just loaded.
#[test]
fn a_findings_reload_requests_scoring_for_the_new_generation() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    store
        .insert_finding("run-1", &queue_finding(0, Severity::High))
        .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(workspace.root().to_path_buf()));
    arm_from_config(&mut app, ReviewYieldMode::WithinBand, shadow_model_path());

    let effects = app.refresh_findings_effect(FindingsRefresh {
        announce: false,
        filter: None,
    });

    assert_eq!(score_requests(&effects).len(), 1);
    assert_eq!(app.findings().len(), 1);
}

/// An unarmed shell reloads findings exactly as it did before this feature.
#[test]
fn a_findings_reload_requests_no_scoring_when_the_mode_is_off() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-1", workspace.root(), "completed")
        .unwrap();
    store
        .insert_finding("run-1", &queue_finding(0, Severity::High))
        .unwrap();
    let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
    app.set_target(Some(workspace.root().to_path_buf()));

    let effects = app.refresh_findings_effect(FindingsRefresh {
        announce: false,
        filter: None,
    });

    assert!(effects.is_empty());
}
