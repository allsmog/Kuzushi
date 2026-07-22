use super::*;
use kuzushi_core::WorkflowPhase;
use ratatui::layout::Rect;

mod assertions;
mod expectations;
mod fixture_support;
mod fixtures;

use assertions::{assert_attention_owner, assert_fixture_surfaces, assert_rectangles};
use expectations::{expected_density, expected_primary, expected_visible_count, surface_ids};
use fixtures::fixture_body;

const CANONICAL_SIZES: [(u16, u16); 5] = [(40, 12), (60, 20), (80, 24), (120, 36), (160, 48)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SemanticFixture {
    Empty,
    Sparse,
    Partial,
    Dense,
    Stale,
    Blocked,
    ResultReady,
    Guided,
    Background,
}

impl SemanticFixture {
    const ALL: [Self; 9] = [
        Self::Empty,
        Self::Sparse,
        Self::Partial,
        Self::Dense,
        Self::Stale,
        Self::Blocked,
        Self::ResultReady,
        Self::Guided,
        Self::Background,
    ];

    const fn richness(self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Sparse | Self::Blocked => 1,
            Self::Partial | Self::Background => 2,
            Self::Dense | Self::Stale | Self::ResultReady | Self::Guided => 3,
        }
    }

    const fn attention(self) -> AttentionMode {
        match self {
            Self::ResultReady => AttentionMode::ResultReady,
            Self::Guided => AttentionMode::GuidedQuestion,
            _ => AttentionMode::Normal,
        }
    }
}

#[test]
fn phase_presentation_matrix_covers_every_phase_state_and_size() {
    assert_matrix_dimensions();
    for phase in WorkflowPhase::ORDER.iter().copied() {
        for state in SemanticFixture::ALL {
            assert_phase_state_matrix(phase, state);
        }
    }
}

fn assert_matrix_dimensions() {
    assert_eq!(
        WorkflowPhase::ORDER.len(),
        5,
        "canonical phase count drifted"
    );
    assert_eq!(
        SemanticFixture::ALL.len(),
        9,
        "semantic fixture count drifted"
    );
    assert_eq!(CANONICAL_SIZES.len(), 5, "canonical size count drifted");
}

fn assert_phase_state_matrix(phase: WorkflowPhase, state: SemanticFixture) {
    let body = fixture_body(phase, state);
    assert_fixture_surfaces(phase, state, &body);
    for (width, height) in CANONICAL_SIZES {
        assert_matrix_cell(phase, state, &body, Rect::new(7, 5, width, height));
    }
}

fn assert_matrix_cell(
    phase: WorkflowPhase,
    state: SemanticFixture,
    body: &PhaseCockpitBody,
    area: Rect,
) {
    let cell = cell_label(phase, state, area.width, area.height);
    let plan = phase_presentation_plan(body, area, None, None, state.attention());
    let specs = phase_surface_specs(body);
    let density = expected_density(specs.len(), area, state.attention());
    let visible_count = expected_visible_count(specs.len(), density);

    assert_eq!(plan.density, density, "{cell}: density");
    assert_eq!(
        surface_ids(&plan.available_surfaces),
        surface_ids(&specs),
        "{cell}: available focused-deck surfaces"
    );
    assert_eq!(
        plan.primary,
        expected_primary(phase, state),
        "{cell}: primary"
    );
    let multi_surface = matches!(
        plan.density,
        LayoutDensity::Dense | LayoutDensity::MasterDetail
    );
    let expected_visible = match phase {
        // Map adopted the canvas+drawer composition: the data-flow canvas
        // dominates and the readiness action card rides the drawer.
        WorkflowPhase::Map if multi_surface => {
            vec![PhaseSurfaceId::MapDfd, PhaseSurfaceId::MapReadiness]
        }
        // Prove adopted the focus+action-menu composition when a finding is
        // selected: one triage body plus the Choose-Next-Action menu.
        WorkflowPhase::Prove
            if multi_surface
                && specs
                    .iter()
                    .any(|spec| spec.id == PhaseSurfaceId::ProveStatus) =>
        {
            vec![PhaseSurfaceId::ProveStatus, PhaseSurfaceId::ProveNextAction]
        }
        // Fix adopted the plan/diff/verification triptych once anything is
        // staged; the third column trades for the diff below 120 columns.
        WorkflowPhase::Fix
            if multi_surface
                && specs
                    .iter()
                    .any(|spec| spec.id == PhaseSurfaceId::FixCandidate) =>
        {
            if area.width >= 120 {
                vec![
                    PhaseSurfaceId::FixRemediation,
                    PhaseSurfaceId::FixCandidate,
                    PhaseSurfaceId::FixVerification,
                ]
            } else {
                vec![PhaseSurfaceId::FixRemediation, PhaseSurfaceId::FixCandidate]
            }
        }
        _ => surface_ids(&specs[..visible_count]),
    };
    assert_eq!(
        surface_ids(&plan.surfaces),
        expected_visible,
        "{cell}: visible surface order"
    );
    assert!(plan.surfaces.len() <= 3, "{cell}: more than three surfaces");
    assert_rectangles(&plan, area, &cell);
    assert_attention_owner(&plan, state.attention(), &cell);
}

#[test]
fn phase_presentation_matrix_restores_hidden_focus_when_space_returns() {
    for phase in WorkflowPhase::ORDER.iter().copied() {
        for state in SemanticFixture::ALL {
            assert_focus_restoration_for_state(phase, state);
        }
    }
}

fn assert_focus_restoration_for_state(phase: WorkflowPhase, state: SemanticFixture) {
    if state.attention() != AttentionMode::Normal {
        return;
    }
    let body = fixture_body(phase, state);
    let probe = phase_presentation_plan(
        &body,
        Rect::new(0, 0, 160, 48),
        None,
        None,
        AttentionMode::Normal,
    );
    let Some(secondary) = probe.surfaces.get(1).map(|surface| surface.id) else {
        return;
    };
    let focus = secondary;
    let compact = phase_presentation_plan(
        &body,
        Rect::new(0, 0, 40, 12),
        Some(focus),
        None,
        AttentionMode::Normal,
    );
    let wide = phase_presentation_plan(
        &body,
        Rect::new(0, 0, 160, 48),
        Some(focus),
        None,
        AttentionMode::Normal,
    );
    let cell = format!("phase={phase:?} state={state:?}");

    if !compact.surfaces.iter().any(|surface| surface.id == focus) {
        assert_eq!(
            compact.effective_focus, compact.primary,
            "{cell}: compact fallback"
        );
    }
    assert_eq!(
        wide.effective_focus, secondary,
        "{cell}: stored focus was not restored"
    );
    assert_eq!(wide.effective_focus, focus, "{cell}: restored slot");
}

#[test]
fn phase_presentation_matrix_restores_focus_after_attention_releases() {
    for phase in WorkflowPhase::ORDER.iter().copied() {
        for attention in [AttentionMode::GuidedQuestion, AttentionMode::ResultReady] {
            assert_attention_release_restores_focus(phase, attention);
        }
    }
}

fn assert_attention_release_restores_focus(phase: WorkflowPhase, attention: AttentionMode) {
    let body = fixture_body(phase, SemanticFixture::Dense);
    let area = Rect::new(0, 0, 160, 48);
    let probe = phase_presentation_plan(&body, area, None, None, AttentionMode::Normal);
    let Some(secondary) = probe.surfaces.get(1).map(|surface| surface.id) else {
        return;
    };
    let focus = Some(secondary);
    let owned = phase_presentation_plan(&body, area, focus, None, attention);
    let released = phase_presentation_plan(&body, area, focus, None, AttentionMode::Normal);
    let cell = format!("phase={phase:?} attention={attention:?}");

    assert_eq!(
        owned.effective_focus, owned.primary,
        "{cell}: attention owner"
    );
    assert_eq!(
        released.effective_focus, secondary,
        "{cell}: focus after attention release"
    );
}

fn cell_label(phase: WorkflowPhase, state: SemanticFixture, width: u16, height: u16) -> String {
    format!("phase={phase:?} state={state:?} size={width}x{height}")
}

/// The Next-Investigation-Plan drawer joins the Review composition only when
/// the recommender has concrete passes, sizes itself by how many, and sheds
/// first on short terminals.
#[test]
fn review_next_plan_drawer_appears_sizes_and_sheds_with_the_recommendations() {
    let ready_row = |scope: &str| NextScanRow {
        scope: scope.to_string(),
        phase: "scan".to_string(),
        reason: "changed".to_string(),
        evidence: "files changed".to_string(),
    };
    let mut body = fixture_body(WorkflowPhase::Review, SemanticFixture::Dense);
    let PhaseCockpitBody::Review(model) = &mut body else {
        panic!("review fixture body");
    };
    model.next_plan = NextScansState::Ready(vec![ready_row("root")]);
    let wide = Rect::new(0, 0, 160, 48);

    let plan = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(plan
        .surfaces
        .iter()
        .any(|surface| surface.id == PhaseSurfaceId::ReviewNextPlan));
    assert_eq!(
        plan.composition.role_of(PhaseSurfaceId::ReviewNextPlan),
        SurfaceRole::Drawer
    );

    let short = phase_presentation_plan(
        &body,
        Rect::new(0, 0, 160, 9),
        None,
        None,
        AttentionMode::Normal,
    );
    assert!(!short
        .surfaces
        .iter()
        .any(|surface| surface.id == PhaseSurfaceId::ReviewNextPlan));

    let PhaseCockpitBody::Review(model) = &mut body else {
        panic!("review fixture body");
    };
    model.next_plan = NextScansState::Ready(vec![
        ready_row("root"),
        ready_row("web/app"),
        ready_row("services/api"),
    ]);
    let expanded = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    let compact_rect = plan
        .surface(PhaseSurfaceId::ReviewNextPlan)
        .expect("compact drawer")
        .rect;
    let expanded_rect = expanded
        .surface(PhaseSurfaceId::ReviewNextPlan)
        .expect("expanded drawer")
        .rect;
    assert!(expanded_rect.height > compact_rect.height);

    let PhaseCockpitBody::Review(model) = &mut body else {
        panic!("review fixture body");
    };
    model.next_plan = NextScansState::Pending;
    let pending = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(!pending
        .surfaces
        .iter()
        .any(|surface| surface.id == PhaseSurfaceId::ReviewNextPlan));
}

/// While a scan run is in flight the Scan page becomes the operational
/// dashboard: scope | engines | delta over a receipt log strip. Small
/// terminals shed the strip first, then degrade to the center column.
#[test]
fn live_scan_composes_the_operational_dashboard_and_degrades_to_center() {
    let mut body = fixture_body(WorkflowPhase::Scan, SemanticFixture::Dense);
    let PhaseCockpitBody::Scan(model) = &mut body else {
        panic!("scan fixture body");
    };
    model.live = Some(LiveScanModel {
        run_id: Some("run-live".to_string()),
        stage: "scanning".to_string(),
        findings: 2,
    });

    let wide = phase_presentation_plan(
        &body,
        Rect::new(0, 0, 160, 48),
        None,
        None,
        AttentionMode::Normal,
    );
    let ids = wide
        .surfaces
        .iter()
        .map(|surface| surface.id)
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            PhaseSurfaceId::ScanScope,
            PhaseSurfaceId::ScanEngines,
            PhaseSurfaceId::ScanDelta,
            PhaseSurfaceId::ScanReceipt,
        ]
    );

    let short = phase_presentation_plan(
        &body,
        Rect::new(0, 0, 160, 12),
        None,
        None,
        AttentionMode::Normal,
    );
    assert!(!short
        .surfaces
        .iter()
        .any(|surface| surface.id == PhaseSurfaceId::ScanReceipt));

    let PhaseCockpitBody::Scan(model) = &mut body else {
        panic!("scan fixture body");
    };
    model.live = None;
    let resting = phase_presentation_plan(
        &body,
        Rect::new(0, 0, 160, 48),
        None,
        None,
        AttentionMode::Normal,
    );
    assert!(matches!(resting.composition, Composition::Columns(_)));
}
