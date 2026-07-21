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
    let expected_visible = if matches!(phase, WorkflowPhase::Map)
        && matches!(
            plan.density,
            LayoutDensity::Dense | LayoutDensity::MasterDetail
        ) {
        // Map adopted the canvas+drawer composition: the data-flow canvas
        // dominates and the readiness action card rides the drawer.
        vec![PhaseSurfaceId::MapDfd, PhaseSurfaceId::MapReadiness]
    } else {
        surface_ids(&specs[..visible_count])
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
