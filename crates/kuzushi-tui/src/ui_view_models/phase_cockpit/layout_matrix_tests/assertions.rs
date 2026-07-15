use super::super::*;
use super::{expectations::expected_surface_ids, SemanticFixture};
use crate::ui_view_models::phase_cockpit::layout::PhaseSurfaceSpec;
use kuzushi_core::WorkflowPhase;
use ratatui::layout::Rect;

pub(super) fn assert_fixture_surfaces(
    phase: WorkflowPhase,
    state: SemanticFixture,
    body: &PhaseCockpitBody,
) {
    let specs = phase_surface_specs(body);
    let cell = format!("phase={phase:?} state={state:?} fixture");
    let actual = specs.iter().map(|spec| spec.id).collect::<Vec<_>>();
    assert_eq!(
        actual,
        expected_surface_ids(phase, state.richness()),
        "{cell}: populated and missing semantic surfaces"
    );
    assert_stale_proof_receipt(phase, state, &specs, &cell);
    assert_empty_primary(state, &specs, &cell);
    assert_blocked_primary(phase, state, &specs, &cell);
}

fn assert_stale_proof_receipt(
    phase: WorkflowPhase,
    state: SemanticFixture,
    specs: &[PhaseSurfaceSpec],
    cell: &str,
) {
    if phase != WorkflowPhase::Prove || state != SemanticFixture::Stale {
        return;
    }
    let receipt = specs
        .iter()
        .find(|spec| spec.id == PhaseSurfaceId::ProveReceipt);
    assert_eq!(
        receipt.map(|spec| spec.state),
        Some(SurfaceState::Stale),
        "{cell}: stale proof receipt"
    );
}

fn assert_empty_primary(state: SemanticFixture, specs: &[PhaseSurfaceSpec], cell: &str) {
    if state == SemanticFixture::Empty {
        assert_eq!(
            specs[0].state,
            SurfaceState::Missing,
            "{cell}: empty primary surface state"
        );
    }
}

fn assert_blocked_primary(
    phase: WorkflowPhase,
    state: SemanticFixture,
    specs: &[PhaseSurfaceSpec],
    cell: &str,
) {
    let can_block = matches!(
        phase,
        WorkflowPhase::Map | WorkflowPhase::Scan | WorkflowPhase::Fix
    );
    if state == SemanticFixture::Blocked && can_block {
        assert_eq!(
            specs[0].state,
            SurfaceState::Blocked,
            "{cell}: blocked primary surface state"
        );
    }
}

pub(super) fn assert_attention_owner(
    plan: &PhasePresentationPlan,
    attention: AttentionMode,
    cell: &str,
) {
    if attention == AttentionMode::Normal {
        assert_ne!(
            plan.density,
            LayoutDensity::Guided,
            "{cell}: false attention owner"
        );
        return;
    }
    assert_eq!(
        plan.density,
        LayoutDensity::Guided,
        "{cell}: attention density"
    );
    assert_eq!(plan.surfaces.len(), 1, "{cell}: attention owner count");
    assert_eq!(
        plan.surfaces[0].id, plan.primary,
        "{cell}: attention owner identity"
    );
    assert_eq!(
        plan.effective_focus, plan.primary,
        "{cell}: attention focus"
    );
}

pub(super) fn assert_rectangles(plan: &PhasePresentationPlan, area: Rect, cell: &str) {
    for surface in &plan.surfaces {
        assert_nonempty_bounded(surface, area, cell);
    }
    for (index, left) in plan.surfaces.iter().enumerate() {
        for right in plan.surfaces.iter().skip(index + 1) {
            assert!(
                !rectangles_overlap(left.rect, right.rect),
                "{cell}: {:?} overlaps {:?}",
                left.id,
                right.id
            );
        }
    }
}

fn assert_nonempty_bounded(surface: &PlannedPhaseSurface, area: Rect, cell: &str) {
    let rect = surface.rect;
    assert!(
        rect.width > 0 && rect.height > 0,
        "{cell}: empty {:?} rect",
        surface.id
    );
    let bounded = rect.x >= area.x
        && rect.y >= area.y
        && rect.right() <= area.right()
        && rect.bottom() <= area.bottom();
    assert!(
        bounded,
        "{cell}: out-of-bounds {:?} rect {:?}",
        surface.id, rect
    );
}

fn rectangles_overlap(left: Rect, right: Rect) -> bool {
    left.x < right.right()
        && right.x < left.right()
        && left.y < right.bottom()
        && right.y < left.bottom()
}
