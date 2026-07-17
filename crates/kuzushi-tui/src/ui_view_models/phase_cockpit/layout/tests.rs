use super::*;

fn test_spec(id: PhaseSurfaceId, slot: WorkbenchPane) -> PhaseSurfaceSpec {
    PhaseSurfaceSpec {
        id,
        legacy_slot: slot,
        state: SurfaceState::Available,
        interaction: SurfaceInteraction::Scrollable,
    }
}

fn test_specs() -> Vec<PhaseSurfaceSpec> {
    vec![
        test_spec(PhaseSurfaceId::FixRemediation, WorkbenchPane::Findings),
        test_spec(PhaseSurfaceId::FixCandidate, WorkbenchPane::Source),
        test_spec(PhaseSurfaceId::FixAttackTree, WorkbenchPane::Center),
        test_spec(PhaseSurfaceId::FixDfd, WorkbenchPane::Details),
    ]
}

#[test]
fn phase_presentation_plan_caps_automatic_dense_at_three() {
    let specs = test_specs();
    let (density, visible) = automatic_specs(&specs, Rect::new(0, 0, 160, 48));
    assert_eq!(density, LayoutDensity::Dense);
    assert_eq!(visible.len(), 3);
    assert_eq!(visible[0].id, PhaseSurfaceId::FixRemediation);
}

#[test]
fn phase_presentation_plan_uses_visible_fallback_without_mutating_stored_focus() {
    let specs = test_specs();
    let (_, compact) = automatic_specs(&specs, Rect::new(0, 0, 40, 12));
    let compact = compact
        .into_iter()
        .map(|spec| planned_surface(*spec, Rect::new(0, 0, 40, 12)))
        .collect::<Vec<_>>();
    assert_eq!(
        effective_focus(&compact, Some(WorkbenchPane::Details), specs[0].id),
        PhaseSurfaceId::FixRemediation
    );
    let (_, wide) = automatic_specs(&specs, Rect::new(0, 0, 160, 48));
    assert!(wide
        .iter()
        .any(|surface| surface.id == PhaseSurfaceId::FixRemediation));
}

#[test]
fn phase_presentation_plan_rectangles_are_bounded_and_non_overlapping() {
    let area = Rect::new(7, 5, 153, 31);
    let rects = surface_rects(area, 3);
    assert_eq!(rects.len(), 3);
    for rect in &rects {
        assert!(rect.x >= area.x && rect.right() <= area.right());
        assert!(rect.y >= area.y && rect.bottom() <= area.bottom());
        assert!(rect.width > 0 && rect.height > 0);
    }
    assert_eq!(rects[0].right(), rects[1].x);
    assert_eq!(rects[1].right(), rects[2].x);
}

#[test]
fn phase_presentation_plan_guided_mode_has_one_attention_surface() {
    let specs = test_specs();
    let (density, visible) = visible_specs(
        &specs,
        Rect::new(0, 0, 160, 48),
        None,
        AttentionMode::GuidedQuestion,
    );
    assert_eq!(density, LayoutDensity::Guided);
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].id, PhaseSurfaceId::FixRemediation);
}
