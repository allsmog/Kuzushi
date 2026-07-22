use super::*;

fn test_spec(id: PhaseSurfaceId) -> PhaseSurfaceSpec {
    PhaseSurfaceSpec {
        id,
        state: SurfaceState::Available,
        interaction: SurfaceInteraction::Scrollable,
    }
}

fn test_specs() -> Vec<PhaseSurfaceSpec> {
    vec![
        test_spec(PhaseSurfaceId::FixRemediation),
        test_spec(PhaseSurfaceId::FixCandidate),
        test_spec(PhaseSurfaceId::FixAttackTree),
        test_spec(PhaseSurfaceId::FixDfd),
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
        effective_focus(&compact, Some(PhaseSurfaceId::FixDfd), specs[0].id),
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
    let rects = super::super::composition::split_columns(area, &[40, 30, 30]);
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
fn automatic_density_changes_at_the_documented_width_boundaries() {
    let specs = test_specs();
    let cases = [
        (77, LayoutDensity::Sparse, 1),
        (78, LayoutDensity::MasterDetail, 2),
        (119, LayoutDensity::MasterDetail, 2),
        (120, LayoutDensity::Dense, 3),
    ];

    for (width, expected_density, expected_count) in cases {
        let (density, visible) = automatic_specs(&specs, Rect::new(0, 0, width, 30));
        assert_eq!(
            density, expected_density,
            "unexpected density at {width} columns"
        );
        assert_eq!(
            visible.len(),
            expected_count,
            "unexpected surface count at {width} columns"
        );
    }
}

#[test]
fn automatic_density_changes_at_the_documented_height_boundaries() {
    let specs = test_specs();
    let cases = [
        (119, 9, LayoutDensity::Sparse, 1),
        (119, 10, LayoutDensity::MasterDetail, 2),
        (120, 15, LayoutDensity::MasterDetail, 2),
        (120, 16, LayoutDensity::Dense, 3),
    ];

    for (width, height, expected_density, expected_count) in cases {
        let (density, visible) = automatic_specs(&specs, Rect::new(0, 0, width, height));
        assert_eq!(
            density, expected_density,
            "unexpected density at {width}x{height}"
        );
        assert_eq!(
            visible.len(),
            expected_count,
            "unexpected surface count at {width}x{height}"
        );
    }
}

#[test]
fn reported_warp_viewport_surface_rectangles_tile_without_overlap() {
    let area = Rect::new(0, 8, 104, 48);
    let rects = crate::ui_view_models::phase_cockpit::composition::split_columns(area, &[44, 56]);

    assert_eq!(
        rects,
        vec![Rect::new(0, 8, 45, 48), Rect::new(45, 8, 59, 48)]
    );
    assert_eq!(rects[0].right(), rects[1].x);
    assert_eq!(rects[1].right(), area.right());
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
