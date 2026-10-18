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

#[test]
fn guided_scan_coverage_can_use_the_available_rows_without_acceptance() {
    use crate::ui_view_models::{ScanEngineOutcomeModel, ScanPhaseModel};
    let body = PhaseCockpitBody::Scan(ScanPhaseModel {
        study: None,
        scope: "service".into(),
        plan: "manual".into(),
        attempt: None,
        empty_hint: None,
        live: None,
        engine_outcomes: vec![ScanEngineOutcomeModel {
            engine: "semgrep".into(),
            tool_key: Some("semgrep:scan".into()),
            outcome: "partial".into(),
            run_ref: None,
            detail: Some("An incompatible rule was omitted".into()),
        }],
    });
    for height in [3, 8, 30, 80] {
        let area = Rect::new(0, 4, 96, height);
        let plan = phase_presentation_plan(&body, area, None, None, AttentionMode::ResultReady);
        assert_eq!(plan.density, LayoutDensity::Guided);
        assert_eq!(plan.surfaces.len(), 1);
        assert_eq!(plan.surfaces[0].rect, area);
        assert_eq!(plan.surfaces[0].interaction, SurfaceInteraction::Scrollable);
    }
    let area = Rect::new(0, 4, 96, 80);
    let question = phase_presentation_plan(&body, area, None, None, AttentionMode::GuidedQuestion);
    assert_eq!(question.surfaces[0].rect.height, 5);
}

#[test]
fn compact_review_reading_keeps_detail_without_changing_the_explicit_zoom() {
    let specs = vec![
        test_spec(PhaseSurfaceId::ReviewQueue),
        test_spec(PhaseSurfaceId::ReviewDetail),
    ];
    for (width, height) in [(40, 4), (60, 12), (120, 9)] {
        let area = Rect::new(0, 0, width, height);
        let focus = compact_reading_focus(&specs, area, Some(PhaseSurfaceId::ReviewDetail));
        let (density, visible) = visible_specs(&specs, area, focus, AttentionMode::Normal);
        assert_eq!(density, LayoutDensity::Focused);
        assert_eq!(visible[0].id, PhaseSurfaceId::ReviewDetail);
        assert!(compact_reading_focus(&specs, area, Some(PhaseSurfaceId::ReviewQueue)).is_none());
    }
    let wide = Rect::new(0, 0, 120, 30);
    assert!(compact_reading_focus(&specs, wide, Some(PhaseSurfaceId::ReviewDetail)).is_none());
    assert_eq!(automatic_specs(&specs, wide).0, LayoutDensity::MasterDetail);
}

#[test]
fn compact_review_reading_requires_detail_and_yields_to_guided_attention() {
    let queue = test_spec(PhaseSurfaceId::ReviewQueue);
    let area = Rect::new(0, 0, 40, 8);
    assert!(compact_reading_focus(&[queue], area, Some(PhaseSurfaceId::ReviewDetail)).is_none());
    let specs = [queue, test_spec(PhaseSurfaceId::ReviewDetail)];
    let focus = compact_reading_focus(&specs, area, Some(PhaseSurfaceId::ReviewDetail));
    let (density, visible) = visible_specs(&specs, area, focus, AttentionMode::GuidedQuestion);
    assert_eq!(density, LayoutDensity::Guided);
    assert_eq!(visible[0].id, PhaseSurfaceId::ReviewQueue);
}

#[test]
fn scan_reading_surface_stays_visible_when_terminal_shrinks() {
    let specs = [
        PhaseSurfaceId::ScanEngines,
        PhaseSurfaceId::ScanReceipt,
        PhaseSurfaceId::ScanDelta,
    ]
    .map(test_spec);
    for selected in [PhaseSurfaceId::ScanReceipt, PhaseSurfaceId::ScanDelta] {
        for (width, height) in [(120, 36), (160, 48), (96, 89), (80, 24), (60, 20), (40, 12)] {
            let area = Rect::new(0, 0, width, height);
            let reading = compact_reading_focus(&specs, area, Some(selected));
            let (_, visible) = visible_specs(&specs, area, reading, AttentionMode::Normal);
            assert!(
                visible.iter().any(|spec| spec.id == selected),
                "{selected:?} at {width}x{height}"
            );
        }
    }
}

#[test]
fn compact_scan_reading_requires_its_surface_and_yields_to_pending_decisions() {
    let engines = test_spec(PhaseSurfaceId::ScanEngines);
    let area = Rect::new(0, 0, 40, 8);
    assert!(compact_reading_focus(&[engines], area, Some(PhaseSurfaceId::ScanDelta)).is_none());
    let specs = [engines, test_spec(PhaseSurfaceId::ScanDelta)];
    let reading = compact_reading_focus(&specs, area, Some(PhaseSurfaceId::ScanDelta));
    for attention in [AttentionMode::GuidedQuestion, AttentionMode::ResultReady] {
        let (density, visible) = visible_specs(&specs, area, reading, attention);
        assert_eq!(density, LayoutDensity::Guided);
        assert_eq!(visible[0].id, PhaseSurfaceId::ScanEngines);
    }
}
