use super::layout::PhaseSurfaceSpec;
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
    assert_matrix_plan_identity(&plan, &specs, density, phase, state, &cell);
    let multi_surface = matches!(
        plan.density,
        LayoutDensity::Dense | LayoutDensity::MasterDetail
    );
    let expected_visible = expected_visible_surfaces(
        phase,
        body,
        &specs,
        visible_count,
        multi_surface,
        density == LayoutDensity::Guided,
        area.width,
    );
    assert_eq!(
        surface_ids(&plan.surfaces),
        expected_visible,
        "{cell}: visible surface order"
    );
    assert!(plan.surfaces.len() <= 3, "{cell}: more than three surfaces");
    assert_rectangles(&plan, area, &cell);
    assert_attention_owner(&plan, state.attention(), &cell);
}

fn assert_matrix_plan_identity(
    plan: &PhasePresentationPlan,
    specs: &[PhaseSurfaceSpec],
    density: LayoutDensity,
    phase: WorkflowPhase,
    state: SemanticFixture,
    cell: &str,
) {
    assert_eq!(plan.density, density, "{cell}: density");
    assert_eq!(
        surface_ids(&plan.available_surfaces),
        surface_ids(specs),
        "{cell}: available focused-deck surfaces"
    );
    assert_eq!(
        plan.primary,
        expected_primary(phase, state),
        "{cell}: primary"
    );
}

fn expected_visible_surfaces(
    phase: WorkflowPhase,
    body: &PhaseCockpitBody,
    specs: &[PhaseSurfaceSpec],
    visible_count: usize,
    multi_surface: bool,
    guided: bool,
    width: u16,
) -> Vec<PhaseSurfaceId> {
    if phase == WorkflowPhase::Map {
        return expected_map_surfaces(body, specs, visible_count, multi_surface, guided);
    }
    if phase == WorkflowPhase::Prove {
        return expected_prove_surfaces(specs, visible_count, multi_surface);
    }
    if phase == WorkflowPhase::Fix {
        return expected_fix_surfaces(specs, visible_count, multi_surface, width);
    }
    surface_ids(&specs[..visible_count])
}

fn expected_map_surfaces(
    body: &PhaseCockpitBody,
    specs: &[PhaseSurfaceSpec],
    visible_count: usize,
    multi_surface: bool,
    guided: bool,
) -> Vec<PhaseSurfaceId> {
    let PhaseCockpitBody::Map(map) = body else {
        unreachable!("Map phase body")
    };
    if super::map::map_has_gallery(map) && !guided {
        return vec![PhaseSurfaceId::MapDfd];
    }
    if multi_surface {
        return vec![PhaseSurfaceId::MapDfd, PhaseSurfaceId::MapReadiness];
    }
    surface_ids(&specs[..visible_count])
}

fn expected_prove_surfaces(
    specs: &[PhaseSurfaceSpec],
    visible_count: usize,
    multi_surface: bool,
) -> Vec<PhaseSurfaceId> {
    let has_status = specs
        .iter()
        .any(|spec| spec.id == PhaseSurfaceId::ProveStatus);
    if multi_surface && has_status {
        return vec![PhaseSurfaceId::ProveStatus, PhaseSurfaceId::ProveNextAction];
    }
    surface_ids(&specs[..visible_count])
}

fn expected_fix_surfaces(
    specs: &[PhaseSurfaceSpec],
    visible_count: usize,
    multi_surface: bool,
    width: u16,
) -> Vec<PhaseSurfaceId> {
    let has_candidate = specs
        .iter()
        .any(|spec| spec.id == PhaseSurfaceId::FixCandidate);
    if !multi_surface || !has_candidate {
        return surface_ids(&specs[..visible_count]);
    }
    expected_fix_triptych(width)
}

fn expected_fix_triptych(width: u16) -> Vec<PhaseSurfaceId> {
    if width >= 120 {
        return vec![
            PhaseSurfaceId::FixRemediation,
            PhaseSurfaceId::FixCandidate,
            PhaseSurfaceId::FixVerification,
        ];
    }
    vec![PhaseSurfaceId::FixRemediation, PhaseSurfaceId::FixCandidate]
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
/// `C` gives the whole Review body to the chain-artifact screen; closing it
/// restores the list+detail triage composition.
#[test]
fn chains_view_composes_full_screen_over_the_review_page() {
    let mut body = fixture_body(WorkflowPhase::Review, SemanticFixture::Dense);
    let PhaseCockpitBody::Review(model) = &mut body else {
        panic!("review fixture body");
    };
    model.chains = Some(crate::ui_view_models::ChainArtifactsModel {
        confirmed_count: 2,
        identity: None,
        candidates: Vec::new(),
        grounded: Vec::new(),
    });
    let wide = Rect::new(0, 0, 160, 48);

    let plan = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(matches!(
        plan.composition,
        Composition::FullScreen(PhaseSurfaceId::ReviewChains)
    ));
    assert_eq!(plan.surfaces.len(), 1);
    assert_eq!(plan.surfaces[0].rect, wide);

    let PhaseCockpitBody::Review(model) = &mut body else {
        panic!("review fixture body");
    };
    model.chains = None;
    let plan = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(matches!(plan.composition, Composition::ListDetail { .. }));
}

/// `t` gives the whole Prove body to the Trace screen; closing it restores
/// the FocusDetail composition.
#[test]
fn trace_view_composes_full_screen_over_the_prove_page() {
    let mut body = fixture_body(WorkflowPhase::Prove, SemanticFixture::Dense);
    let PhaseCockpitBody::Prove(model) = &mut body else {
        panic!("prove fixture body");
    };
    model.trace = Some(crate::ui_view_models::TraceEvidenceModel {
        reference: "F-1".to_string(),
        severity: "HIGH".to_string(),
        identity: None,
        original: Vec::new(),
        expanded: Vec::new(),
        open_questions: Vec::new(),
        evidence_deltas: Vec::new(),
        expand_command: "run trace:expand {}".to_string(),
        next_hint: "hint".to_string(),
    });
    let wide = Rect::new(0, 0, 160, 48);

    let plan = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(matches!(
        plan.composition,
        Composition::FullScreen(PhaseSurfaceId::ProveTrace)
    ));
    assert_eq!(plan.surfaces.len(), 1);
    assert_eq!(plan.surfaces[0].rect, wide);

    let PhaseCockpitBody::Prove(model) = &mut body else {
        panic!("prove fixture body");
    };
    model.trace = None;
    let plan = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(matches!(plan.composition, Composition::FocusDetail { .. }));
}

/// The `v` investigation card takes over the Prove page as a centered form;
/// closing it restores the FocusDetail triage composition.
#[test]
fn investigation_card_composes_a_centered_form_over_the_prove_page() {
    let mut body = fixture_body(WorkflowPhase::Prove, SemanticFixture::Dense);
    let PhaseCockpitBody::Prove(model) = &mut body else {
        panic!("prove fixture body");
    };
    model.investigation = Some(InvestigationPlanModel {
        reference: "F-7".to_string(),
        severity: "HIGH".to_string(),
        why: "evidence message-only".to_string(),
        evidence_goals: vec!["Recover structured evidence anchors".to_string()],
        empirical: false,
        model_ladder: vec!["gate: not set (rejection only)".to_string()],
        command: "run verify:finding {}".to_string(),
    });
    let wide = Rect::new(0, 0, 160, 48);

    let plan = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(matches!(
        plan.composition,
        Composition::CenteredForm(PhaseSurfaceId::ProveInvestigation)
    ));
    assert_eq!(plan.surfaces.len(), 1);
    assert!(plan.surfaces[0].rect.width <= 100);
    assert_eq!(plan.effective_focus, PhaseSurfaceId::ProveStatus);
    let focused = phase_presentation_plan(
        &body,
        wide,
        Some(PhaseSurfaceId::ProveInvestigation),
        None,
        AttentionMode::Normal,
    );
    assert_eq!(focused.effective_focus, PhaseSurfaceId::ProveInvestigation);

    let PhaseCockpitBody::Prove(model) = &mut body else {
        panic!("prove fixture body");
    };
    model.investigation = None;
    let plan = phase_presentation_plan(&body, wide, None, None, AttentionMode::Normal);
    assert!(matches!(plan.composition, Composition::FocusDetail { .. }));
}

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

/// #172: a Map whose only surface is its readiness card is a form asking for
/// one action, not a workspace. The generic column solver handed it the entire
/// body, so on a wide terminal a ~124-column pane carried rows that stopped
/// near column 90 above thirty blank rows. It is now capped at the
/// centered-form width and bounded to the rows the card renders, while
/// terminals narrower than that cap keep the full-width card.
#[test]
fn actionable_map_status_card_is_bounded_to_its_own_content() {
    for state in [
        SemanticFixture::Empty,
        SemanticFixture::Blocked,
        SemanticFixture::Stale,
    ] {
        let body = fixture_body(WorkflowPhase::Map, state);
        for (width, height) in CANONICAL_SIZES {
            assert_map_status_card_bounds(&body, state, Rect::new(7, 5, width, height));
        }
    }
}

fn assert_map_status_card_bounds(body: &PhaseCockpitBody, state: SemanticFixture, area: Rect) {
    let plan = phase_presentation_plan(body, area, None, None, AttentionMode::Normal);
    let Composition::StatusCard {
        surface,
        content_rows,
    } = plan.composition
    else {
        return;
    };
    let cell = cell_label(WorkflowPhase::Map, state, area.width, area.height);
    let card = plan
        .surface(surface)
        .unwrap_or_else(|| panic!("{cell}: status card has no rect"));
    assert_eq!(
        card.rect.width,
        area.width
            .min(super::composition::CENTERED_FORM_MAX_COLUMNS),
        "{cell}: status-card width"
    );
    let PhaseCockpitBody::Map(model) = body else {
        unreachable!("Map fixture body")
    };
    assert_eq!(
        content_rows,
        super::map::map_status_card_rows(model),
        "{cell}: card sized from the rows the renderer emits"
    );
    assert!(
        card.rect.height <= area.height,
        "{cell}: card height {} exceeds the body",
        card.rect.height
    );
    assert!(
        card.rect.height <= content_rows + 1 || card.rect.height == area.height,
        "{cell}: card height {} outgrew its {content_rows} content rows",
        card.rect.height
    );
}

/// The unbuilt-Map card and the rows it promises, for one terminal size.
fn unbuilt_map_card(area: Rect) -> (PlannedPhaseSurface, u16) {
    let body = fixture_body(WorkflowPhase::Map, SemanticFixture::Empty);
    let PhaseCockpitBody::Map(model) = &body else {
        unreachable!("Map fixture body")
    };
    let content_rows = super::map::map_status_card_rows(model);
    let plan = phase_presentation_plan(&body, area, None, None, AttentionMode::Normal);
    assert_eq!(plan.surfaces.len(), 1, "unbuilt Map shows one card");
    (plan.surfaces[0], content_rows)
}

/// The 160x48 corner the defect report named: a ~124-column pane whose rows
/// stopped near column 90, above thirty blank rows.
#[test]
fn unbuilt_map_status_card_is_capped_at_one_hundred_and_sixty_columns() {
    let (card, content_rows) = unbuilt_map_card(Rect::new(0, 0, 160, 48));
    assert!(
        card.rect.width <= 100,
        "160x48 card width was {}",
        card.rect.width
    );
    assert_eq!(
        card.rect.height,
        content_rows + 1,
        "160x48 card must stop at its last row, not fill 48 rows"
    );
}

/// The 80x24 corner: narrower than the width cap, so the card keeps the full
/// width and still stops at its last row.
#[test]
fn unbuilt_map_status_card_stays_full_width_at_eighty_columns() {
    let (card, content_rows) = unbuilt_map_card(Rect::new(0, 0, 80, 24));
    assert_eq!(card.rect.width, 80, "80x24 keeps the full-width card");
    assert_eq!(
        card.rect.height,
        content_rows + 1,
        "80x24 card must stop at its last row"
    );
}

/// The audited state the earlier width cap did not reach: an accepted Map with
/// a built context but no threat model has nothing missing, stale, or blocked,
/// so its readiness card fell through to the generic column solver and was
/// stretched over the whole body — six populated rows above thirty blank ones.
#[test]
fn map_awaiting_only_a_threat_model_gets_the_status_card_not_the_body() {
    let mut body = fixture_body(WorkflowPhase::Map, SemanticFixture::Empty);
    let PhaseCockpitBody::Map(model) = &mut body else {
        unreachable!("Map fixture body")
    };
    // Context is built, so the readiness card is Available; only the missing
    // threat model still asks for an action.
    model.empty_hint = None;
    model.project.rows = vec![crate::ui_view_models::ProjectModelRow {
        section: "context feed",
        origin: crate::ui_view_models::ProjectModelOrigin::Local,
        state: "present",
        summary: "1 snapshot".to_string(),
        action: "context build",
    }];
    assert!(super::map::map_requires_action(model));
    assert_eq!(phase_surface_specs(&body).len(), 1);

    let area = Rect::new(0, 0, 160, 48);
    let plan = phase_presentation_plan(&body, area, None, None, AttentionMode::Normal);
    assert_eq!(plan.density, LayoutDensity::Sparse);
    assert!(
        matches!(plan.composition, Composition::StatusCard { .. }),
        "sparse actionable Map composition was {:?}",
        plan.composition
    );
    assert_eq!(
        plan.surfaces[0].rect.height, 4,
        "heading, status, one receipt row, and the pane title"
    );
}
