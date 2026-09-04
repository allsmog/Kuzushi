use super::composition::Composition;
use super::PhaseCockpitBody;
use crate::app::WorkbenchPage;
use ratatui::layout::Rect;

mod surface_specs;
pub(crate) use surface_specs::phase_surface_specs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayoutDensity {
    Sparse,
    MasterDetail,
    Dense,
    Focused,
    Guided,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttentionMode {
    Normal,
    GuidedQuestion,
    ResultReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum PhaseSurfaceId {
    MapReadiness,
    MapAttackSurface,
    MapHotModules,
    MapDfd,
    ScanEngines,
    ScanReceipt,
    ScanDelta,
    ScanScope,
    ReviewQueue,
    ReviewChains,
    ReviewDetail,
    ReviewNextPlan,
    ProveStatus,
    ProveEvidence,
    ProveLadder,
    ProveReceipt,
    ProveNextAction,
    ProveInvestigation,
    ProveTrace,
    FixRemediation,
    FixCandidate,
    FixAttackTree,
    FixDfd,
    FixVerification,
}

impl PhaseSurfaceId {
    /// The Workbench page that owns this surface. Focus, zoom, and scroll are
    /// keyed by surface id; this reverse edge lets a stored focus from another
    /// page fall back to the rendered page's default instead of aliasing onto
    /// an unrelated surface.
    pub(crate) const fn page(self) -> WorkbenchPage {
        match self {
            Self::MapReadiness | Self::MapAttackSurface | Self::MapHotModules | Self::MapDfd => {
                WorkbenchPage::Map
            }
            Self::ScanEngines | Self::ScanReceipt | Self::ScanDelta | Self::ScanScope => {
                WorkbenchPage::Scan
            }
            Self::ReviewChains | Self::ReviewQueue | Self::ReviewDetail | Self::ReviewNextPlan => {
                WorkbenchPage::Review
            }
            Self::ProveStatus
            | Self::ProveEvidence
            | Self::ProveLadder
            | Self::ProveReceipt
            | Self::ProveNextAction
            | Self::ProveInvestigation
            | Self::ProveTrace => WorkbenchPage::Prove,
            Self::FixRemediation
            | Self::FixCandidate
            | Self::FixAttackTree
            | Self::FixDfd
            | Self::FixVerification => WorkbenchPage::Fix,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::MapReadiness => "Project Context",
            Self::MapAttackSurface => "Attack Surface",
            Self::MapHotModules => "Hot Modules",
            Self::MapDfd => "Data-flow Diagram",
            Self::ScanEngines => "Engine Outcomes",
            Self::ScanReceipt => "Scan Receipt",
            Self::ScanDelta => "Finding Delta",
            Self::ScanScope => "Scope and Plan",
            Self::ReviewQueue => "Review Queue",
            Self::ReviewChains => "Attack Chains",
            Self::ReviewDetail => "Selected Finding",
            Self::ReviewNextPlan => "Next Investigation Plan",
            Self::ProveStatus => "Proof Status",
            Self::ProveEvidence => "Evidence",
            Self::ProveLadder => "Proof Ladder",
            Self::ProveReceipt => "Verification Receipt",
            Self::ProveNextAction => "Next Action",
            Self::ProveInvestigation => "Investigation Plan",
            Self::ProveTrace => "Trace",
            Self::FixRemediation => "Remediation",
            Self::FixCandidate => "Patch Candidate",
            Self::FixAttackTree => "Attack Tree",
            Self::FixDfd => "Data-flow Diagram",
            Self::FixVerification => "Verification",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SurfaceState {
    Missing,
    Status,
    Available,
    Stale,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SurfaceInteraction {
    Static,
    Selectable,
    Scrollable,
    Diagram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PhaseSurfaceSpec {
    pub(crate) id: PhaseSurfaceId,
    pub(crate) state: SurfaceState,
    pub(crate) interaction: SurfaceInteraction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlannedPhaseSurface {
    pub(crate) id: PhaseSurfaceId,
    pub(crate) state: SurfaceState,
    pub(crate) interaction: SurfaceInteraction,
    pub(crate) rect: Rect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhasePresentationPlan {
    pub(crate) density: LayoutDensity,
    pub(crate) primary: PhaseSurfaceId,
    pub(crate) effective_focus: PhaseSurfaceId,
    pub(crate) composition: Composition,
    pub(crate) available_surfaces: Vec<PhaseSurfaceSpec>,
    pub(crate) surfaces: Vec<PlannedPhaseSurface>,
}

impl PhasePresentationPlan {
    pub(crate) fn surface(&self, id: PhaseSurfaceId) -> Option<&PlannedPhaseSurface> {
        self.surfaces.iter().find(|surface| surface.id == id)
    }

    pub(crate) fn hit_test(&self, column: u16, row: u16) -> Option<&PlannedPhaseSurface> {
        self.surfaces
            .iter()
            .find(|surface| rect_contains(surface.rect, column, row))
    }
}

pub(crate) fn phase_presentation_plan(
    body: &PhaseCockpitBody,
    area: Rect,
    stored_focus: Option<PhaseSurfaceId>,
    zoomed: Option<PhaseSurfaceId>,
    attention: AttentionMode,
) -> PhasePresentationPlan {
    let specs = phase_surface_specs(body);
    let primary = specs[0].id;
    let (density, visible) = visible_specs(&specs, area, zoomed, attention);
    let planned_area = if density == LayoutDensity::Guided {
        Rect {
            height: area.height.min(5),
            ..area
        }
    } else {
        area
    };
    let composition = screen_composition(body, density, &visible);
    let surfaces = composition
        .solve(planned_area)
        .into_iter()
        .map(|(id, rect)| planned_surface(spec_for(id, &specs), rect))
        .collect::<Vec<_>>();
    let effective_focus = effective_focus(&surfaces, stored_focus, primary);
    PhasePresentationPlan {
        density,
        primary,
        effective_focus,
        composition,
        available_surfaces: specs,
        surfaces,
    }
}

/// Choose the screen-specific composition. Attention states, zoom, and
/// small terminals keep the plain column layout of whatever is visible;
/// pages that have adopted their investigation-IDE composition switch here.
fn screen_composition(
    body: &PhaseCockpitBody,
    density: LayoutDensity,
    visible: &[&PhaseSurfaceSpec],
) -> Composition {
    let columns = || Composition::Columns(visible.iter().map(|spec| spec.id).collect::<Vec<_>>());
    if let Some(composition) = ready_map_composition(body, density) {
        return composition;
    }
    if let Some(composition) = sparse_map_status_composition(body, density, visible) {
        return composition;
    }
    if !matches!(density, LayoutDensity::Dense | LayoutDensity::MasterDetail) {
        return columns();
    }
    rich_phase_composition(body, visible.len()).unwrap_or_else(columns)
}

/// A completed Map is one coherent gallery at every terminal size. Letting
/// the generic sparse layout unwrap MapDfd would resurrect the retired textual
/// readiness pane exactly where space is tightest.
fn ready_map_composition(body: &PhaseCockpitBody, density: LayoutDensity) -> Option<Composition> {
    let PhaseCockpitBody::Map(model) = body else {
        return None;
    };
    if density == LayoutDensity::Guided {
        return None;
    }
    (!super::map::map_requires_action(model)).then_some(Composition::CanvasWithDrawer {
        canvas: PhaseSurfaceId::MapDfd,
        drawer: None,
    })
}

/// A Map that still needs an action has only its readiness card, so the
/// generic column solver handed one status card the entire body: on a
/// 160-column terminal every row stopped near column 90 inside a 124-column
/// pane, and every row past the card's last line was blank to the bottom of
/// the frame. A card that exists to ask for an action is a form, not a
/// workspace, so it takes the centered-form width cap and stops at the rows it
/// renders. A ready Map never reaches here — `ready_map_composition` claims it
/// first. Scoped to Map — the other phases keep their matrix.
fn sparse_map_status_composition(
    body: &PhaseCockpitBody,
    density: LayoutDensity,
    visible: &[&PhaseSurfaceSpec],
) -> Option<Composition> {
    let PhaseCockpitBody::Map(model) = body else {
        return None;
    };
    let spec = visible.first()?;
    if density != LayoutDensity::Sparse || spec.id != PhaseSurfaceId::MapReadiness {
        return None;
    }
    Some(Composition::StatusCard {
        surface: spec.id,
        content_rows: super::map::map_status_card_rows(model),
    })
}

fn rich_phase_composition(body: &PhaseCockpitBody, visible_count: usize) -> Option<Composition> {
    prove_composition(body)
        .or_else(|| fix_composition(body))
        .or_else(|| scan_composition(body))
        .or_else(|| review_composition(body, visible_count))
        .or_else(|| actionable_map_composition(body))
}

fn prove_composition(body: &PhaseCockpitBody) -> Option<Composition> {
    let PhaseCockpitBody::Prove(model) = body else {
        return None;
    };
    if model.trace.is_some() {
        return Some(Composition::FullScreen(PhaseSurfaceId::ProveTrace));
    }
    if model.investigation.is_some() {
        return Some(Composition::CenteredForm(
            PhaseSurfaceId::ProveInvestigation,
        ));
    }
    model.finding.is_some().then_some(Composition::FocusDetail {
        body: PhaseSurfaceId::ProveStatus,
        action_menu: Some(PhaseSurfaceId::ProveNextAction),
    })
}

fn fix_composition(body: &PhaseCockpitBody) -> Option<Composition> {
    let PhaseCockpitBody::Fix(model) = body else {
        return None;
    };
    let active = model.finding.is_some()
        || model.patch.is_some()
        || model.remediation.stage != super::RemediationLifecycleStage::NotDrafted;
    active.then_some(Composition::Triptych {
        plan: PhaseSurfaceId::FixRemediation,
        diff: PhaseSurfaceId::FixCandidate,
        verification: PhaseSurfaceId::FixVerification,
    })
}

fn scan_composition(body: &PhaseCockpitBody) -> Option<Composition> {
    let PhaseCockpitBody::Scan(model) = body else {
        return None;
    };
    model
        .live
        .is_some()
        .then_some(Composition::OperationalColumns {
            left: PhaseSurfaceId::ScanScope,
            center: PhaseSurfaceId::ScanEngines,
            right: PhaseSurfaceId::ScanDelta,
            log_strip: Some(PhaseSurfaceId::ScanReceipt),
        })
}

fn review_composition(body: &PhaseCockpitBody, visible_count: usize) -> Option<Composition> {
    let PhaseCockpitBody::Review(model) = body else {
        return None;
    };
    if model.chains.is_some() {
        return Some(Composition::FullScreen(PhaseSurfaceId::ReviewChains));
    }
    (visible_count >= 2).then_some(Composition::ListDetail {
        list: PhaseSurfaceId::ReviewQueue,
        detail: PhaseSurfaceId::ReviewDetail,
        drawer: review_next_plan_drawer(model),
    })
}

fn actionable_map_composition(body: &PhaseCockpitBody) -> Option<Composition> {
    let PhaseCockpitBody::Map(model) = body else {
        return None;
    };
    super::map::map_requires_action(model).then_some(Composition::CanvasWithDrawer {
        canvas: PhaseSurfaceId::MapDfd,
        drawer: Some(super::composition::DrawerSpec {
            surface: PhaseSurfaceId::MapReadiness,
            size: super::composition::DrawerSize::Expanded,
        }),
    })
}

/// The Next-Investigation-Plan drawer appears only when the recommender has
/// concrete follow-up passes to offer; a pending or failed fold shows nothing
/// rather than an empty card. Three or more passes earn the expanded card.
fn review_next_plan_drawer(
    model: &super::ReviewPhaseModel,
) -> Option<super::composition::DrawerSpec> {
    match &model.next_plan {
        super::NextScansState::Ready(rows) if !rows.is_empty() => {
            Some(super::composition::DrawerSpec {
                surface: PhaseSurfaceId::ReviewNextPlan,
                size: if rows.len() >= 3 {
                    super::composition::DrawerSize::Expanded
                } else {
                    super::composition::DrawerSize::Compact
                },
            })
        }
        _ => None,
    }
}

/// The spec backing a composition region. Regions the spec builder skipped
/// (a canvas whose artifact is missing) synthesize a Missing placeholder so
/// the region can still explain itself instead of vanishing.
fn spec_for(id: PhaseSurfaceId, specs: &[PhaseSurfaceSpec]) -> PhaseSurfaceSpec {
    specs
        .iter()
        .find(|spec| spec.id == id)
        .copied()
        .unwrap_or(PhaseSurfaceSpec {
            id,
            state: SurfaceState::Missing,
            interaction: SurfaceInteraction::Static,
        })
}

fn visible_specs<'a>(
    specs: &'a [PhaseSurfaceSpec],
    area: Rect,
    zoomed: Option<PhaseSurfaceId>,
    attention: AttentionMode,
) -> (LayoutDensity, Vec<&'a PhaseSurfaceSpec>) {
    if attention != AttentionMode::Normal {
        return (LayoutDensity::Guided, vec![&specs[0]]);
    }
    if let Some(zoomed) = zoomed {
        let selected = specs
            .iter()
            .find(|spec| spec.id == zoomed)
            .unwrap_or(&specs[0]);
        return (LayoutDensity::Focused, vec![selected]);
    }
    automatic_specs(specs, area)
}

fn automatic_specs(
    specs: &[PhaseSurfaceSpec],
    area: Rect,
) -> (LayoutDensity, Vec<&PhaseSurfaceSpec>) {
    if specs.len() >= 3 && area.width >= 120 && area.height >= 16 {
        return (LayoutDensity::Dense, specs.iter().take(3).collect());
    }
    if specs.len() >= 2 && area.width >= 78 && area.height >= 10 {
        return (LayoutDensity::MasterDetail, specs.iter().take(2).collect());
    }
    (LayoutDensity::Sparse, vec![&specs[0]])
}

fn effective_focus(
    surfaces: &[PlannedPhaseSurface],
    stored_focus: Option<PhaseSurfaceId>,
    primary: PhaseSurfaceId,
) -> PhaseSurfaceId {
    stored_focus
        .and_then(|id| surfaces.iter().find(|surface| surface.id == id))
        .map(|surface| surface.id)
        .unwrap_or(primary)
}

fn planned_surface(spec: PhaseSurfaceSpec, rect: Rect) -> PlannedPhaseSurface {
    PlannedPhaseSurface {
        id: spec.id,
        state: spec.state,
        interaction: spec.interaction,
        rect,
    }
}

fn rect_contains(rect: Rect, column: u16, row: u16) -> bool {
    column >= rect.x && column < rect.right() && row >= rect.y && row < rect.bottom()
}

#[cfg(test)]
mod tests;
