use super::PhaseCockpitBody;
use crate::app::WorkbenchPane;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    ReviewDetail,
    ProveStatus,
    ProveEvidence,
    ProveLadder,
    ProveReceipt,
    FixRemediation,
    FixCandidate,
    FixAttackTree,
    FixDfd,
}

impl PhaseSurfaceId {
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
            Self::ReviewDetail => "Selected Finding",
            Self::ProveStatus => "Proof Status",
            Self::ProveEvidence => "Evidence",
            Self::ProveLadder => "Proof Ladder",
            Self::ProveReceipt => "Verification Receipt",
            Self::FixRemediation => "Remediation",
            Self::FixCandidate => "Patch Candidate",
            Self::FixAttackTree => "Attack Tree",
            Self::FixDfd => "Data-flow Diagram",
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
    pub(crate) legacy_slot: WorkbenchPane,
    pub(crate) state: SurfaceState,
    pub(crate) interaction: SurfaceInteraction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlannedPhaseSurface {
    pub(crate) id: PhaseSurfaceId,
    pub(crate) legacy_slot: WorkbenchPane,
    pub(crate) state: SurfaceState,
    pub(crate) interaction: SurfaceInteraction,
    pub(crate) rect: Rect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PhasePresentationPlan {
    pub(crate) density: LayoutDensity,
    pub(crate) primary: PhaseSurfaceId,
    pub(crate) effective_focus: PhaseSurfaceId,
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

    pub(crate) fn effective_slot(&self) -> WorkbenchPane {
        self.surface(self.effective_focus)
            .map(|surface| surface.legacy_slot)
            .unwrap_or(WorkbenchPane::Source)
    }
}

pub(crate) fn phase_presentation_plan(
    body: &PhaseCockpitBody,
    area: Rect,
    stored_focus: Option<WorkbenchPane>,
    focused_slot: Option<WorkbenchPane>,
    attention: AttentionMode,
) -> PhasePresentationPlan {
    let specs = phase_surface_specs(body);
    let primary = specs[0].id;
    let (density, visible) = visible_specs(&specs, area, focused_slot, attention);
    let planned_area = if density == LayoutDensity::Guided {
        Rect {
            height: area.height.min(5),
            ..area
        }
    } else {
        area
    };
    let rects = surface_rects(planned_area, visible.len());
    let surfaces = visible
        .iter()
        .zip(rects)
        .map(|(spec, rect)| planned_surface(**spec, rect))
        .collect::<Vec<_>>();
    let effective_focus = effective_focus(&surfaces, stored_focus, primary);
    PhasePresentationPlan {
        density,
        primary,
        effective_focus,
        available_surfaces: specs,
        surfaces,
    }
}

fn visible_specs<'a>(
    specs: &'a [PhaseSurfaceSpec],
    area: Rect,
    focused_slot: Option<WorkbenchPane>,
    attention: AttentionMode,
) -> (LayoutDensity, Vec<&'a PhaseSurfaceSpec>) {
    if attention != AttentionMode::Normal {
        return (LayoutDensity::Guided, vec![&specs[0]]);
    }
    if let Some(focused) = focused_slot {
        let selected = specs
            .iter()
            .find(|spec| spec.legacy_slot == focused)
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

fn surface_rects(area: Rect, count: usize) -> Vec<Rect> {
    match count {
        0 => Vec::new(),
        1 => vec![area],
        2 => split_columns(area, &[44, 56]),
        _ => split_columns(area, &[40, 30, 30]),
    }
}

fn split_columns(area: Rect, percentages: &[u16]) -> Vec<Rect> {
    let mut x = area.x;
    percentages
        .iter()
        .enumerate()
        .map(|(index, percentage)| {
            let last = index + 1 == percentages.len();
            let width = if last {
                area.right().saturating_sub(x)
            } else {
                area.width.saturating_mul(*percentage) / 100
            };
            let rect = Rect::new(x, area.y, width, area.height);
            x = x.saturating_add(width);
            rect
        })
        .collect()
}

fn effective_focus(
    surfaces: &[PlannedPhaseSurface],
    stored_focus: Option<WorkbenchPane>,
    primary: PhaseSurfaceId,
) -> PhaseSurfaceId {
    stored_focus
        .and_then(|slot| surfaces.iter().find(|surface| surface.legacy_slot == slot))
        .map(|surface| surface.id)
        .unwrap_or(primary)
}

fn planned_surface(spec: PhaseSurfaceSpec, rect: Rect) -> PlannedPhaseSurface {
    PlannedPhaseSurface {
        id: spec.id,
        legacy_slot: spec.legacy_slot,
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
