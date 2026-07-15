use super::super::*;
use super::SemanticFixture;
use crate::ui_view_models::phase_cockpit::layout::PhaseSurfaceSpec;
use kuzushi_core::WorkflowPhase;
use ratatui::layout::Rect;

pub(super) fn surface_ids<T>(surfaces: &[T]) -> Vec<PhaseSurfaceId>
where
    T: SurfaceIdentity,
{
    surfaces.iter().map(SurfaceIdentity::surface_id).collect()
}

pub(super) trait SurfaceIdentity {
    fn surface_id(&self) -> PhaseSurfaceId;
}

impl SurfaceIdentity for PhaseSurfaceSpec {
    fn surface_id(&self) -> PhaseSurfaceId {
        self.id
    }
}

impl SurfaceIdentity for PlannedPhaseSurface {
    fn surface_id(&self) -> PhaseSurfaceId {
        self.id
    }
}

pub(super) fn expected_density(
    count: usize,
    area: Rect,
    attention: AttentionMode,
) -> LayoutDensity {
    if attention != AttentionMode::Normal {
        return LayoutDensity::Guided;
    }
    if count >= 3 && area.width >= 120 && area.height >= 16 {
        LayoutDensity::Dense
    } else if count >= 2 && area.width >= 78 && area.height >= 10 {
        LayoutDensity::MasterDetail
    } else {
        LayoutDensity::Sparse
    }
}

pub(super) fn expected_visible_count(count: usize, density: LayoutDensity) -> usize {
    match density {
        LayoutDensity::Sparse | LayoutDensity::Focused | LayoutDensity::Guided => 1,
        LayoutDensity::MasterDetail => count.min(2),
        LayoutDensity::Dense => count.min(3),
    }
}

pub(super) fn expected_primary(phase: WorkflowPhase, state: SemanticFixture) -> PhaseSurfaceId {
    match phase {
        WorkflowPhase::Map => PhaseSurfaceId::MapReadiness,
        WorkflowPhase::Scan if state.richness() == 0 => PhaseSurfaceId::ScanScope,
        WorkflowPhase::Scan => PhaseSurfaceId::ScanEngines,
        WorkflowPhase::Review => PhaseSurfaceId::ReviewQueue,
        WorkflowPhase::Prove => PhaseSurfaceId::ProveStatus,
        WorkflowPhase::Fix => PhaseSurfaceId::FixRemediation,
    }
}

pub(super) fn expected_surface_ids(phase: WorkflowPhase, richness: usize) -> Vec<PhaseSurfaceId> {
    match phase {
        WorkflowPhase::Map => map_surface_ids(richness),
        WorkflowPhase::Scan => scan_surface_ids(richness),
        WorkflowPhase::Review => review_surface_ids(richness),
        WorkflowPhase::Prove => prove_surface_ids(richness),
        WorkflowPhase::Fix => fix_surface_ids(richness),
    }
}

fn map_surface_ids(richness: usize) -> Vec<PhaseSurfaceId> {
    let mut ids = vec![PhaseSurfaceId::MapReadiness];
    push_id(&mut ids, richness >= 1, PhaseSurfaceId::MapAttackSurface);
    push_id(&mut ids, richness >= 2, PhaseSurfaceId::MapHotModules);
    push_id(&mut ids, richness >= 3, PhaseSurfaceId::MapDfd);
    ids
}

fn scan_surface_ids(richness: usize) -> Vec<PhaseSurfaceId> {
    if richness == 0 {
        return vec![PhaseSurfaceId::ScanScope];
    }
    let mut ids = vec![PhaseSurfaceId::ScanEngines];
    push_id(&mut ids, richness >= 2, PhaseSurfaceId::ScanReceipt);
    push_id(&mut ids, richness >= 3, PhaseSurfaceId::ScanDelta);
    ids.push(PhaseSurfaceId::ScanScope);
    ids
}

fn review_surface_ids(richness: usize) -> Vec<PhaseSurfaceId> {
    let mut ids = vec![PhaseSurfaceId::ReviewQueue];
    push_id(&mut ids, richness >= 1, PhaseSurfaceId::ReviewDetail);
    ids
}

fn prove_surface_ids(richness: usize) -> Vec<PhaseSurfaceId> {
    let mut ids = vec![PhaseSurfaceId::ProveStatus];
    push_id(&mut ids, richness >= 1, PhaseSurfaceId::ProveEvidence);
    push_id(&mut ids, richness >= 1, PhaseSurfaceId::ProveLadder);
    push_id(&mut ids, richness >= 2, PhaseSurfaceId::ProveReceipt);
    ids
}

fn fix_surface_ids(richness: usize) -> Vec<PhaseSurfaceId> {
    let mut ids = vec![PhaseSurfaceId::FixRemediation];
    push_id(&mut ids, richness >= 1, PhaseSurfaceId::FixCandidate);
    push_id(&mut ids, richness >= 2, PhaseSurfaceId::FixDfd);
    ids
}

fn push_id(ids: &mut Vec<PhaseSurfaceId>, condition: bool, id: PhaseSurfaceId) {
    if condition {
        ids.push(id);
    }
}
