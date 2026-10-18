use super::{PhaseSurfaceId, PhaseSurfaceSpec, SurfaceInteraction, SurfaceState};
use crate::ui_view_models::phase_cockpit::{
    FixPhaseModel, MapPhaseModel, PhaseCockpitBody, ProvePhaseModel, RemediationLifecycleStage,
    RemediationLoadState, ReviewPhaseModel, ScanPhaseModel,
};

pub(crate) fn phase_surface_specs(body: &PhaseCockpitBody) -> Vec<PhaseSurfaceSpec> {
    match body {
        PhaseCockpitBody::Map(model) => map_specs(model),
        PhaseCockpitBody::Scan(model) => scan_specs(model),
        PhaseCockpitBody::Review(model) => review_specs(model),
        PhaseCockpitBody::Prove(model) => prove_specs(model),
        PhaseCockpitBody::Fix(model) => fix_specs(model),
    }
}

fn map_specs(model: &MapPhaseModel) -> Vec<PhaseSurfaceSpec> {
    let mut specs = vec![scrollable_with_state(
        PhaseSurfaceId::MapReadiness,
        map_readiness_state(model),
    )];
    push_if(
        &mut specs,
        model.attack_surface.is_some(),
        scrollable(PhaseSurfaceId::MapAttackSurface),
    );
    push_if(
        &mut specs,
        !model.hot_modules.modules.is_empty(),
        scrollable(PhaseSurfaceId::MapHotModules),
    );
    push_if(
        &mut specs,
        model.dfd.empty_hint.is_none(),
        diagram(PhaseSurfaceId::MapDfd),
    );
    specs
}

fn map_readiness_state(model: &MapPhaseModel) -> SurfaceState {
    if model.context.state.eq_ignore_ascii_case("stale") {
        return SurfaceState::Stale;
    }
    if model
        .context
        .status
        .to_ascii_lowercase()
        .contains("blocked")
    {
        return SurfaceState::Blocked;
    }
    if model.empty_hint.is_some() {
        SurfaceState::Missing
    } else {
        SurfaceState::Available
    }
}

fn scan_specs(model: &ScanPhaseModel) -> Vec<PhaseSurfaceSpec> {
    if model.study.is_some() {
        return vec![
            scrollable(PhaseSurfaceId::ScanDelta),
            scrollable(PhaseSurfaceId::ScanEngines),
            scrollable(PhaseSurfaceId::ScanReceipt),
            static_surface(PhaseSurfaceId::ScanScope),
        ];
    }
    let mut specs = vec![scan_primary_spec(model)];
    push_if(
        &mut specs,
        model.attempt.is_some(),
        scrollable(PhaseSurfaceId::ScanReceipt),
    );
    push_if(
        &mut specs,
        scan_has_delta(model),
        scrollable(PhaseSurfaceId::ScanDelta),
    );
    let needs_scope = specs[0].id != PhaseSurfaceId::ScanScope;
    push_if(
        &mut specs,
        needs_scope,
        static_surface(PhaseSurfaceId::ScanScope),
    );
    specs
}

fn scan_primary_spec(model: &ScanPhaseModel) -> PhaseSurfaceSpec {
    if model.engine_outcomes.is_empty() {
        return spec(
            PhaseSurfaceId::ScanScope,
            scan_scope_state(model),
            SurfaceInteraction::Static,
        );
    }
    let blocked = model
        .engine_outcomes
        .iter()
        .any(|outcome| outcome.outcome.eq_ignore_ascii_case("blocked"));
    let state = if blocked {
        SurfaceState::Blocked
    } else {
        SurfaceState::Available
    };
    scrollable_with_state(PhaseSurfaceId::ScanEngines, state)
}

fn scan_scope_state(model: &ScanPhaseModel) -> SurfaceState {
    if model.empty_hint.is_some() {
        SurfaceState::Missing
    } else {
        SurfaceState::Status
    }
}

fn review_specs(model: &ReviewPhaseModel) -> Vec<PhaseSurfaceSpec> {
    if model.trace.is_some() {
        return vec![scrollable(PhaseSurfaceId::ReviewTrace)];
    }
    let queue = if model.review.total_count == 0 {
        spec(
            PhaseSurfaceId::ReviewQueue,
            SurfaceState::Missing,
            SurfaceInteraction::Static,
        )
    } else {
        selectable(PhaseSurfaceId::ReviewQueue)
    };
    let mut specs = vec![queue];
    push_if(
        &mut specs,
        model.finding.is_some(),
        scrollable(PhaseSurfaceId::ReviewDetail),
    );
    let has_plan =
        matches!(&model.next_plan, super::super::NextScansState::Ready(rows) if !rows.is_empty());
    push_if(
        &mut specs,
        has_plan,
        selectable(PhaseSurfaceId::ReviewNextPlan),
    );
    push_if(
        &mut specs,
        model.chains.is_some(),
        selectable(PhaseSurfaceId::ReviewChains),
    );
    specs
}

fn prove_specs(model: &ProvePhaseModel) -> Vec<PhaseSurfaceSpec> {
    if model.pending_result.is_some() {
        return vec![scrollable(PhaseSurfaceId::ProveResult)];
    }
    let mut specs = vec![scrollable_with_state(
        PhaseSurfaceId::ProveStatus,
        presence_state(model.finding.is_some()),
    )];
    let has_evidence = prove_has_evidence(model);
    push_if(
        &mut specs,
        has_evidence,
        scrollable(PhaseSurfaceId::ProveEvidence),
    );
    push_if(
        &mut specs,
        model.finding.is_some() && has_evidence,
        static_surface(PhaseSurfaceId::ProveLadder),
    );
    if let Some(proof) = model.proof.as_ref() {
        specs.push(scrollable_with_state(
            PhaseSurfaceId::ProveReceipt,
            proof_state(proof.requires_revalidation),
        ));
    }
    push_if(
        &mut specs,
        model.investigation.is_some(),
        scrollable(PhaseSurfaceId::ProveInvestigation),
    );
    push_if(
        &mut specs,
        model.trace.is_some(),
        scrollable(PhaseSurfaceId::ProveTrace),
    );
    specs
}

fn fix_specs(model: &FixPhaseModel) -> Vec<PhaseSurfaceSpec> {
    let mut specs = vec![scrollable_with_state(
        PhaseSurfaceId::FixRemediation,
        remediation_state(model),
    )];
    push_if(
        &mut specs,
        fix_has_candidate(model),
        scrollable(PhaseSurfaceId::FixCandidate),
    );
    if !model.attack_tree.chains.is_empty() {
        specs.push(diagram(PhaseSurfaceId::FixAttackTree));
    } else if model.dfd.empty_hint.is_none() {
        specs.push(diagram(PhaseSurfaceId::FixDfd));
    }
    specs
}

fn remediation_state(model: &FixPhaseModel) -> SurfaceState {
    match (model.remediation.load_state, model.remediation.stage) {
        (RemediationLoadState::Failed, _) | (_, RemediationLifecycleStage::ApplyFailed) => {
            SurfaceState::Blocked
        }
        (_, RemediationLifecycleStage::ChangedSinceApply)
        | (_, RemediationLifecycleStage::PriorFindingGeneration) => SurfaceState::Stale,
        (RemediationLoadState::Missing, RemediationLifecycleStage::NotDrafted) => {
            SurfaceState::Missing
        }
        _ => SurfaceState::Available,
    }
}

/// A severity breakdown is delta evidence in its own right. The `added`/
/// `updated` pair is withheld whenever it stops counting the same findings
/// the breakdown describes, so keying the surface on that pair alone would
/// take the whole panel away — the reconciled distinct/observation total and
/// the breakdown with it — exactly when the panel finally reads honestly.
/// The Scan cockpit owes the operator its finding delta (AGENTS.md § durable
/// Scan page), so the surface follows the content, not the cleared fields.
fn scan_has_delta(model: &ScanPhaseModel) -> bool {
    model.attempt.as_ref().is_some_and(|attempt| {
        attempt.findings_added.unwrap_or_default() > 0
            || attempt.findings_updated.unwrap_or_default() > 0
            || !attempt.severity_counts.is_empty()
            || attempt.artifact_count > 0
            || attempt.error.is_some()
    })
}

fn prove_has_evidence(model: &ProvePhaseModel) -> bool {
    model
        .finding
        .as_ref()
        .is_some_and(|finding| !finding.evidence.is_empty())
        || !model.attack_path.stages.is_empty()
}

fn fix_has_candidate(model: &FixPhaseModel) -> bool {
    model.finding.is_some()
        || model.patch.is_some()
        || model.threat_patch.is_some()
        || model.remediation.stage != RemediationLifecycleStage::NotDrafted
}

const fn presence_state(present: bool) -> SurfaceState {
    if present {
        SurfaceState::Available
    } else {
        SurfaceState::Missing
    }
}

const fn proof_state(requires_revalidation: bool) -> SurfaceState {
    if requires_revalidation {
        SurfaceState::Stale
    } else {
        SurfaceState::Available
    }
}

fn push_if(specs: &mut Vec<PhaseSurfaceSpec>, condition: bool, surface: PhaseSurfaceSpec) {
    if condition {
        specs.push(surface);
    }
}

const fn scrollable(id: PhaseSurfaceId) -> PhaseSurfaceSpec {
    scrollable_with_state(id, SurfaceState::Available)
}

const fn scrollable_with_state(id: PhaseSurfaceId, state: SurfaceState) -> PhaseSurfaceSpec {
    spec(id, state, SurfaceInteraction::Scrollable)
}

const fn selectable(id: PhaseSurfaceId) -> PhaseSurfaceSpec {
    spec(id, SurfaceState::Available, SurfaceInteraction::Selectable)
}

const fn static_surface(id: PhaseSurfaceId) -> PhaseSurfaceSpec {
    spec(id, SurfaceState::Status, SurfaceInteraction::Static)
}

const fn diagram(id: PhaseSurfaceId) -> PhaseSurfaceSpec {
    spec(id, SurfaceState::Available, SurfaceInteraction::Diagram)
}

const fn spec(
    id: PhaseSurfaceId,
    state: SurfaceState,
    interaction: SurfaceInteraction,
) -> PhaseSurfaceSpec {
    PhaseSurfaceSpec {
        id,
        state,
        interaction,
    }
}
