use super::*;

pub fn present_run(read: &RunProjectionRead) -> RunPresentationV1 {
    present_projection_with_hydration(
        &read.projection,
        read.source.clone(),
        &read.presentation_hydration,
    )
}

pub fn present_projection(
    projection: &RunProjection,
    source: RunProjectionSource,
) -> RunPresentationV1 {
    present_projection_with_hydration(projection, source, &RunPresentationHydrationV1::default())
}

pub fn present_projection_with_hydration(
    projection: &RunProjection,
    source: RunProjectionSource,
    hydration: &RunPresentationHydrationV1,
) -> RunPresentationV1 {
    present_projection_with_hydration_and_health(
        projection,
        source,
        hydration,
        projection.lifecycle_health(),
    )
}

pub fn present_projection_with_hydration_and_health(
    projection: &RunProjection,
    source: RunProjectionSource,
    hydration: &RunPresentationHydrationV1,
    health: RunLifecycleHealth,
) -> RunPresentationV1 {
    let details = call_details::call_details(projection);
    let quarantine = completion_quarantine::CompletionQuarantine::for_health(
        projection.run_id.as_ref(),
        &health,
    );
    RunPresentationV1 {
        run_id: projection.run_id.clone(),
        source,
        health,
        summary: summary_sections(projection, &details, hydration, quarantine.as_ref()),
        timeline: timeline::timeline_cells(projection),
        terminal_status: projection
            .terminal
            .as_ref()
            .map(|terminal| presented_status(terminal.status, quarantine.as_ref())),
    }
}

fn summary_sections(
    projection: &RunProjection,
    details: &BTreeMap<RunCallId, call_details::CallDetails>,
    hydration: &RunPresentationHydrationV1,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> Vec<RunPresentationSectionV1> {
    [
        section(
            RunPresentationSectionKindV1::Work,
            work::work_cells(projection, details, quarantine),
        ),
        section(
            RunPresentationSectionKindV1::Evidence,
            evidence::evidence_cells(projection, hydration),
        ),
        section(
            RunPresentationSectionKindV1::Attention,
            outcome::attention_cells(projection),
        ),
        section(
            RunPresentationSectionKindV1::Outcome,
            outcome::outcome_cells(projection, quarantine),
        ),
    ]
    .into_iter()
    .filter(|section| !section.cells.is_empty())
    .collect()
}

fn presented_status(
    recorded: RunItemStatus,
    quarantine: Option<&completion_quarantine::CompletionQuarantine>,
) -> RunItemStatus {
    quarantine.map_or(recorded, |quarantine| quarantine.status(recorded))
}

fn section(
    kind: RunPresentationSectionKindV1,
    cells: Vec<RunPresentationCellV1>,
) -> RunPresentationSectionV1 {
    RunPresentationSectionV1 { kind, cells }
}
