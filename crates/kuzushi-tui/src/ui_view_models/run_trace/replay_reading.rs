use kuzushi_core::run_lifecycle::*;

pub(crate) fn replay_can_lead_with_results(presentation: &RunPresentationV1) -> bool {
    presentation
        .terminal_status
        .is_some_and(RunItemStatus::is_terminal)
        && matches!(
            &presentation.health,
            RunLifecycleHealth {
                integrity: ProjectionHealth::Healthy,
                durability: RunDurabilityHealth::Durable { .. },
                progress: RunProgressFidelity::Complete,
                delivery: RunDeliveryHealth::Current { .. },
                derivative_delivery: RunDerivativeDeliveryHealth::NotObserved
                    | RunDerivativeDeliveryHealth::Current { .. },
            }
        )
}

pub(crate) fn replay_reading_rows(
    presentation: &RunPresentationV1,
    leading_outcome: Option<&RunCellKey>,
) -> Vec<RunPresentationTextRowV1> {
    let mut rows: Vec<_> = presentation
        .summary_text_rows()
        .into_iter()
        .filter(|row| leading_outcome != Some(&row.key))
        .collect();
    if replay_can_lead_with_results(presentation) {
        rows.sort_by_key(|row| section_priority(row.section.as_ref()));
    }
    rows
}

fn section_priority(section: Option<&RunPresentationSectionKindV1>) -> u8 {
    use RunPresentationSectionKindV1::*;
    match section {
        Some(Attention) => 0,
        Some(Evidence) => 1,
        Some(Work) => 2,
        _ => 3,
    }
}

#[cfg(test)]
mod tests;
