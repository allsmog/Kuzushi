use super::*;
use std::collections::BTreeMap;

fn receipt() -> RunPresentationV1 {
    let mut value = present_projection(&RunProjection::default(), RunProjectionSource::TypedV1);
    value.terminal_status = Some(RunItemStatus::Completed);
    value.summary = vec![
        section(RunPresentationSectionKindV1::Work, "Fixed workload"),
        section(
            RunPresentationSectionKindV1::Evidence,
            "Unverified supplied metadata",
        ),
        section(
            RunPresentationSectionKindV1::Attention,
            "Review the remaining question",
        ),
        section(
            RunPresentationSectionKindV1::Outcome,
            "Retained earlier outcome",
        ),
    ];
    value
}

fn section(kind: RunPresentationSectionKindV1, text: &str) -> RunPresentationSectionV1 {
    RunPresentationSectionV1 {
        kind,
        cells: vec![RunPresentationCellV1 {
            key: RunCellKey {
                source: RunCellSourceV1::Item(RunItemId::new()),
                role: RunCellRoleV1::Plan,
                ordinal: 0,
            },
            importance: RunCellImportanceV1::Essential,
            payload: RunPresentationPayloadV1::Plan(PlanPresentationV1 {
                revision: 1,
                title: SafeText::operator_visible(text),
                status: RunItemStatus::Completed,
            }),
            disclosure: None,
        }],
    }
}

#[test]
fn terminal_receipts_prioritize_substance_without_changing_truth() {
    for status in [
        RunItemStatus::Completed,
        RunItemStatus::Partial,
        RunItemStatus::Failed,
        RunItemStatus::Canceled,
    ] {
        let mut value = receipt();
        value.terminal_status = Some(status);
        let original = value.clone();
        assert!(replay_can_lead_with_results(&value));
        let rows = replay_reading_rows(&value, None);
        assert_eq!(
            rows[0].section,
            Some(RunPresentationSectionKindV1::Attention)
        );
        assert_eq!(
            rows[1].section,
            Some(RunPresentationSectionKindV1::Evidence)
        );
        assert_eq!(rows[2].section, Some(RunPresentationSectionKindV1::Work));
        assert_eq!(rows[3].section, Some(RunPresentationSectionKindV1::Outcome));
        assert_eq!(value, original);
    }
}

#[test]
fn live_receipts_keep_progress_and_health_first() {
    for status in [
        None,
        Some(RunItemStatus::Pending),
        Some(RunItemStatus::Running),
    ] {
        let mut value = receipt();
        value.terminal_status = status;
        assert!(!replay_can_lead_with_results(&value));
        assert_eq!(replay_reading_rows(&value, None), value.summary_text_rows());
    }
}

#[test]
fn integrity_and_durability_uncertainty_remain_prominent() {
    let baseline = receipt();
    let mut integrity = baseline.clone();
    integrity.health.integrity = ProjectionHealth::Degraded {
        valid_through_seq: 1,
        reason: "Owned gap".into(),
    };
    let mut durability = baseline;
    durability.health.durability = RunDurabilityHealth::Failed {
        last_durable_seq: 1,
        stage: PersistenceFailureStage::Sync,
        detail: SafeText::operator_visible("Owned sync failure"),
        execution_may_have_occurred: true,
    };
    for value in [integrity, durability] {
        assert!(!replay_can_lead_with_results(&value));
        assert_eq!(replay_reading_rows(&value, None), value.summary_text_rows());
    }
}

#[test]
fn incomplete_progress_remains_prominent() {
    for progress in [
        RunProgressFidelity::Coalesced { omitted: 1 },
        RunProgressFidelity::Saturated {
            omitted_at_least: 1,
        },
    ] {
        let mut value = receipt();
        value.health.progress = progress;
        assert!(!replay_can_lead_with_results(&value));
    }
}

#[test]
fn delivery_uncertainty_remains_prominent() {
    let mut value = receipt();
    value.health.delivery = RunDeliveryHealth::CatchingUp {
        applied_seq: 1,
        durable_seq: 2,
    };
    assert!(!replay_can_lead_with_results(&value));
    value.health.delivery = RunDeliveryHealth::Failed {
        applied_seq: 1,
        stage: RunItemDeliveryFailureStage::ItemSubscriber,
        detail: SafeText::operator_visible("Owned delivery failure"),
    };
    assert!(!replay_can_lead_with_results(&value));
}

#[test]
fn derivative_uncertainty_remains_prominent() {
    let mut value = receipt();
    value.health.derivative_delivery = RunDerivativeDeliveryHealth::CatchingUp {
        applied_seq: 1,
        durable_seq: 2,
    };
    assert!(!replay_can_lead_with_results(&value));
    value.health.derivative_delivery = RunDerivativeDeliveryHealth::Failed {
        applied_seq: 1,
        durable_seq: 2,
        stage: RunItemDeliveryFailureStage::DerivativeSubscriber,
        detail: SafeText::operator_visible("Owned derivative failure"),
    };
    assert!(!replay_can_lead_with_results(&value));
    value.health.derivative_delivery = RunDerivativeDeliveryHealth::Current { through_seq: 2 };
    assert!(replay_can_lead_with_results(&value));
}

fn cells(
    rows: Vec<RunPresentationTextRowV1>,
) -> BTreeMap<RunCellKey, Vec<RunPresentationTextRowV1>> {
    let mut result: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for row in rows {
        result.entry(row.key.clone()).or_default().push(row);
    }
    result
}

#[test]
fn reading_order_preserves_every_cell_row_and_disclosure() {
    let mut value = receipt();
    let mut second = section(
        RunPresentationSectionKindV1::Evidence,
        "Distinct second observation",
    );
    second.cells[0].disclosure = Some(RunCellDisclosureV1 {
        reason: SafeText::operator_visible("Owned omitted detail"),
        omitted_count: Some(3),
        inspect_action: None,
    });
    value.summary[1].cells.extend(second.cells);
    let expected = value.summary_text_rows();
    let rows = replay_reading_rows(&value, None);
    assert_eq!(cells(rows.clone()), cells(expected));
    let text = rows
        .iter()
        .map(|row| row.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.find("Unverified supplied metadata").unwrap()
            < text.find("Distinct second observation").unwrap()
    );
    assert!(text.contains("Owned omitted detail"));
}

#[test]
fn already_rendered_outcome_is_the_only_excluded_cell() {
    let value = receipt();
    let key = &value.summary[0].cells[0].key;
    let expected = value
        .summary_text_rows()
        .into_iter()
        .filter(|row| &row.key != key)
        .collect();
    assert_eq!(
        cells(replay_reading_rows(&value, Some(key))),
        cells(expected)
    );
}
