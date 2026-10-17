//! Projection of captured `worklist:rank` JSON into the scene view model.
//!
//! The core `Worklist` is serialize-only because it carries static labels, so
//! this mirror deserializes only the fields the operator surface renders.

use super::{
    dedupe_citations, empty_hint_for, legend_entry, location_label, summary_label,
    WorklistRowModel, WorklistViewModel,
};
use kuzushi_core::capabilities::worklist::{Contributor, ContributorState};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotWorklist {
    #[serde(default)]
    rows: Vec<SnapshotRow>,
    #[serde(default)]
    ranked_total: usize,
    #[serde(default)]
    degraded: Vec<String>,
    #[serde(default)]
    unranked: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    systems_inspection: Option<serde_json::Value>,
    #[serde(default)]
    contributors: BTreeMap<Contributor, ContributorState>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotRow {
    rank: usize,
    path: String,
    #[serde(default)]
    line: Option<u32>,
    #[serde(default)]
    citations: Vec<SnapshotCitation>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotCitation {
    contributor: Contributor,
    #[serde(default)]
    raw: f64,
    raw_display: String,
}

pub(super) fn project_snapshot(value: &serde_json::Value) -> Option<WorklistViewModel> {
    let snapshot: SnapshotWorklist = serde_json::from_value(value.clone()).ok()?;
    let ranked_total = snapshot.ranked_total.max(snapshot.rows.len());
    Some(WorklistViewModel {
        rows: snapshot.rows.iter().map(snapshot_row_model).collect(),
        legend: snapshot
            .contributors
            .iter()
            .map(|(contributor, state)| legend_entry(*contributor, state))
            .collect(),
        inspection: inspection_lines(snapshot.systems_inspection.as_ref(), &snapshot.contributors),
        history_notice: None,
        degraded: snapshot.degraded,
        unranked_count: snapshot.unranked.len(),
        ranked_total,
        empty_hint: empty_hint_for(
            snapshot.rows.is_empty(),
            snapshot.contributors.get(&Contributor::AttackSurface),
        ),
    })
}

fn snapshot_row_model(row: &SnapshotRow) -> WorklistRowModel {
    let display = dedupe_citations(row.citations.iter().map(|citation| {
        (
            citation.contributor.glyph(),
            citation.raw,
            citation.raw_display.clone(),
        )
    }));
    WorklistRowModel {
        rank: row.rank,
        glyphs: display.iter().map(|citation| citation.glyph).collect(),
        location: location_label(&row.path, row.line),
        summary: summary_label(&display),
    }
}

fn inspection_lines(
    receipt: Option<&serde_json::Value>,
    contributors: &BTreeMap<Contributor, ContributorState>,
) -> Vec<String> {
    if matches!(
        contributors.get(&Contributor::SystemsHunt),
        None | Some(ContributorState::NotRequested)
    ) {
        return Vec::new();
    }
    let Some(receipt) = receipt.filter(|value| value["schemaVersion"] == 1) else {
        return vec![
            "Deep inspection limits are unrecorded or unsupported in this saved result.".into(),
        ];
    };
    vec![
        format!(
            "Deep inspection: {} · {} files · {} known source read",
            receipt["status"].as_str().unwrap_or("unrecorded"),
            count(receipt, "indexedFiles"),
            bytes(receipt, "inspectedSourceBytes")
        ),
        format!(
            "Bounds: {} file attempts · {} per file · {} source total",
            count(receipt, "maxSourceFiles"),
            bytes(receipt, "maxFileBytes"),
            bytes(receipt, "maxSourceBytes")
        ),
        format!(
            "Inventory and source ceiling: {} · complete repository coverage is not established",
            bytes(receipt, "maxCombinedInspectedBytes")
        ),
        format!(
            "Omitted source paths: {} · prefix limits: {} · files with evidence limits: {}",
            count(receipt, "omittedSourceFiles"),
            count(receipt, "truncatedSourceFiles"),
            count(receipt, "evidenceLimitedFiles")
        ),
    ]
}

fn count(value: &serde_json::Value, field: &str) -> String {
    value[field]
        .as_u64()
        .map(|n| n.to_string())
        .unwrap_or_else(|| "unrecorded".into())
}

fn bytes(value: &serde_json::Value, field: &str) -> String {
    let Some(n) = value[field].as_u64() else {
        return "unrecorded".into();
    };
    match [("MiB", 1024 * 1024), ("KiB", 1024)]
        .into_iter()
        .find(|(_, scale)| n >= *scale)
    {
        Some((unit, scale)) => format!("{:.1} {unit}", n as f64 / scale as f64),
        None => format!("{n} B"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn current_deep_receipt_reaches_view_with_limits_and_partial_state() {
        let report = json!({"contributors":{"systemsHunt":"live"},"systemsInspection":{"schemaVersion":1,"status":"partial","indexedFiles":3,"inspectedSourceBytes":16384,"maxSourceFiles":2000,"maxFileBytes":16384,"maxSourceBytes":16777216,"maxCombinedInspectedBytes":536870912,"omittedSourceFiles":2,"truncatedSourceFiles":1,"evidenceLimitedFiles":1}});
        let model = project_snapshot(&report).unwrap();
        let text = model.inspection.join("\n");
        for term in [
            "partial",
            "3 files",
            "16.0 KiB",
            "2000 file attempts",
            "16.0 MiB",
            "512.0 MiB",
            "Omitted source paths: 2",
        ] {
            assert!(text.contains(term), "{text}");
        }
    }
    #[test]
    fn legacy_deep_receipts_disclose_unrecorded_limits_instead_of_zero() {
        let model = project_snapshot(&json!({"contributors":{"systemsHunt":"live"}})).unwrap();
        assert!(model.inspection[0].contains("unrecorded"));
        assert!(!model.inspection[0].contains("0 files"));
    }
    #[test]
    fn default_legacy_snapshots_have_no_implied_deep_inspection() {
        let model =
            project_snapshot(&json!({"contributors":{"systemsHunt":"notRequested"}})).unwrap();
        assert!(model.inspection.is_empty());
    }
}
