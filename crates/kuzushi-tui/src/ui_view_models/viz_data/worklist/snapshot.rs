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
