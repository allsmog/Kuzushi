//! Reconciliation of the model's proposal against system-owned ground truth.
//!
//! A build has two provenance classes: facts the system measured, and
//! judgments the model proposed. This module owns the measured half so that
//! the result envelope can refuse to report `completed` for a document that
//! silently dropped ground-truth surfaces or emitted anchor-free rows.
//!
//! Coverage numbers here are the pre-park measurement. Parking (see
//! `park_unaccounted`) makes dropped rows visible; it never forges coverage.

use super::*;

const GROUNDED_ENTRY_POINT_FIELDS: &[&str] = &[
    "id",
    "name",
    "location",
    "kind",
    "path",
    "line",
    "language",
    "framework",
    "title",
    "evidence",
    "method",
    "route",
    "boundary",
    "risk",
    "metadata",
];

/// Replace every deterministic field on a model-emitted grounded row with
/// the exact source surface. Model-owned links and explanations survive.
pub(crate) fn restore_grounded_entry_point_facts(
    document: &mut Value,
    surfaces: &[crate::attack_surface::AttackSurface],
    catalog_surfaces: &[crate::attack_surface::AttackSurface],
) -> Result<()> {
    let by_id = surfaces
        .iter()
        .chain(catalog_surfaces)
        .map(|surface| (surface.id.as_str(), surface))
        .collect::<BTreeMap<_, _>>();
    let Some(rows) = document
        .pointer_mut("/attackSurface/entryPoints")
        .and_then(Value::as_array_mut)
    else {
        return Ok(());
    };
    for row in rows {
        let Some(surface) = row
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| by_id.get(id))
        else {
            continue;
        };
        restore_grounded_row(row, surface)?;
    }
    Ok(())
}

fn restore_grounded_row(
    row: &mut Value,
    surface: &crate::attack_surface::AttackSurface,
) -> Result<()> {
    let fields = row
        .as_object_mut()
        .context("grounded attack-surface row is not an object")?;
    for field in GROUNDED_ENTRY_POINT_FIELDS {
        fields.remove(*field);
    }
    let source = serde_json::to_value(surface)?;
    fields.extend(
        source
            .as_object()
            .context("serialized attack surface is not an object")?
            .clone(),
    );
    fields.insert("name".to_string(), json!(surface.title));
    fields.insert("location".to_string(), grounded_location(surface));
    Ok(())
}

fn grounded_location(surface: &crate::attack_surface::AttackSurface) -> Value {
    surface.line.map_or_else(
        || json!(surface.path),
        |line| json!(format!("{}:{line}", surface.path)),
    )
}

/// Measured facts about how one build's document reconciles against the
/// ground truth it was shown. Built by each pipeline after its final coverage
/// check and consumed by the result envelope.
pub(crate) struct BuildReconciliation {
    pub(crate) considered: usize,
    pub(crate) covered: usize,
    pub(crate) invariant_satisfied: bool,
    pub(crate) parked_by_system: usize,
    pub(crate) anchor_free_entry_points: usize,
    pub(crate) entry_point_total: usize,
    pub(crate) scope_label: &'static str,
}

impl BuildReconciliation {
    pub(crate) fn from_report(
        report: &CoverageReport,
        parked_by_system: usize,
        scope_label: &'static str,
        document: &Value,
    ) -> Self {
        let (anchor_free_entry_points, entry_point_total) =
            count_anchor_free_entry_points(document);
        Self {
            considered: report.considered,
            covered: report.covered(),
            invariant_satisfied: report.invariant_satisfied(),
            parked_by_system,
            anchor_free_entry_points,
            entry_point_total,
            scope_label,
        }
    }

    /// Operator-facing warnings, one per violated axis. Empty exactly when the
    /// build accounted for every ground-truth surface and anchored every entry
    /// point it emitted — the envelope treats emptiness as the clean signal, so
    /// this is the single definition of a clean build.
    pub(crate) fn warning_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.invariant_satisfied {
            lines.push(format!(
                "coverage: {}/{} {} accounted; {} parked by system into deprioritized",
                self.covered, self.considered, self.scope_label, self.parked_by_system
            ));
        }
        if self.anchor_free_entry_points > 0 {
            lines.push(format!(
                "attack surface: {}/{} entry points carry no path or evidence anchor",
                self.anchor_free_entry_points, self.entry_point_total
            ));
        }
        lines
    }
}

/// Count `attackSurface.entryPoints` rows that carry neither a `path` nor an
/// `evidence` anchor. Such rows name a surface without locating it, which is
/// the property that makes the row actionable. Returns `(anchor_free, total)`.
pub(crate) fn count_anchor_free_entry_points(document: &Value) -> (usize, usize) {
    let Some(rows) = document
        .pointer("/attackSurface/entryPoints")
        .and_then(Value::as_array)
    else {
        return (0, 0);
    };
    let anchor_free = rows.iter().filter(|row| !row_is_anchored(row)).count();
    (anchor_free, rows.len())
}

/// Append one `deprioritized` row per unaccounted ground-truth gap and return
/// how many were parked.
///
/// This makes the partition invariant structural: a ground-truth surface the
/// model neither threatened nor deprioritized can no longer vanish silently.
/// Parked rows are bookkeeping, not coverage — the persisted `coverage` object
/// keeps the pre-park measurement so parking can never forge accountedness.
pub(crate) fn park_unaccounted(document: &mut Value, gaps: &[CoverageGap]) -> usize {
    if gaps.is_empty() {
        return 0;
    }
    if !document.get("deprioritized").is_some_and(Value::is_array) {
        document["deprioritized"] = json!([]);
    }
    if let Some(existing) = document
        .get_mut("deprioritized")
        .and_then(Value::as_array_mut)
    {
        let parked_ids = existing_system_parked_ids(existing);
        let rows: Vec<Value> = gaps
            .iter()
            .filter(|gap| !parked_ids.contains(&gap.entry_point_id))
            .map(parked_row)
            .collect();
        let parked = rows.len();
        existing.extend(rows);
        return parked;
    }
    0
}

fn existing_system_parked_ids(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .filter(|row| row.get("parkedBy").and_then(Value::as_str) == Some("system"))
        .filter_map(|row| row.get("entryPointId").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn parked_row(gap: &CoverageGap) -> Value {
    json!({
        "entryPointId": gap.entry_point_id,
        "entryPoint": gap.entry_point,
        "path": gap.path,
        "reason": "unaccounted: model emitted neither a threat nor a deprioritized row for this ground-truth surface",
        "parkedBy": "system",
    })
}

fn row_is_anchored(row: &Value) -> bool {
    has_non_empty_text(row.get("path")) || has_non_empty_text(row.get("evidence"))
}

fn has_non_empty_text(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(text)) => !text.trim().is_empty(),
        Some(Value::Array(items)) => items.iter().any(|item| has_non_empty_text(Some(item))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_surface::{AttackSurface, AttackSurfaceKind, AttackSurfaceRisk};
    use serde_json::json;

    fn grounded_surface() -> AttackSurface {
        AttackSurface {
            id: "AS-grounded".to_string(),
            kind: AttackSurfaceKind::RpcHandler,
            path: "src/commands.rs".to_string(),
            line: Some(42),
            language: "Rust".to_string(),
            framework: None,
            title: "open_project".to_string(),
            evidence: "#[tauri::command]".to_string(),
            method: None,
            route: None,
            boundary: Some("desktop-ipc".to_string()),
            risk: AttackSurfaceRisk {
                rank: 3,
                score: 81,
                tier: "high".to_string(),
                reasons: vec!["privileged command".to_string()],
            },
            metadata: json!({"command": "open_project"}),
        }
    }

    fn report(considered: usize, gaps: usize) -> CoverageReport {
        CoverageReport {
            considered,
            gaps: (0..gaps)
                .map(|index| CoverageGap {
                    entry_point_id: format!("surface-{index}"),
                    entry_point: format!("surface {index}"),
                    kind: "http_route".to_string(),
                    path: format!("src/file{index}.rs"),
                })
                .collect(),
        }
    }

    fn anchored_document() -> Value {
        json!({"attackSurface": {"entryPoints": [{"path": "src/main.rs"}]}})
    }

    #[test]
    fn clean_reconciliation_emits_no_warnings() {
        let reconciliation = BuildReconciliation::from_report(
            &report(40, 0),
            0,
            "grounded surfaces",
            &anchored_document(),
        );
        assert!(reconciliation.warning_lines().is_empty());
    }

    #[test]
    fn unaccounted_surfaces_report_measured_counts() {
        let reconciliation = BuildReconciliation::from_report(
            &report(40, 19),
            19,
            "grounded surfaces",
            &anchored_document(),
        );
        assert_eq!(
            reconciliation.warning_lines(),
            vec![
                "coverage: 21/40 grounded surfaces accounted; 19 parked by system into deprioritized"
                    .to_string()
            ]
        );
    }

    #[test]
    fn anchor_free_entry_points_are_counted_and_warned() {
        let document = json!({"attackSurface": {"entryPoints": [
            {"name": "bucket", "path": null},
            {"name": "located", "path": "src/main.rs"},
            {"name": "evidenced", "evidence": ["src/lib.rs:4"]},
            {"name": "blank", "path": "   ", "evidence": []},
        ]}});
        assert_eq!(count_anchor_free_entry_points(&document), (2, 4));
        let reconciliation =
            BuildReconciliation::from_report(&report(1, 0), 0, "grounded surfaces", &document);
        assert_eq!(
            reconciliation.warning_lines(),
            vec!["attack surface: 2/4 entry points carry no path or evidence anchor".to_string()]
        );
    }

    #[test]
    fn absent_attack_surface_counts_zero() {
        assert_eq!(count_anchor_free_entry_points(&json!({})), (0, 0));
    }

    #[test]
    fn parking_creates_the_array_and_marks_the_parker() {
        let mut document = json!({"threats": []});
        let parked = park_unaccounted(&mut document, &report(2, 2).gaps);
        assert_eq!(parked, 2);
        let rows = document["deprioritized"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["parkedBy"], json!("system"));
        assert_eq!(rows[0]["path"], json!("src/file0.rs"));
        assert_eq!(rows[0]["entryPointId"], json!("surface-0"));
        assert_eq!(rows[0]["entryPoint"], json!("surface 0"));
        assert!(rows[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with("unaccounted:")));
    }

    #[test]
    fn parking_appends_to_existing_deprioritized_rows() {
        let mut document = json!({"deprioritized": [{"entryPoint": "model row"}]});
        assert_eq!(park_unaccounted(&mut document, &report(1, 1).gaps), 1);
        let rows = document["deprioritized"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["entryPoint"], json!("model row"));
        assert!(rows[0].get("parkedBy").is_none());
    }

    #[test]
    fn repeated_parking_does_not_duplicate_system_rows() {
        let mut document = json!({"threats": []});
        let gaps = report(2, 2).gaps;

        assert_eq!(park_unaccounted(&mut document, &gaps), 2);
        assert_eq!(park_unaccounted(&mut document, &gaps), 0);
        assert_eq!(document["deprioritized"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn parking_nothing_leaves_the_document_untouched() {
        let mut document = json!({"threats": []});
        assert_eq!(park_unaccounted(&mut document, &[]), 0);
        assert!(document.get("deprioritized").is_none());
    }

    #[test]
    fn unselected_catalog_facts_replace_model_prose_without_erasing_model_links() {
        let surface = grounded_surface();
        let mut document = json!({"attackSurface": {"entryPoints": [{
            "id": surface.id,
            "targetElementIds": ["desktop-shell"],
            "trustZone": "local-user",
            "description": "model judgment",
            "name": "invented",
            "kind": "http_route",
            "path": "invented.rs",
            "line": 999,
            "method": "POST",
            "evidence": "unsupported prose",
            "risk": {"score": 100}
        }]}});

        restore_grounded_entry_point_facts(&mut document, &[], &[surface]).unwrap();

        let row = &document["attackSurface"]["entryPoints"][0];
        assert_eq!(row["name"], json!("open_project"));
        assert_eq!(row["kind"], json!("rpc_handler"));
        assert_eq!(row["path"], json!("src/commands.rs"));
        assert_eq!(row["line"], json!(42));
        assert_eq!(row["evidence"], json!("#[tauri::command]"));
        assert_eq!(row["risk"]["score"], json!(81));
        assert!(row.get("method").is_none());
        assert_eq!(row["targetElementIds"], json!(["desktop-shell"]));
        assert_eq!(row["description"], json!("model judgment"));
        assert_eq!(row["trustZone"], json!("local-user"));
    }
}
