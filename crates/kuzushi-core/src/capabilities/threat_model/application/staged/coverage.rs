use crate::attack_surface::AttackSurface;
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Deterministic coverage invariant over the surfaces the model was shown:
/// every ground-truth entry point needs its stable id in an explicit
/// deprioritized row, or in both the modeled entry-point inventory and a
/// covering threat. Paths and titles are prose, not identity. The model's
/// own coverage claim is replaced by this check.
pub(crate) struct CoverageReport {
    pub(crate) considered: usize,
    pub(crate) gaps: Vec<CoverageGap>,
}

pub(crate) struct CoverageGap {
    pub(crate) entry_point_id: String,
    pub(crate) entry_point: String,
    pub(crate) kind: String,
    pub(crate) path: String,
}

#[derive(Default)]
struct CoverageIndex {
    modeled_ids: BTreeSet<String>,
    threatened_ids: BTreeSet<String>,
    deprioritized_ids: BTreeSet<String>,
}

impl CoverageReport {
    pub(crate) fn covered(&self) -> usize {
        self.considered.saturating_sub(self.gaps.len())
    }

    pub(crate) fn invariant_satisfied(&self) -> bool {
        self.gaps.is_empty()
    }
}

pub(crate) fn check_coverage(document: &Value, surfaces: &[AttackSurface]) -> CoverageReport {
    let index = coverage_index(document);
    let gaps = surfaces
        .iter()
        .filter(|surface| !surface_is_covered(&index, surface))
        .map(coverage_gap)
        .collect();
    CoverageReport {
        considered: surfaces.len(),
        gaps,
    }
}

fn coverage_gap(surface: &AttackSurface) -> CoverageGap {
    CoverageGap {
        entry_point_id: surface.id.clone(),
        entry_point: surface.title.clone(),
        kind: surface.kind.as_str().to_string(),
        path: surface.path.clone(),
    }
}

fn coverage_index(document: &Value) -> CoverageIndex {
    CoverageIndex {
        modeled_ids: row_ids(document.pointer("/attackSurface/entryPoints"), "id"),
        threatened_ids: threat_entry_point_ids(document.pointer("/threats")),
        deprioritized_ids: deprioritized_entry_point_ids(document.pointer("/deprioritized")),
    }
}

fn row_ids(rows: Option<&Value>, field: &str) -> BTreeSet<String> {
    rows.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get(field).and_then(Value::as_str))
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn threat_entry_point_ids(rows: Option<&Value>) -> BTreeSet<String> {
    let mut ids = row_ids(rows, "entryPointId");
    for row in rows.and_then(Value::as_array).into_iter().flatten() {
        ids.extend(
            row.get("entryPointIds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|id| !id.trim().is_empty())
                .map(str::to_string),
        );
    }
    ids
}

fn deprioritized_entry_point_ids(rows: Option<&Value>) -> BTreeSet<String> {
    rows.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|row| row.get("parkedBy").and_then(Value::as_str) != Some("system"))
        .filter(|row| {
            row.get("reason")
                .and_then(Value::as_str)
                .is_some_and(|reason| !reason.trim().is_empty())
        })
        .filter_map(|row| {
            row.get("entryPointId")
                .or_else(|| row.get("entryPoint"))
                .and_then(Value::as_str)
        })
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn surface_is_covered(index: &CoverageIndex, surface: &AttackSurface) -> bool {
    index.deprioritized_ids.contains(&surface.id)
        || (index.modeled_ids.contains(&surface.id) && index.threatened_ids.contains(&surface.id))
}

pub(crate) fn apply_coverage(
    document: &mut Value,
    report: &CoverageReport,
    method: &str,
    parked_by_system: usize,
) {
    if !document.is_object() {
        return;
    }
    document["coverage"] = coverage_json(report, method, parked_by_system);
}

/// `entryPointsCovered` and `invariantSatisfied` are the pre-park measurement
/// of what the model itself accounted for. `parkedBySystem` records how many
/// gaps the system subsequently made visible in `deprioritized`; it is
/// deliberately a separate field so parking never reads as coverage.
pub(crate) fn coverage_json(
    report: &CoverageReport,
    gap_fill_method: &str,
    parked_by_system: usize,
) -> Value {
    json!({
        "entryPointsConsidered": report.considered,
        "entryPointsCovered": report.covered(),
        "invariantSatisfied": report.invariant_satisfied(),
        "gapFillMethod": gap_fill_method,
        "gaps": report.gaps.iter().map(gap_json).collect::<Vec<_>>(),
        "parkedBySystem": parked_by_system,
    })
}

fn gap_json(gap: &CoverageGap) -> Value {
    json!({
        "entryPointId": gap.entry_point_id,
        "entryPoint": gap.entry_point,
        "kind": gap.kind,
        "path": gap.path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack_surface::{AttackSurfaceKind, AttackSurfaceRisk};

    fn surface(path: &str, title: &str) -> AttackSurface {
        AttackSurface {
            id: format!("surface-{path}"),
            kind: AttackSurfaceKind::HttpRoute,
            path: path.to_string(),
            line: Some(10),
            language: "javascript".to_string(),
            framework: None,
            title: title.to_string(),
            evidence: "app.get(...)".to_string(),
            method: None,
            route: None,
            boundary: None,
            risk: AttackSurfaceRisk::default(),
            metadata: Value::Null,
        }
    }

    #[test]
    fn coverage_requires_stable_ids_and_a_modeled_entry_for_threats() {
        let upload = surface("src/upload.ts", "POST /upload");
        let health = surface("src/health.ts", "GET /health");
        let document = json!({
            "attackSurface": {"entryPoints": [{"id": upload.id}]},
            "threats": [{
                "title": "RCE via upload",
                "entryPointIds": [upload.id],
                "affectedFiles": [{"filePath": "src/upload.ts"}]
            }],
            "deprioritized": [{
                "entryPointId": health.id,
                "entryPoint": health.title,
                "reason": "no data crosses"
            }],
        });
        let surfaces = vec![upload, health];
        let report = check_coverage(&document, &surfaces);
        assert!(report.invariant_satisfied(), "both surfaces are covered");
        assert_eq!(report.covered(), 2);
    }

    #[test]
    fn path_or_title_prose_cannot_forge_stable_id_coverage() {
        let surface = surface("src/upload.ts", "POST /upload");
        let document = json!({
            "threats": [{
                "title": "POST /upload",
                "affectedFiles": [{"filePath": "src/upload.ts"}]
            }],
            "deprioritized": [{"entryPoint": "POST /upload", "reason": "prose only"}],
        });

        let report = check_coverage(&document, &[surface]);

        assert_eq!(report.gaps.len(), 1);
    }

    #[test]
    fn threat_id_without_matching_attack_surface_row_is_not_linked_coverage() {
        let surface = surface("src/upload.ts", "POST /upload");
        let document = json!({"threats": [{"entryPointIds": [surface.id]}]});

        let report = check_coverage(&document, &[surface]);

        assert_eq!(report.gaps.len(), 1);
    }

    #[test]
    fn deprioritization_without_a_reason_is_not_coverage() {
        let surface = surface("src/upload.ts", "POST /upload");
        let document = json!({
            "deprioritized": [{"entryPointId": surface.id, "reason": "  "}]
        });

        let report = check_coverage(&document, &[surface]);

        assert_eq!(report.gaps.len(), 1);
    }

    #[test]
    fn system_parking_never_becomes_coverage_on_a_later_check() {
        let surface = surface("src/upload.ts", "POST /upload");
        let document = json!({
            "deprioritized": [{
                "entryPointId": surface.id,
                "reason": "unaccounted: system bookkeeping",
                "parkedBy": "system"
            }]
        });

        let report = check_coverage(&document, &[surface]);

        assert_eq!(report.gaps.len(), 1);
        assert!(!report.invariant_satisfied());
    }

    #[test]
    fn uncovered_surface_becomes_a_gap_and_fails_the_invariant() {
        let document = json!({
            "threats": [{"title": "unrelated", "affectedFiles": [{"filePath": "src/other.ts"}]}],
        });
        let surfaces = vec![surface("src/admin.ts", "GET /admin/debug")];
        let report = check_coverage(&document, &surfaces);
        assert!(!report.invariant_satisfied());
        assert_eq!(report.gaps.len(), 1);
        assert_eq!(report.gaps[0].path, "src/admin.ts");
    }

    #[test]
    fn apply_coverage_replaces_model_claimed_coverage_with_measured_truth() {
        let mut document = json!({
            "threats": [],
            "coverage": {"entryPointsCovered": 999, "invariantSatisfied": true},
        });
        let surfaces = vec![surface("src/admin.ts", "GET /admin/debug")];
        let report = check_coverage(&document, &surfaces);
        apply_coverage(&mut document, &report, "unresolved", 1);
        assert_eq!(document["coverage"]["entryPointsConsidered"], json!(1));
        assert_eq!(document["coverage"]["entryPointsCovered"], json!(0));
        assert_eq!(document["coverage"]["invariantSatisfied"], json!(false));
        assert_eq!(document["coverage"]["gapFillMethod"], json!("unresolved"));
        assert_eq!(
            document["coverage"]["gaps"][0]["path"],
            json!("src/admin.ts")
        );
        assert_eq!(
            document["coverage"]["gaps"][0]["entryPointId"],
            json!("surface-src/admin.ts")
        );
        assert_eq!(document["coverage"]["parkedBySystem"], json!(1));
    }

    #[test]
    fn parking_never_promotes_measured_coverage() {
        let mut document = json!({"threats": []});
        let surfaces = vec![surface("src/admin.ts", "GET /admin/debug")];
        let report = check_coverage(&document, &surfaces);
        apply_coverage(&mut document, &report, "unresolved", 1);
        assert_eq!(
            document["coverage"]["invariantSatisfied"],
            json!(false),
            "a system-parked gap is bookkeeping, never model coverage"
        );
        assert_eq!(document["coverage"]["entryPointsCovered"], json!(0));
    }
}
