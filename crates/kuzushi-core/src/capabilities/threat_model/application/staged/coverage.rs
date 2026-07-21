use crate::attack_surface::AttackSurface;
use serde_json::{json, Value};

/// Deterministic coverage invariant over the surfaces the model was shown:
/// every ground-truth entry point needs at least one threat or an explicit
/// deprioritized row. The model's own coverage claim is replaced by this
/// check — coverage is measured, never self-reported.
pub(crate) struct CoverageReport {
    pub(crate) considered: usize,
    pub(crate) gaps: Vec<CoverageGap>,
}

pub(crate) struct CoverageGap {
    pub(crate) entry_point: String,
    pub(crate) path: String,
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
    let haystacks = coverage_haystacks(document);
    let gaps = surfaces
        .iter()
        .filter(|surface| !surface_is_covered(&haystacks, surface))
        .map(coverage_gap)
        .collect();
    CoverageReport {
        considered: surfaces.len(),
        gaps,
    }
}

fn coverage_gap(surface: &AttackSurface) -> CoverageGap {
    CoverageGap {
        entry_point: surface.title.clone(),
        path: surface.path.clone(),
    }
}

fn coverage_haystacks(document: &Value) -> Vec<String> {
    let mut haystacks = collect_row_texts(document.pointer("/threats"));
    haystacks.extend(collect_row_texts(document.pointer("/deprioritized")));
    haystacks
}

fn collect_row_texts(rows: Option<&Value>) -> Vec<String> {
    rows.and_then(Value::as_array)
        .map(|rows| rows.iter().map(row_text).collect())
        .unwrap_or_default()
}

fn row_text(row: &Value) -> String {
    serde_json::to_string(row).unwrap_or_default()
}

fn surface_is_covered(haystacks: &[String], surface: &AttackSurface) -> bool {
    haystacks
        .iter()
        .any(|haystack| haystack.contains(&surface.path) || haystack.contains(&surface.title))
}

pub(crate) fn apply_coverage(document: &mut Value, report: &CoverageReport, method: &str) {
    if !document.is_object() {
        return;
    }
    document["coverage"] = coverage_json(report, method);
}

pub(crate) fn coverage_json(report: &CoverageReport, gap_fill_method: &str) -> Value {
    json!({
        "entryPointsConsidered": report.considered,
        "entryPointsCovered": report.covered(),
        "invariantSatisfied": report.invariant_satisfied(),
        "gapFillMethod": gap_fill_method,
        "gaps": report.gaps.iter().map(gap_json).collect::<Vec<_>>(),
    })
}

fn gap_json(gap: &CoverageGap) -> Value {
    json!({
        "entryPoint": gap.entry_point,
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
    fn covered_surface_via_affected_files_and_deprioritized_row() {
        let document = json!({
            "threats": [{"title": "RCE via upload", "affectedFiles": [{"filePath": "src/upload.ts"}]}],
            "deprioritized": [{"entryPoint": "GET /health", "reason": "no data crosses"}],
        });
        let surfaces = vec![
            surface("src/upload.ts", "POST /upload"),
            surface("src/health.ts", "GET /health"),
        ];
        let report = check_coverage(&document, &surfaces);
        assert!(report.invariant_satisfied(), "both surfaces are covered");
        assert_eq!(report.covered(), 2);
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
        apply_coverage(&mut document, &report, "unresolved");
        assert_eq!(document["coverage"]["entryPointsConsidered"], json!(1));
        assert_eq!(document["coverage"]["entryPointsCovered"], json!(0));
        assert_eq!(document["coverage"]["invariantSatisfied"], json!(false));
        assert_eq!(document["coverage"]["gapFillMethod"], json!("unresolved"));
        assert_eq!(document["coverage"]["gaps"][0]["path"], json!("src/admin.ts"));
    }
}
