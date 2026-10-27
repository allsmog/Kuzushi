use super::cyclonedx::cyclonedx_export;
use super::export_graph::ExportGraph;
use super::spdx::spdx_export;
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(super) fn ecosystem_counts(components: &[SbomComponent]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for component in components {
        *counts.entry(component.ecosystem.clone()).or_insert(0) += 1;
    }
    counts
}

pub(super) fn component_sort_key(component: &SbomComponent) -> (String, String, String, String) {
    (
        component.ecosystem.clone(),
        component.manifest_path.clone(),
        component.scope.clone(),
        component.name.clone(),
    )
}

impl SbomScanReport {
    pub fn output(&self) -> String {
        format!(
            "sbom-scan: {} component{} across {} manifest{} and {} lockfile{} under {}",
            self.components.len(),
            plural_suffix(self.components.len()),
            self.manifests_scanned,
            plural_suffix(self.manifests_scanned),
            self.lockfiles.len(),
            plural_suffix(self.lockfiles.len()),
            self.target
        )
    }

    pub fn to_tool_json(&self) -> Value {
        let graph = ExportGraph::new(self);
        let spdx = spdx_export(self, &graph);
        let cyclonedx = cyclonedx_export(self, &graph);
        crate::scan::completed_scan_tool_json(
            export_summary(self, graph.omitted_count()),
            json!({
                "target": self.target,
                "manifestsScanned": self.manifests_scanned,
                "lockfileCount": self.lockfiles.len(),
                "lockfiles": self.lockfiles,
                "dependencyCount": self.dependencies.len(),
                "dependencies": self.dependencies,
                "componentCount": self.components.len(),
                "components": self.components,
                "byEcosystem": self.by_ecosystem,
                "cycloneDx": cyclonedx.document,
                "cycloneDxExport": cyclonedx.diagnostics,
                "spdx": spdx.document,
                "spdxExport": spdx.diagnostics,
            }),
        )
    }
}

fn export_summary(report: &SbomScanReport, omitted: usize) -> String {
    if omitted == 0 {
        return report.output();
    }
    format!(
        "{}\nSPDX and CycloneDX omitted {omitted} dependency relationship{} with missing or ambiguous endpoints; raw dependency links remain available.",
        report.output(), plural_suffix(omitted)
    )
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}
