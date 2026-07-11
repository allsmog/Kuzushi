use super::cyclonedx::cyclonedx_document;
use super::spdx::spdx_document;
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
        crate::scan::completed_scan_tool_json(
            self.output(),
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
                "cycloneDx": cyclonedx_document(self),
                "spdx": spdx_document(self),
            }),
        )
    }
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}
