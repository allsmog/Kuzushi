use super::*;
use serde_json::{json, Value};

impl LicenseScanReport {
    pub fn output(&self) -> String {
        format!(
            "license-scan: {} finding{} across {} manifest{} under {}",
            self.findings.len(),
            plural_suffix(self.findings.len()),
            self.manifests_scanned,
            plural_suffix(self.manifests_scanned),
            self.target
        )
    }

    pub fn to_tool_json(&self) -> Value {
        crate::scan::completed_scan_tool_json(
            self.output(),
            json!({
                "count": self.findings.len(),
                "findings": self.findings,
                "manifestsScanned": self.manifests_scanned,
                "target": self.target,
            }),
        )
    }
}

fn plural_suffix(count: usize) -> &'static str {
    (count != 1).then_some("s").unwrap_or("")
}
