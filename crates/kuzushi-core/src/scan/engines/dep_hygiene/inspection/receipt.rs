use super::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HygieneInspectionReceipt {
    pub regular_files_enumerated: usize,
    pub manifests_discovered: usize,
    pub manifests_attempted: usize,
    pub manifests_inspected: usize,
    pub content_bytes_reserved: u64,
    pub gaps: Vec<String>,
}

impl HygieneInspectionReceipt {
    fn to_json(&self) -> Value {
        serde_json::json!({
            "regularFilesEnumerated": self.regular_files_enumerated,
            "manifestsDiscovered": self.manifests_discovered,
            "manifestsAttempted": self.manifests_attempted,
            "manifestsInspected": self.manifests_inspected,
            "contentBytesReserved": self.content_bytes_reserved,
            "gaps": self.gaps,
        })
    }
}

pub(crate) struct HygieneInspection {
    pub report: DepHygieneReport,
    pub receipt: HygieneInspectionReceipt,
}

impl HygieneInspection {
    pub(super) fn new(target: &Path, files: usize, manifests: usize) -> Self {
        Self {
            report: DepHygieneReport {
                target: target.display().to_string(),
                count: 0,
                findings: Vec::new(),
            },
            receipt: HygieneInspectionReceipt {
                regular_files_enumerated: files,
                manifests_discovered: manifests,
                manifests_attempted: 0,
                manifests_inspected: 0,
                content_bytes_reserved: 0,
                gaps: Vec::new(),
            },
        }
    }

    pub(crate) fn ensure_complete(&self) -> Result<()> {
        anyhow::ensure!(
            self.receipt.gaps.is_empty(),
            "dep-hygiene: incomplete inspection: {}",
            self.receipt.gaps.join("; ")
        );
        Ok(())
    }

    pub(crate) fn to_tool_json(&self) -> Value {
        let mut result = self.report.to_tool_json();
        result["data"]["inspection"] = self.receipt.to_json();
        result["data"]["inspection"]["limits"] = json_limits();
        result["data"]["inspection"]["exclusions"] = serde_json::json!([
            "symlinks",
            ".git",
            ".kuzushi",
            "node_modules",
            "vendor",
            "target",
            "dist",
            "build",
            ".venv",
            "venv"
        ]);
        let output = self.output();
        result["output"] = serde_json::json!(output);
        result["summary"] = result["output"].clone();
        if !self.receipt.gaps.is_empty() {
            result["status"] = serde_json::json!("partial");
            result["warnings"] = serde_json::json!(self.receipt.gaps);
        }
        result
    }

    fn output(&self) -> String {
        let mut lines = vec![
            self.signal_text(),
            format!(
                "Inspection: {} / {} manifests inspected · {} content bytes reserved",
                self.receipt.manifests_inspected,
                self.receipt.manifests_discovered,
                self.receipt.content_bytes_reserved
            ),
        ];
        lines.push("Checks: dependency version-policy signals requiring owner review.".into());
        lines.push("Limits: 100000 entries, 50000 files, 64 levels, 16 MiB per manifest, 512 MiB shared reads.".into());
        lines.push("Excludes symlinks, repository state, dependencies and build output. Heuristic inspection does not establish full repository coverage.".into());
        append_gaps(&mut lines, &self.receipt.gaps);
        lines.join("\n")
    }

    fn signal_text(&self) -> String {
        if self.report.count == 0 && !self.receipt.gaps.is_empty() {
            return "dep-hygiene: 0 policy signals from inspected manifests".into();
        }
        self.report.output()
    }
}

fn json_limits() -> Value {
    serde_json::json!({"maxEntries":100000,"maxFiles":50000,"maxDepth":64,"maxManifestBytes":reads::MAX_MANIFEST_BYTES,"maxReadBytes":reads::MAX_READ_BYTES})
}

fn append_gaps(lines: &mut Vec<String>, gaps: &[String]) {
    if gaps.is_empty() {
        return;
    }
    lines.push(format!(
        "Incomplete inspection: {} gap(s); observed signals are retained.",
        gaps.len()
    ));
    lines.extend(gaps.iter().take(8).map(|gap| format!("  {gap}")));
    if gaps.len() > 8 {
        lines.push("Further gaps remain in the structured inspection receipt.".into());
    }
}

#[cfg(test)]
mod tests;
