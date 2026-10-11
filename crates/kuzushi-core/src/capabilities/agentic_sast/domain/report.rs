use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticSastReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<AgenticSastPersistedRun>,
    /// Exact and incomplete cost envelopes use different JSON field names.
    /// Accept the canonical incomplete form when `sast:scan` rehydrates this
    /// report from a normalized subtool result.
    #[serde(alias = "observedCostUsd")]
    pub cost_usd: f64,
    #[serde(default = "default_cost_usd_exact", skip_serializing_if = "is_true")]
    pub cost_usd_exact: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_coverage: Option<AgenticInventoryCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<AgenticScopeReceipt>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub out_of_scope_observations: Vec<Finding>,
}

const fn default_cost_usd_exact() -> bool {
    true
}

const fn is_true(value: &bool) -> bool {
    *value
}

impl AgenticSastReport {
    pub(crate) fn output(&self) -> String {
        let mut lines = vec![self.summary()];
        if let Some(scope) = self.scope_summary() {
            lines.push(scope);
        }
        if let Some(coverage) = &self.inventory_coverage {
            lines.extend(coverage.reading_lines());
        }
        append_persisted_run(&mut lines, self.persisted.as_ref());
        append_top_findings(&mut lines, &self.findings);
        lines.join("\n")
    }

    pub(crate) fn scope_summary(&self) -> Option<String> {
        let scope = self.scope.as_ref()?;
        Some(format!("Accepted scope: {} · {} discovery files · {} inherited context files · {} observations outside discovery retained in the run receipt", scope.name, scope.discovery_files, scope.inherited_context_files, self.out_of_scope_observations.len()))
    }

    pub(crate) fn to_tool_json(&self) -> Value {
        let mut output = crate::module_result::completed_output_result(
            self.summary(),
            self.output(),
            json!(self),
        );
        let observed =
            crate::runtime::RuntimeCost::from_usd(self.cost_usd, "agentic SAST report cost")
                .expect("agentic SAST report cost was checked before construction");
        let cost = if self.cost_usd_exact {
            crate::runtime::RuntimeCostReport::known(observed)
        } else {
            crate::runtime::RuntimeCostReport::incomplete(observed)
        };
        crate::module_result::apply_runtime_cost_report(&mut output, cost);
        output
    }

    fn summary(&self) -> String {
        format!(
            "agentic-sast: {} finding{} under {}",
            self.count,
            if self.count == 1 { "" } else { "s" },
            self.target
        )
    }
}

fn append_persisted_run(lines: &mut Vec<String>, persisted: Option<&AgenticSastPersistedRun>) {
    if let Some(persisted) = persisted {
        lines.push(format!(
            "  Persisted run: {} ({})",
            persisted.run_id, persisted.findings_db
        ));
    }
}

fn append_top_findings(lines: &mut Vec<String>, findings: &[Finding]) {
    if findings.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("Top findings:".to_string());
    lines.extend(crate::findings::presentation::top_finding_lines(
        findings, 10,
    ));
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticSastPersistedRun {
    pub run_id: String,
    pub findings_db: String,
    /// Findings the run's batches created in the store, measured from the
    /// committed rows rather than pre-insertion fingerprints — observations
    /// that dedup-merge into one finding count once.
    #[serde(default)]
    pub findings_added: u64,
    /// Findings the run updated instead of added: committed rows that were
    /// already in the run's ledger before the batch or whose fingerprint the
    /// store had already seen.
    #[serde(default)]
    pub findings_updated: u64,
}
