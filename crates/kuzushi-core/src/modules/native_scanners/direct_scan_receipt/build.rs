use super::*;

impl DirectScanPolicy {
    pub(super) fn engine(&self) -> &'static str {
        match self {
            Self::Iac(_) => "iac-scan",
            Self::CargoAudit => "cargo-audit",
        }
    }

    fn rules(&self) -> Option<Vec<String>> {
        match self {
            Self::Iac(kind) => Some(crate::iac_scan::enabled_rule_ids(*kind)),
            Self::CargoAudit => None,
        }
    }

    fn stage_engine(&self, run: &str, complete: bool) -> ScanStageEngine {
        ScanStageEngine {
            engine: self.engine().into(),
            outcome: if complete {
                ScanEngineStageOutcome::Complete
            } else {
                ScanEngineStageOutcome::Partial
            },
            rule_ids: self.rules(),
            run_ref: Some(run.into()),
            detail: self.detail(complete),
        }
    }

    fn detail(&self, complete: bool) -> Option<String> {
        match self {
            Self::CargoAudit => Some("Selected Cargo.lock only. Advisory policy was not recorded; absence cannot establish reassessment. Nested lockfiles and source reachability were not inspected.".into()),
            Self::Iac(_) if !complete => Some("Inspection or source verification was incomplete. Absence is not reassessment.".into()),
            Self::Iac(_) => None,
        }
    }
}

impl DirectScanReceipt {
    pub(super) fn build(
        mut self,
        run: &str,
        status: RunItemStatus,
        delta: ScanFindingDelta,
        findings: &[Finding],
        output: &Value,
    ) -> Result<PhaseStageReceipt> {
        self.scope.inspected_files = Some(self.inspected_files(output)?);
        let complete = status == RunItemStatus::Completed;
        let engine = self.policy.stage_engine(run, complete);
        let scan = self.scan_data(run, delta, findings, engine);
        Ok(PhaseStageReceipt {
            phase: crate::WorkflowPhase::Scan,
            outcome: if complete {
                PhaseStageOutcome::Completed
            } else {
                PhaseStageOutcome::Partial
            },
            run_refs: vec![run.into()],
            scan: Some(scan),
        })
    }

    fn scan_data(
        self,
        run: &str,
        delta: ScanFindingDelta,
        findings: &[Finding],
        engine: ScanStageEngine,
    ) -> ScanStageData {
        ScanStageData {
            scope: self.scope,
            plan: ScanStagePlan {
                selection: "direct".into(),
                engines: vec![engine.engine.clone()],
            },
            engines: vec![engine],
            finding_delta: delta,
            severity_counts: scan_severity_counts(findings),
            artifact_delta: vec![ScanArtifactDelta {
                run_ref: run.into(),
                path: "findings.json".into(),
            }],
            duration_ms: self
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            cost: None,
            target_snapshot: self.snapshot,
        }
    }

    fn inspected_files(&self, output: &Value) -> Result<std::collections::BTreeSet<String>> {
        match self.policy {
            DirectScanPolicy::CargoAudit => Ok(self.scope.paths.iter().cloned().collect()),
            DirectScanPolicy::Iac(_) => serde_json::from_value(
                output
                    .pointer("/data/inspectedFiles")
                    .cloned()
                    .context("IaC inspected-file membership is unavailable")?,
            )
            .context("Invalid IaC inspected-file membership"),
        }
    }
}
