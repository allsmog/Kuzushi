//! Per-finding classification and the retirement (coverage) proof.

use super::super::super::persistence::{CompletedScanScope, FindingStore};
use super::{ComparedFinding, ScanComparisonClass, ScanFindingSignature, ScanUncertainMatch};
use crate::findings::{
    all_components_deterministic, is_deterministic_scanner, tool_components, Finding,
};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};

/// What the compare run can honestly prove about findings it did NOT observe.
pub(super) struct RetirementCoverage {
    pub(super) base_status: String,
    pub(super) compare_status: String,
    base_target: Option<String>,
    scope: Option<CompletedScanScope>,
    tools: BTreeSet<String>,
}

impl RetirementCoverage {
    pub(super) fn load(store: &FindingStore, base_run_id: &str, compare_run_id: &str) -> Result<Self> {
        // Both ids must name runs this target actually recorded; an unrecorded
        // id would otherwise read as an empty side and forge a plausible diff.
        let base_status = require_recorded_run_status(store, base_run_id, "base")?;
        let compare_status = require_recorded_run_status(store, compare_run_id, "compare")?;
        let scope = store.completed_scan_scope(compare_run_id)?;
        let tools = match &scope {
            Some(scope) => store.engines_proven_by_run(compare_run_id, scope)?,
            // Unknown scope blocks retirement in `provable_scope` before the
            // engine evidence is ever consulted, so loading it would be dead
            // work dressed up as a meaningful input.
            None => BTreeSet::new(),
        };
        Ok(Self {
            base_status,
            compare_status,
            base_target: store.run_target(base_run_id)?,
            scope,
            tools,
        })
    }

    /// `None` when the compare run honestly retires this finding; otherwise
    /// the specific missing proof, reported verbatim as the reason.
    fn retirement_block(&self, finding: &Finding) -> Option<String> {
        match self.provable_scope() {
            Err(reason) => Some(reason),
            Ok(scope) => engine_block(finding, scope, &self.tools),
        }
    }

    /// The compare run's recorded scope, or the run-level reason the compare
    /// run proves nothing about absent findings.
    fn provable_scope(&self) -> std::result::Result<&CompletedScanScope, String> {
        if self.compare_status != "completed" {
            return Err(format!("compare run status is {}", self.compare_status));
        }
        let Some(scope) = &self.scope else {
            return Err(
                "compare run scope is unknown (run artifacts missing or unreadable)".to_string(),
            );
        };
        if self.base_target.as_deref() != Some(scope.target()) {
            return Err("compare run scanned a different target".to_string());
        }
        Ok(scope)
    }
}

/// The engine-level proof the compare run must carry to retire one finding. A
/// merged tool (`"codeql,semgrep"`) is only retirable when EVERY component
/// engine is deterministic and evidenced; the reason names the first that isn't.
fn engine_block(
    finding: &Finding,
    scope: &CompletedScanScope,
    tools: &BTreeSet<String>,
) -> Option<String> {
    deterministic_block(&finding.tool)
        .or_else(|| evidence_block(&finding.tool, tools))
        .or_else(|| path_block(finding, scope))
}

fn deterministic_block(tool: &str) -> Option<String> {
    if all_components_deterministic(tool) {
        return None;
    }
    let Some(named) = tool_components(tool).find(|component| !is_deterministic_scanner(component))
    else {
        // Every component passed individually, so the block came from a tool
        // naming no engine at all — say that instead of printing "".
        return Some("finding names no engine; absence is not proof".to_string());
    };
    Some(format!(
        "{named} is not a deterministic engine; absence is not proof"
    ))
}

fn evidence_block(tool: &str, tools: &BTreeSet<String>) -> Option<String> {
    let missing = tool_components(tool).find(|component| !tools.contains(*component))?;
    Some(format!(
        "no run evidence for engine {missing} in the compare scan"
    ))
}

fn path_block(finding: &Finding, scope: &CompletedScanScope) -> Option<String> {
    (!scope.covers_file(&finding.file_path))
        .then(|| "finding path is outside the compare scan's paths".to_string())
}

/// A run id with no `run_states` row is an operator mistake, not an empty side.
fn require_recorded_run_status(store: &FindingStore, run_id: &str, role: &str) -> Result<String> {
    store.run_status(run_id)?.with_context(|| {
        format!(
            "{role} run {run_id} is not recorded in this target's findings history. \
             List recorded runs with `kuzushi runs list --target <path>`."
        )
    })
}

pub(super) fn classify_findings(
    base: &BTreeMap<String, Finding>,
    compare: &BTreeMap<String, Finding>,
    coverage: &RetirementCoverage,
    reopened: &BTreeSet<String>,
    uncertain: &[ScanUncertainMatch],
) -> Vec<ComparedFinding> {
    let excluded = uncertain_keys(uncertain);
    let mut findings = compare_side_entries(base, compare, reopened, &excluded);
    findings.extend(base_only_entries(base, compare, coverage, &excluded));
    findings
}

fn compare_side_entries(
    base: &BTreeMap<String, Finding>,
    compare: &BTreeMap<String, Finding>,
    reopened: &BTreeSet<String>,
    excluded: &BTreeSet<String>,
) -> Vec<ComparedFinding> {
    compare
        .iter()
        .filter(|(key, _)| !excluded.contains(*key))
        .map(|(key, finding)| classify_compare_side(key, finding, base, reopened))
        .collect()
}

fn base_only_entries(
    base: &BTreeMap<String, Finding>,
    compare: &BTreeMap<String, Finding>,
    coverage: &RetirementCoverage,
    excluded: &BTreeSet<String>,
) -> Vec<ComparedFinding> {
    base.iter()
        .filter(|(key, _)| !compare.contains_key(*key) && !excluded.contains(*key))
        .map(|(key, finding)| classify_base_only(key, finding, coverage))
        .collect()
}

fn classify_compare_side(
    key: &str,
    finding: &Finding,
    base: &BTreeMap<String, Finding>,
    reopened: &BTreeSet<String>,
) -> ComparedFinding {
    let before = base.get(key).map(ScanFindingSignature::of);
    // The reopen key set is global to the compare run, so a finding first
    // observed after the base run is only `Reopened` relative to a base that
    // actually saw it; otherwise it is simply `New` in this pair.
    let class = if before.is_some() && reopened.contains(key) {
        ScanComparisonClass::Reopened
    } else if before.is_some() {
        ScanComparisonClass::Persisting
    } else {
        ScanComparisonClass::New
    };
    compared(key, finding, class, None, before, Some(ScanFindingSignature::of(finding)))
}

fn classify_base_only(
    key: &str,
    finding: &Finding,
    coverage: &RetirementCoverage,
) -> ComparedFinding {
    let (class, reason) = match coverage.retirement_block(finding) {
        None => (ScanComparisonClass::Resolved, None),
        Some(reason) => (ScanComparisonClass::NotRescanned, Some(reason)),
    };
    compared(key, finding, class, reason, Some(ScanFindingSignature::of(finding)), None)
}

fn compared(
    key: &str,
    finding: &Finding,
    class: ScanComparisonClass,
    reason: Option<String>,
    before: Option<ScanFindingSignature>,
    after: Option<ScanFindingSignature>,
) -> ComparedFinding {
    ComparedFinding {
        stable_key: key.to_string(),
        title: finding.title.clone(),
        tool: finding.tool.clone(),
        file_path: finding.file_path.clone(),
        class,
        reason,
        before,
        after,
    }
}

fn uncertain_keys(uncertain: &[ScanUncertainMatch]) -> BTreeSet<String> {
    uncertain
        .iter()
        .flat_map(|row| [row.base_key.clone(), row.compare_key.clone()])
        .collect()
}
