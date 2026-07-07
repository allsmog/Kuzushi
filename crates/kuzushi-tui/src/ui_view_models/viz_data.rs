//! View models for the security-viz gallery, built from real `ShellApp` state
//! (findings, threat-model doc, exploit chains, taint flow). Pure: each builder
//! takes `&ShellApp`/`&[Finding]` and returns an owned model. When the backing
//! artifact hasn't been generated, the model carries an `empty_hint` so the
//! renderer can draw a single guidance line instead of dummy content.

use crate::{ChainSeverity, ExploitChainStep, RiskByModuleCacheKey, ShellApp, TaintFlowSnapshot};
use kuzushi_core::{Finding, Severity};
use std::collections::BTreeMap;

mod dfd;
pub(crate) use dfd::{dfd_model, DfdFlowModel, DfdKind, DfdModel, DfdNodeModel};

// ── Risk by module (shared by heatmap + terrain) ──────────────────────────

/// Per-module severity counts (`[critical, high, medium, low, info]`) and a
/// severity-weighted `score` used for ranking and terrain height.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ModuleRisk {
    pub module: String,
    pub counts: [u32; 5],
    pub score: f32,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct RiskByModule {
    /// Modules sorted by `score` descending (ties broken by name).
    pub modules: Vec<ModuleRisk>,
}

const SEVERITY_WEIGHTS: [f32; 5] = [10.0, 5.0, 2.0, 1.0, 0.25];

/// Group key for a finding: its immediate parent directory (e.g.
/// `src/auth/login.rs` → `auth`), or `(root)` for a top-level file.
pub(crate) fn module_of(file_path: &str) -> String {
    match file_path.trim().rsplit_once('/') {
        Some((dir, _file)) => dir
            .rsplit('/')
            .find(|seg| !seg.is_empty())
            .unwrap_or("(root)")
            .to_string(),
        None => "(root)".to_string(),
    }
}

fn severity_index(severity: Severity) -> Option<usize> {
    match severity {
        Severity::Critical => Some(0),
        Severity::High => Some(1),
        Severity::Medium => Some(2),
        Severity::Low => Some(3),
        Severity::Info => Some(4),
        Severity::Unknown => None,
    }
}

pub(crate) fn risk_by_module(findings: &[Finding]) -> RiskByModule {
    let mut by_module: BTreeMap<String, [u32; 5]> = BTreeMap::new();
    for finding in findings {
        if let Some(index) = severity_index(finding.severity) {
            by_module.entry(module_of(&finding.file_path)).or_default()[index] += 1;
        }
    }
    let mut modules: Vec<ModuleRisk> = by_module
        .into_iter()
        .map(|(module, counts)| {
            let score = counts
                .iter()
                .zip(SEVERITY_WEIGHTS)
                .map(|(count, weight)| *count as f32 * weight)
                .sum();
            ModuleRisk {
                module,
                counts,
                score,
            }
        })
        .collect();
    modules.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.module.cmp(&b.module))
    });
    RiskByModule { modules }
}

pub(crate) fn cached_risk_by_module(app: &ShellApp) -> RiskByModule {
    let key = RiskByModuleCacheKey::from_findings(&app.findings);
    if let Some(cached) = app.workbench_cache.borrow().risk_by_module(&key) {
        return cached;
    }
    let risk = risk_by_module(&app.findings);
    app.workbench_cache
        .borrow_mut()
        .cache_risk_by_module(key, risk.clone());
    risk
}

// ── Findings heatmap ───────────────────────────────────────────────────────

const MAX_HEATMAP_ROWS: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingsHeatmap {
    pub rows: Vec<ModuleRisk>,
    pub empty_hint: Option<String>,
    pub selected_module: Option<String>,
}

pub(crate) fn findings_heatmap(findings: &[Finding]) -> FindingsHeatmap {
    findings_heatmap_with_selection(findings, None)
}

pub(crate) fn findings_heatmap_with_selection(
    findings: &[Finding],
    selected: Option<&Finding>,
) -> FindingsHeatmap {
    let risk = risk_by_module(findings);
    findings_heatmap_from_risk(risk, selected)
}

pub(crate) fn cached_findings_heatmap(app: &ShellApp) -> FindingsHeatmap {
    cached_findings_heatmap_with_selection(app, None)
}

pub(crate) fn cached_findings_heatmap_with_selection(
    app: &ShellApp,
    selected: Option<&Finding>,
) -> FindingsHeatmap {
    findings_heatmap_from_risk(cached_risk_by_module(app), selected)
}

fn findings_heatmap_from_risk(risk: RiskByModule, selected: Option<&Finding>) -> FindingsHeatmap {
    if risk.modules.is_empty() {
        return FindingsHeatmap {
            rows: Vec::new(),
            empty_hint: Some("no findings yet — run `scan` to populate".to_string()),
            selected_module: None,
        };
    }
    FindingsHeatmap {
        rows: risk.modules.into_iter().take(MAX_HEATMAP_ROWS).collect(),
        empty_hint: None,
        selected_module: selected.map(|finding| module_of(&finding.file_path)),
    }
}

// ── Attack tree (exploit chains) ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AttackChain {
    pub title: String,
    pub severity: ChainSeverity,
    pub narrative: Option<String>,
    pub impact_description: Option<String>,
    pub preconditions: Vec<String>,
    pub steps: Vec<String>,
    pub hidden_step_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AttackTree {
    pub chains: Vec<AttackChain>,
    pub hidden_chain_count: usize,
    pub empty_hint: Option<String>,
}

pub(crate) fn attack_tree(app: &ShellApp) -> AttackTree {
    if app.exploit_chains.is_empty() {
        return AttackTree {
            empty_hint: Some("no exploit chains yet — run `exploit-chain:scan`".to_string()),
            ..Default::default()
        };
    }
    let chains = app
        .exploit_chains
        .iter()
        .take(3)
        .map(|chain| AttackChain {
            title: chain.title.clone(),
            severity: chain.severity,
            narrative: chain.narrative.clone(),
            impact_description: chain.impact_description.clone(),
            preconditions: chain.preconditions.clone(),
            steps: chain.steps.iter().take(4).map(step_label).collect(),
            hidden_step_count: chain.steps.len().saturating_sub(4),
        })
        .collect();
    AttackTree {
        chains,
        hidden_chain_count: app.exploit_chains.len().saturating_sub(3),
        empty_hint: None,
    }
}

fn step_label(step: &ExploitChainStep) -> String {
    if step.description.is_empty() {
        format!("{}:{}", short_file(&step.file), step.line)
    } else {
        step.description.clone()
    }
}

// ── Taint flow path ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TaintStageModel {
    pub title: String,
    pub location: String,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct TaintFlowPath {
    pub cwe: String,
    pub severity: String,
    pub stages: Vec<TaintStageModel>,
    pub empty_hint: Option<String>,
}

pub(crate) fn taint_flow_path(app: &ShellApp) -> TaintFlowPath {
    let Some(flow) = app.taint_flow.as_ref() else {
        return TaintFlowPath {
            empty_hint: Some("no taint flow yet — run `taint-iris:hunt`".to_string()),
            ..Default::default()
        };
    };
    taint_flow_path_from_snapshot(flow)
}

pub(crate) fn selected_taint_flow_path(app: &ShellApp) -> TaintFlowPath {
    let Some(selected) = app.selected_finding.as_ref() else {
        return taint_flow_path(app);
    };
    let Some(flow) = app.taint_flow.as_ref() else {
        return TaintFlowPath {
            empty_hint: Some(
                "no taint flow for the selected finding yet — run `taint-iris:hunt`".to_string(),
            ),
            ..Default::default()
        };
    };
    if flow_matches_finding(flow, selected) {
        return taint_flow_path_from_snapshot(flow);
    }
    TaintFlowPath {
        empty_hint: Some(
            "cached taint flow does not match the selected finding — run `taint-iris:hunt`"
                .to_string(),
        ),
        ..Default::default()
    }
}

fn flow_matches_finding(flow: &TaintFlowSnapshot, finding: &Finding) -> bool {
    flow.stages
        .iter()
        .any(|stage| stage.file == finding.file_path || stage.file.ends_with(&finding.file_path))
}

fn taint_flow_path_from_snapshot(flow: &TaintFlowSnapshot) -> TaintFlowPath {
    TaintFlowPath {
        cwe: flow.cwe.clone(),
        severity: flow.severity.clone(),
        stages: flow
            .stages
            .iter()
            .take(6)
            .map(|stage| TaintStageModel {
                title: if stage.message.is_empty() {
                    short_file(&stage.file)
                } else {
                    stage.message.clone()
                },
                location: format!("{}:{}", short_file(&stage.file), stage.line),
                snippet: stage.snippet.clone(),
            })
            .collect(),
        empty_hint: None,
    }
}

fn short_file(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::Finding;

    fn finding(path: &str, severity: Severity) -> Finding {
        Finding::new_tool(
            "t",
            "r".to_string(),
            path.to_string(),
            1,
            None,
            severity,
            "m".to_string(),
        )
    }

    #[test]
    fn module_of_uses_immediate_parent_dir() {
        assert_eq!(module_of("src/auth/login.rs"), "auth");
        assert_eq!(module_of("auth/x.rs"), "auth");
        assert_eq!(module_of("main.rs"), "(root)");
    }

    #[test]
    fn risk_by_module_groups_counts_and_ranks_by_score() {
        let findings = vec![
            finding("auth/a.rs", Severity::Critical),
            finding("auth/b.rs", Severity::High),
            finding("api/c.rs", Severity::Low),
        ];
        let risk = risk_by_module(&findings);
        assert_eq!(risk.modules[0].module, "auth"); // highest score first
        assert_eq!(risk.modules[0].counts, [1, 1, 0, 0, 0]);
        assert!(risk.modules[0].score > risk.modules[1].score);
    }

    #[test]
    fn heatmap_empty_state_when_no_findings() {
        assert!(findings_heatmap(&[]).empty_hint.is_some());
        assert!(findings_heatmap(&[finding("a/b.rs", Severity::High)])
            .empty_hint
            .is_none());
    }
}
