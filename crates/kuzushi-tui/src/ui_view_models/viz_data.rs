//! View models for the security-viz gallery, built from real `ShellApp` state
//! (findings, threat-model doc, exploit chains, taint flow). Pure: each builder
//! takes `&ShellApp`/`&[Finding]` and returns an owned model. When the backing
//! artifact hasn't been generated, the model carries an `empty_hint` so the
//! renderer can draw a single guidance line instead of dummy content.

use super::threat_dfd_diagram::{parse_flows, parse_nodes, zones_in_order};
use crate::{ChainSeverity, ExploitChainStep, ShellApp};
use kuzushi_core::{Finding, Severity};
use std::collections::BTreeMap;

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

// ── Findings heatmap ───────────────────────────────────────────────────────

const MAX_HEATMAP_ROWS: usize = 10;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FindingsHeatmap {
    pub rows: Vec<ModuleRisk>,
    pub empty_hint: Option<String>,
}

pub(crate) fn findings_heatmap(findings: &[Finding]) -> FindingsHeatmap {
    let risk = risk_by_module(findings);
    if risk.modules.is_empty() {
        return FindingsHeatmap {
            rows: Vec::new(),
            empty_hint: Some("no findings yet — run `scan` to populate".to_string()),
        };
    }
    FindingsHeatmap {
        rows: risk.modules.into_iter().take(MAX_HEATMAP_ROWS).collect(),
        empty_hint: None,
    }
}

// ── Data-flow diagram ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DfdKind {
    Entity,
    Process,
    Store,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdNodeModel {
    pub name: String,
    pub zone: String,
    pub kind: DfdKind,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdFlowModel {
    pub from: String,
    pub to: String,
    pub crosses: bool,
    pub label: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DfdModel {
    pub zones: Vec<String>,
    pub nodes: Vec<DfdNodeModel>,
    pub flows: Vec<DfdFlowModel>,
    pub empty_hint: Option<String>,
}

fn dfd_kind(raw: &str) -> DfdKind {
    let kind = raw.to_ascii_lowercase();
    if kind.contains("entity") || kind.contains("actor") || kind.contains("external") {
        DfdKind::Entity
    } else if kind.contains("store") || kind.contains("data") {
        DfdKind::Store
    } else {
        DfdKind::Process
    }
}

pub(crate) fn dfd_model(app: &ShellApp) -> DfdModel {
    let Some(doc) = super::threat_model_doc(app) else {
        return DfdModel {
            empty_hint: Some("no threat model yet — run `threat-model` to populate".to_string()),
            ..Default::default()
        };
    };
    let nodes = parse_nodes(&doc);
    if nodes.is_empty() {
        return DfdModel {
            empty_hint: Some("threat model has no data-flow diagram yet".to_string()),
            ..Default::default()
        };
    }
    let flows = parse_flows(&doc, &nodes);
    let zones = zones_in_order(&nodes);
    DfdModel {
        nodes: nodes
            .iter()
            .map(|n| DfdNodeModel {
                name: n.name.clone(),
                zone: n.zone.clone(),
                kind: dfd_kind(&n.kind),
            })
            .collect(),
        flows: flows
            .iter()
            .map(|f| DfdFlowModel {
                from: f.source.clone(),
                to: f.target.clone(),
                crosses: f.crosses,
                label: f.label.clone(),
            })
            .collect(),
        zones,
        empty_hint: None,
    }
}

// ── Attack tree (exploit chains) ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AttackChain {
    pub title: String,
    pub severity: ChainSeverity,
    pub steps: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AttackTree {
    pub chains: Vec<AttackChain>,
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
            steps: chain.steps.iter().take(4).map(step_label).collect(),
        })
        .collect();
    AttackTree {
        chains,
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
