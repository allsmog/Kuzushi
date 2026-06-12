//! Builds the "generated views" section pinned to the bottom of the Activity
//! OUTPUT pane: every security-viz page that currently has data, rendered as feed
//! rows from persistent `ShellApp` state. Mirrors `threat_dfd_diagram`'s feed-row
//! projection so a repo's generated visualizations stay visible across every later
//! phase of the walker (and, with the on-disk snapshots, across sessions).
//!
//! The 3D attack-surface page can't rasterize inside a text feed, so it collapses
//! to a one-line risk summary; the other four pages draw their full diagrams.
//! Each builder is gated by its page's existing `empty_hint`, so a page with no
//! backing artifact contributes nothing rather than a placeholder.

use super::activity_feed_rows::{ActivityFeedPaneRow, ActivityFeedRowTone};
use super::threat_dfd_diagram::{threat_dfd_diagram_feed_rows, threat_dfd_summary_feed_rows};
use super::threat_model_doc;
use super::viz_data::{
    attack_tree, findings_heatmap, risk_by_module, taint_flow_path, AttackTree, FindingsHeatmap,
    ModuleRisk, TaintFlowPath,
};
use crate::{ChainSeverity, ShellApp};

const HEADER: &str = "generated views · always available for this repo";

/// All generated visualizations that currently have data, as Activity OUTPUT feed
/// rows. Empty when nothing has been generated yet, so the live feed stands alone.
pub(crate) fn generated_views_feed_rows(app: &ShellApp, width: usize) -> Vec<ActivityFeedPaneRow> {
    let sections = [
        attack_surface_rows(app, width),
        attack_path_rows(&taint_flow_path(app), width),
        dfd_rows(app, width),
        heatmap_rows(&findings_heatmap(&app.findings), width),
        exploit_chain_rows(&attack_tree(app), width),
    ];
    assemble(sections, width)
        .into_iter()
        .map(|paned| row(clip(paned.text, width), paned.tone))
        .collect()
}

/// Join the present (non-empty) sections under a single header, blank-separated.
fn assemble(sections: [Vec<ActivityFeedPaneRow>; 5], width: usize) -> Vec<ActivityFeedPaneRow> {
    let present: Vec<Vec<ActivityFeedPaneRow>> = sections
        .into_iter()
        .filter(|section| !section.is_empty())
        .collect();
    if present.is_empty() {
        return Vec::new();
    }
    let mut out = vec![
        row(String::new(), ActivityFeedRowTone::Subtle),
        row(rule(HEADER, width), ActivityFeedRowTone::Primary),
    ];
    for (index, mut section) in present.into_iter().enumerate() {
        if index > 0 {
            out.push(row(String::new(), ActivityFeedRowTone::Subtle));
        }
        out.append(&mut section);
    }
    out
}

// ── 3D attack surface (one-line summary; the framebuffer can't draw in a feed) ──

fn attack_surface_rows(app: &ShellApp, width: usize) -> Vec<ActivityFeedPaneRow> {
    let risk = risk_by_module(&app.findings);
    let Some(hottest) = risk.modules.first() else {
        return Vec::new();
    };
    let total: u32 = risk.modules.iter().map(module_total).sum();
    vec![
        row(rule("ATTACK SURFACE", width), ActivityFeedRowTone::Success),
        row(
            format!(
                "  risk relief · {total} findings · {} modules · hottest {}",
                risk.modules.len(),
                hottest.module
            ),
            ActivityFeedRowTone::Muted,
        ),
    ]
}

// ── attack path (taint source → sink) ──

fn attack_path_rows(model: &TaintFlowPath, _width: usize) -> Vec<ActivityFeedPaneRow> {
    if model.empty_hint.is_some() {
        return Vec::new();
    }
    let chain = model
        .stages
        .iter()
        .map(|stage| stage.title.clone())
        .collect::<Vec<_>>()
        .join(" ─▶ ");
    vec![
        row(rule("ATTACK PATH", _width), ActivityFeedRowTone::Success),
        row(
            format!("  {} · {}", model.cwe, model.severity),
            ActivityFeedRowTone::Warn,
        ),
        row(format!("  {chain}"), ActivityFeedRowTone::Muted),
    ]
}

// ── data-flow diagram (reuses the existing projection) ──

/// Below this many columns the DFD's node boxes degrade into clipped "…"
/// noise — show the title + counts and point at /scene instead.
const DFD_DIAGRAM_MIN_WIDTH: usize = 56;

fn dfd_rows(app: &ShellApp, width: usize) -> Vec<ActivityFeedPaneRow> {
    match threat_model_doc(app) {
        Some(doc) => dfd_rows_for_doc(&doc, width),
        None => Vec::new(),
    }
}

fn dfd_rows_for_doc(doc: &serde_json::Value, width: usize) -> Vec<ActivityFeedPaneRow> {
    if width >= DFD_DIAGRAM_MIN_WIDTH {
        return threat_dfd_diagram_feed_rows(doc, width);
    }
    let mut rows = threat_dfd_summary_feed_rows(doc, width);
    if !rows.is_empty() {
        rows.push(row(
            "  open /scene for the full diagram".to_string(),
            ActivityFeedRowTone::Subtle,
        ));
    }
    rows
}

// ── findings heatmap (severity × module) ──

fn heatmap_rows(model: &FindingsHeatmap, width: usize) -> Vec<ActivityFeedPaneRow> {
    if model.empty_hint.is_some() {
        return Vec::new();
    }
    let total: u32 = model.rows.iter().map(module_total).sum();
    let mut rows = vec![
        row(
            rule("FINDINGS HEATMAP", width),
            ActivityFeedRowTone::Success,
        ),
        row(
            format!(
                "  {total} findings across {} modules · CRIT HIGH MED LOW INFO",
                model.rows.len()
            ),
            ActivityFeedRowTone::Subtle,
        ),
    ];
    rows.extend(
        model
            .rows
            .iter()
            .map(|module| row(heatmap_cells(module), ActivityFeedRowTone::Muted)),
    );
    rows
}

fn heatmap_cells(module: &ModuleRisk) -> String {
    let cells: String = module
        .counts
        .iter()
        .map(|count| format!(" {}", cell(*count)))
        .collect();
    format!("  {:<16}{cells}", truncate(&module.module, 16))
}

fn cell(count: u32) -> String {
    if count == 0 {
        "·".to_string()
    } else {
        format!("{}{count}", "█".repeat((count as usize).min(3)))
    }
}

// ── exploit chain / attack tree ──

fn exploit_chain_rows(model: &AttackTree, width: usize) -> Vec<ActivityFeedPaneRow> {
    if model.empty_hint.is_some() {
        return Vec::new();
    }
    let mut rows = vec![
        row(rule("EXPLOIT CHAIN", width), ActivityFeedRowTone::Success),
        row(
            format!("  ☠ attacker goal — {} chains", model.chains.len()),
            ActivityFeedRowTone::Danger,
        ),
    ];
    for chain in &model.chains {
        rows.push(row(
            format!("  ◇ {} · {}", chain.title, severity_label(chain.severity)),
            chain_tone(chain.severity),
        ));
        rows.extend(
            chain
                .steps
                .iter()
                .map(|step| row(format!("      → {step}"), ActivityFeedRowTone::Subtle)),
        );
    }
    rows
}

fn severity_label(severity: ChainSeverity) -> &'static str {
    match severity {
        ChainSeverity::Critical => "CRIT",
        ChainSeverity::High => "HIGH",
        ChainSeverity::Medium => "MED",
    }
}

fn chain_tone(severity: ChainSeverity) -> ActivityFeedRowTone {
    match severity {
        ChainSeverity::Critical => ActivityFeedRowTone::Danger,
        ChainSeverity::High => ActivityFeedRowTone::Warn,
        ChainSeverity::Medium => ActivityFeedRowTone::Muted,
    }
}

// ── shared helpers ──

fn module_total(module: &ModuleRisk) -> u32 {
    module.counts.iter().sum()
}

fn row(text: String, tone: ActivityFeedRowTone) -> ActivityFeedPaneRow {
    ActivityFeedPaneRow { text, tone }
}

fn rule(label: &str, width: usize) -> String {
    let prefix = format!("── {label} ");
    let fill = width.saturating_sub(prefix.chars().count()).min(48);
    format!("{prefix}{}", "─".repeat(fill))
}

fn truncate(value: &str, width: usize) -> String {
    match value.chars().count() <= width {
        true => value.to_string(),
        false => value.chars().take(width).collect(),
    }
}

fn clip(text: String, width: usize) -> String {
    if text.chars().count() <= width {
        return text;
    }
    text.chars()
        .take(width.saturating_sub(1))
        .chain(std::iter::once('…'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::viz_data::{AttackChain, TaintStageModel};
    use super::*;

    fn dfd_doc() -> serde_json::Value {
        serde_json::json!({
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "trustZone": "internet"},
                    {"id": "api", "name": "API server", "trustZone": "app-tier"}
                ],
                "flows": [
                    {"id": "f1", "sourceId": "user", "targetId": "api", "description": "https"}
                ]
            }
        })
    }

    #[test]
    fn dfd_rows_draw_full_diagram_when_the_pane_is_wide() {
        let rows = dfd_rows_for_doc(&dfd_doc(), 80);
        assert!(rows.iter().any(|row| row.text.contains('┌')));
    }

    #[test]
    fn dfd_rows_compact_to_summary_in_narrow_panes() {
        // A box diagram clipped to "…" every row is noise; narrow panes get
        // the counts and a pointer to the full-width /scene page instead.
        let rows = dfd_rows_for_doc(&dfd_doc(), DFD_DIAGRAM_MIN_WIDTH - 1);
        assert!(!rows.iter().any(|row| row.text.contains('┌')));
        assert!(rows.iter().any(|row| row.text.contains("zones")));
        assert!(rows.iter().any(|row| row.text.contains("/scene")));
    }

    #[test]
    fn heatmap_rows_hidden_without_findings() {
        let model = FindingsHeatmap {
            rows: Vec::new(),
            empty_hint: Some("none".into()),
        };
        assert!(heatmap_rows(&model, 80).is_empty());
    }

    #[test]
    fn heatmap_rows_render_title_and_modules() {
        let model = FindingsHeatmap {
            rows: vec![ModuleRisk {
                module: "auth".into(),
                counts: [1, 2, 0, 0, 0],
                score: 0.0,
            }],
            empty_hint: None,
        };
        let rows = heatmap_rows(&model, 80);
        assert!(rows.iter().any(|r| r.text.contains("FINDINGS HEATMAP")));
        assert!(rows.iter().any(|r| r.text.contains("auth")));
    }

    #[test]
    fn attack_path_rows_show_cwe_and_chained_stages() {
        let model = TaintFlowPath {
            cwe: "CWE-89".into(),
            severity: "critical".into(),
            stages: vec![
                TaintStageModel {
                    title: "order_id".into(),
                    location: "a:1".into(),
                },
                TaintStageModel {
                    title: "db.query".into(),
                    location: "b:2".into(),
                },
            ],
            empty_hint: None,
        };
        let rows = attack_path_rows(&model, 80);
        assert!(rows.iter().any(|r| r.text.contains("CWE-89")));
        assert!(rows.iter().any(|r| r.text.contains("order_id ─▶ db.query")));
    }

    #[test]
    fn attack_path_rows_hidden_when_empty() {
        let model = TaintFlowPath {
            cwe: String::new(),
            severity: String::new(),
            stages: Vec::new(),
            empty_hint: Some("none".into()),
        };
        assert!(attack_path_rows(&model, 80).is_empty());
    }

    #[test]
    fn exploit_chain_rows_list_chains_and_steps() {
        let model = AttackTree {
            chains: vec![AttackChain {
                title: "SQLi /orders".into(),
                severity: ChainSeverity::Critical,
                steps: vec!["unsanitised id".into()],
            }],
            empty_hint: None,
        };
        let rows = exploit_chain_rows(&model, 80);
        assert!(rows
            .iter()
            .any(|r| r.text.contains("SQLi /orders") && r.text.contains("CRIT")));
        assert!(rows.iter().any(|r| r.text.contains("unsanitised id")));
    }
}
