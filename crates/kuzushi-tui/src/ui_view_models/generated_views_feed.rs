//! Builds the Activity OUTPUT view strip. Pages project real persisted security
//! state from `ShellApp` (findings, threat-model DFD, taint flow, exploit
//! chains) into a compact selectable list plus inspector. Live trace rows live
//! in the TASKS pane.

use super::activity_feed_rows::{ActivityFeedPaneRow, ActivityFeedRowTone};
use super::findings::{findings_model, FindingListRow};
#[cfg(test)]
use super::threat_dfd_diagram::{threat_dfd_diagram_feed_rows, threat_dfd_summary_feed_rows};
#[cfg(test)]
use super::threat_model_doc;
use super::viz_data::{
    attack_tree, dfd_model, findings_heatmap, risk_by_module, taint_flow_path, AttackTree,
    DfdFlowModel, DfdModel, FindingsHeatmap, ModuleRisk, RiskByModule, TaintFlowPath,
};
use super::SeverityTone;
use crate::{ActivityDeckPage, ActivitySession, ChainSeverity, ShellApp};

#[cfg(test)]
#[allow(dead_code)]
const HEADER: &str = "generated views · always available for this repo";
const DECK_WINDOW_ROWS: usize = 7;

/// The Activity right pane as a navigable view strip. Every page renders one
/// real persisted model with a selected item inspector instead of dumping all
/// generated views below the task stream.
pub(crate) fn activity_deck_rows(
    app: &ShellApp,
    session: &ActivitySession,
    width: usize,
    _running_tool: Option<&str>,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = activity_deck_header_rows(app, session, width);
    rows.extend(match session.deck_page {
        ActivityDeckPage::Feed | ActivityDeckPage::Findings => {
            findings_deck_rows(app, session.deck_cursor, width)
        }
        ActivityDeckPage::AttackSurface => {
            attack_surface_deck_rows(&risk_by_module(&app.findings), session.deck_cursor, width)
        }
        ActivityDeckPage::Dfd => dfd_deck_rows(&dfd_model(app), session.deck_cursor, width),
        ActivityDeckPage::Heatmap => {
            heatmap_deck_rows(&findings_heatmap(&app.findings), session.deck_cursor, width)
        }
        ActivityDeckPage::AttackPath => {
            attack_path_deck_rows(&taint_flow_path(app), session.deck_cursor, width)
        }
        ActivityDeckPage::ExploitChain => {
            exploit_chain_deck_rows(&attack_tree(app), session.deck_cursor, width)
        }
    });
    rows.into_iter()
        .map(|paned| row(clip(paned.text, width), paned.tone))
        .collect()
}

pub(crate) fn activity_deck_plain_extra_rows(
    app: &ShellApp,
    session: &ActivitySession,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = activity_deck_header_rows(app, session, width);
    rows.extend(match session.deck_page {
        ActivityDeckPage::Feed | ActivityDeckPage::Findings => {
            findings_deck_rows(app, session.deck_cursor, width)
        }
        ActivityDeckPage::AttackSurface => {
            attack_surface_deck_rows(&risk_by_module(&app.findings), session.deck_cursor, width)
        }
        ActivityDeckPage::Dfd => dfd_deck_rows(&dfd_model(app), session.deck_cursor, width),
        ActivityDeckPage::Heatmap => {
            heatmap_deck_rows(&findings_heatmap(&app.findings), session.deck_cursor, width)
        }
        ActivityDeckPage::AttackPath => {
            attack_path_deck_rows(&taint_flow_path(app), session.deck_cursor, width)
        }
        ActivityDeckPage::ExploitChain => {
            exploit_chain_deck_rows(&attack_tree(app), session.deck_cursor, width)
        }
    });
    rows.into_iter()
        .map(|paned| row(clip(paned.text, width), paned.tone))
        .collect()
}

fn activity_deck_header_rows(
    app: &ShellApp,
    session: &ActivitySession,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    vec![
        row(
            deck_tabs(app, session.deck_page),
            ActivityFeedRowTone::Primary,
        ),
        row(
            deck_hint(session.deck_page, width),
            ActivityFeedRowTone::Muted,
        ),
        row(String::new(), ActivityFeedRowTone::Subtle),
    ]
}

fn deck_tabs(app: &ShellApp, active: ActivityDeckPage) -> String {
    let labels = ActivityDeckPage::ALL
        .iter()
        .map(|page| deck_tab(app, *page, active))
        .collect::<Vec<_>>()
        .join(" ");
    format!("views  {labels}")
}

fn deck_tab(app: &ShellApp, page: ActivityDeckPage, active: ActivityDeckPage) -> String {
    let mut label = page.label().to_string();
    if page != ActivityDeckPage::Feed && !deck_page_has_content(app, page) {
        label.push('·');
    }
    if page == active {
        format!("[{label}]")
    } else {
        format!(" {label} ")
    }
}

fn deck_page_has_content(app: &ShellApp, page: ActivityDeckPage) -> bool {
    match page {
        ActivityDeckPage::Feed | ActivityDeckPage::Findings => !app.findings.is_empty(),
        ActivityDeckPage::AttackSurface | ActivityDeckPage::Heatmap => !app.findings.is_empty(),
        ActivityDeckPage::Dfd => dfd_model(app).empty_hint.is_none(),
        ActivityDeckPage::AttackPath => app.taint_flow.is_some(),
        ActivityDeckPage::ExploitChain => !app.exploit_chains.is_empty(),
    }
}

fn deck_hint(page: ActivityDeckPage, width: usize) -> String {
    let hint = match page {
        ActivityDeckPage::Findings | ActivityDeckPage::Feed => {
            "←/→ views · j/k item · o open findings · dots mean no artifact"
        }
        _ => "←/→ views · j/k item · f findings · o open · dots mean no artifact",
    };
    format!("  {}", truncate(hint, width.saturating_sub(2)))
}

// ── Activity artifact pages ───────────────────────────────────────────────

fn findings_deck_rows(app: &ShellApp, cursor: usize, width: usize) -> Vec<ActivityFeedPaneRow> {
    let model = findings_model(app);
    if model.rows.is_empty() {
        return empty_deck_rows("FINDINGS", model.empty.hint, width);
    }
    let index = selected_index(model.rows.len(), cursor);
    let selected = &model.rows[index];
    let mut rows = findings_header_rows(&model, width);
    rows.extend(finding_window_rows(&model.rows, index, width));
    rows.push(row(String::new(), ActivityFeedRowTone::Subtle));
    rows.extend(selected_finding_rows(selected, width));
    rows
}

fn findings_header_rows(
    model: &super::findings::FindingsModel,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    vec![
        row(rule("FINDINGS", width), ActivityFeedRowTone::Success),
        row(
            format!(
                "  {} total · {} triaged · {} pending · crit {} high {} med {} low {} info {}",
                model.total,
                model.triaged,
                model.pending,
                model.counts.critical,
                model.counts.high,
                model.counts.medium,
                model.counts.low,
                model.counts.info
            ),
            ActivityFeedRowTone::Subtle,
        ),
        row("  FINDINGS".to_string(), ActivityFeedRowTone::Primary),
    ]
}

fn finding_window_rows(
    findings: &[FindingListRow],
    selected: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    visible_window(findings.len(), selected)
        .map(|index| {
            let finding = &findings[index];
            let active = index == selected;
            row(
                format!(
                    "  {} {:<6} {:<8} {}",
                    selection_marker(active),
                    finding.alias,
                    finding.severity_label,
                    truncate(&finding.title, width.saturating_sub(22))
                ),
                finding_list_tone(finding.severity_tone, active),
            )
        })
        .collect()
}

fn selected_finding_rows(selected: &FindingListRow, width: usize) -> Vec<ActivityFeedPaneRow> {
    let mut rows = selected_finding_base_rows(selected, width);
    if selected.evidence != "-" {
        rows.push(row(
            format!(
                "  evidence: {}",
                truncate(&selected.evidence, width.saturating_sub(14))
            ),
            ActivityFeedRowTone::Subtle,
        ));
    }
    rows.push(row(
        "  action: f or o opens full findings review".to_string(),
        ActivityFeedRowTone::Subtle,
    ));
    rows
}

fn selected_finding_base_rows(selected: &FindingListRow, width: usize) -> Vec<ActivityFeedPaneRow> {
    vec![
        row(
            "  SELECTED FINDING".to_string(),
            ActivityFeedRowTone::Primary,
        ),
        row(
            format!(
                "  {} · {} · {}",
                selected.alias, selected.severity_label, selected.title
            ),
            finding_tone(selected.severity_tone),
        ),
        row(
            format!(
                "  location: {}",
                truncate(&selected.location, width.saturating_sub(14))
            ),
            ActivityFeedRowTone::Muted,
        ),
        row(
            format!(
                "  status: {} {} · {} · {}",
                selected.verdict, selected.confidence, selected.cwe, selected.source
            ),
            ActivityFeedRowTone::Subtle,
        ),
    ]
}

fn attack_surface_deck_rows(
    risk: &RiskByModule,
    cursor: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let Some(selected) = selected_module(&risk.modules, cursor) else {
        return empty_deck_rows(
            "ATTACK SURFACE",
            "no findings yet — run `scan` to populate",
            width,
        );
    };
    let total: u32 = risk.modules.iter().map(module_total).sum();
    let index = selected_index(risk.modules.len(), cursor);
    let mut rows = vec![
        row(rule("ATTACK SURFACE", width), ActivityFeedRowTone::Success),
        row(
            format!(
                "  {total} findings · {} modules · hottest {}",
                risk.modules.len(),
                risk.modules[0].module
            ),
            ActivityFeedRowTone::Subtle,
        ),
        row("  HOTSPOTS".to_string(), ActivityFeedRowTone::Primary),
    ];
    rows.extend(module_window_rows(&risk.modules, index, width));
    rows.push(row(String::new(), ActivityFeedRowTone::Subtle));
    rows.extend(selected_module_rows("SELECTED HOTSPOT", selected, width));
    rows
}

fn heatmap_deck_rows(
    model: &FindingsHeatmap,
    cursor: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    if let Some(hint) = &model.empty_hint {
        return empty_deck_rows("FINDINGS HEATMAP", hint, width);
    }
    if model.rows.is_empty() {
        return empty_deck_rows("FINDINGS HEATMAP", "no module risk rows available", width);
    }
    let index = selected_index(model.rows.len(), cursor);
    let selected = &model.rows[index];
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
    rows.extend(module_window_rows(&model.rows, index, width));
    rows.push(row(String::new(), ActivityFeedRowTone::Subtle));
    rows.extend(selected_module_rows("SELECTED MODULE", selected, width));
    rows
}

fn dfd_deck_rows(model: &DfdModel, cursor: usize, width: usize) -> Vec<ActivityFeedPaneRow> {
    if let Some(hint) = &model.empty_hint {
        return empty_deck_rows("DATA FLOW", hint, width);
    }
    let crossings = model.flows.iter().filter(|flow| flow.crosses).count();
    let mut rows = vec![
        row(rule("DATA FLOW", width), ActivityFeedRowTone::Success),
        row(
            format!(
                "  {} zones · {} nodes · {} flows · {crossings} boundary crossings",
                model.zones.len(),
                model.nodes.len(),
                model.flows.len()
            ),
            ActivityFeedRowTone::Subtle,
        ),
    ];
    if model.flows.is_empty() {
        rows.extend(dfd_node_rows(model, cursor, width));
        return rows;
    }
    let index = selected_index(model.flows.len(), cursor);
    rows.push(row("  FLOWS".to_string(), ActivityFeedRowTone::Primary));
    rows.extend(flow_window_rows(model, index, width));
    rows.push(row(String::new(), ActivityFeedRowTone::Subtle));
    rows.extend(selected_flow_rows(model, &model.flows[index], width));
    rows
}

fn attack_path_deck_rows(
    model: &TaintFlowPath,
    cursor: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    if let Some(hint) = &model.empty_hint {
        return empty_deck_rows("ATTACK PATH", hint, width);
    }
    if model.stages.is_empty() {
        return empty_deck_rows("ATTACK PATH", "taint flow has no stages", width);
    }
    let index = selected_index(model.stages.len(), cursor);
    let mut rows = attack_path_header_rows(model, width);
    rows.extend(attack_path_stage_rows(model, index));
    rows.push(row(String::new(), ActivityFeedRowTone::Subtle));
    rows.extend(selected_stage_rows(&model.stages[index], width));
    rows
}

fn attack_path_header_rows(model: &TaintFlowPath, width: usize) -> Vec<ActivityFeedPaneRow> {
    let chain = model
        .stages
        .iter()
        .map(|stage| stage.title.clone())
        .collect::<Vec<_>>()
        .join(" ─▶ ");
    vec![
        row(rule("ATTACK PATH", width), ActivityFeedRowTone::Success),
        row(
            format!(
                "  {} · {} · {} stages",
                model.cwe,
                model.severity,
                model.stages.len()
            ),
            ActivityFeedRowTone::Warn,
        ),
        row(
            format!("  {}", truncate(&chain, width.saturating_sub(2))),
            ActivityFeedRowTone::Muted,
        ),
        row(String::new(), ActivityFeedRowTone::Subtle),
        row("  STAGES".to_string(), ActivityFeedRowTone::Primary),
    ]
}

fn attack_path_stage_rows(model: &TaintFlowPath, selected: usize) -> Vec<ActivityFeedPaneRow> {
    visible_window(model.stages.len(), selected)
        .map(|index| {
            let stage = &model.stages[index];
            let active = index == selected;
            row(
                format!(
                    "  {} {:02} {} · {}",
                    selection_marker(active),
                    index + 1,
                    truncate(&stage.title, 32),
                    stage.location
                ),
                activity_selection_tone(active),
            )
        })
        .collect()
}

fn selected_stage_rows(
    selected: &super::viz_data::TaintStageModel,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    vec![
        row("  SELECTED STAGE".to_string(), ActivityFeedRowTone::Primary),
        row(
            format!(
                "  title: {}",
                truncate(&selected.title, width.saturating_sub(9))
            ),
            ActivityFeedRowTone::Muted,
        ),
        row(
            format!("  location: {}", selected.location),
            ActivityFeedRowTone::Subtle,
        ),
    ]
}

fn exploit_chain_deck_rows(
    model: &AttackTree,
    cursor: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    if let Some(hint) = &model.empty_hint {
        return empty_deck_rows("EXPLOIT CHAIN", hint, width);
    }
    if model.chains.is_empty() {
        return empty_deck_rows(
            "EXPLOIT CHAIN",
            "no exploit chains in the latest artifact",
            width,
        );
    }
    let index = selected_index(model.chains.len(), cursor);
    let mut rows = exploit_chain_header_rows(model, width);
    rows.extend(exploit_chain_list_rows(model, index));
    rows.push(row(String::new(), ActivityFeedRowTone::Subtle));
    rows.extend(selected_chain_rows(&model.chains[index], width));
    rows
}

fn exploit_chain_header_rows(model: &AttackTree, width: usize) -> Vec<ActivityFeedPaneRow> {
    vec![
        row(rule("EXPLOIT CHAIN", width), ActivityFeedRowTone::Success),
        row(
            format!("  attacker goal · {} chains", model.chains.len()),
            ActivityFeedRowTone::Danger,
        ),
        row("  CHAINS".to_string(), ActivityFeedRowTone::Primary),
    ]
}

fn exploit_chain_list_rows(model: &AttackTree, selected: usize) -> Vec<ActivityFeedPaneRow> {
    visible_window(model.chains.len(), selected)
        .map(|index| {
            let chain = &model.chains[index];
            let active = index == selected;
            row(
                format!(
                    "  {} {:02} {} · {}",
                    selection_marker(active),
                    index + 1,
                    truncate(&chain.title, 34),
                    severity_label(chain.severity)
                ),
                chain_list_tone(chain.severity, active),
            )
        })
        .collect()
}

fn selected_chain_rows(
    selected: &super::viz_data::AttackChain,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = vec![
        row("  SELECTED CHAIN".to_string(), ActivityFeedRowTone::Primary),
        row(
            format!(
                "  {} · {}",
                truncate(&selected.title, width.saturating_sub(10)),
                severity_label(selected.severity)
            ),
            chain_tone(selected.severity),
        ),
    ];
    rows.extend(
        selected
            .steps
            .iter()
            .map(|step| row(format!("    → {step}"), ActivityFeedRowTone::Subtle)),
    );
    rows
}

fn chain_list_tone(severity: ChainSeverity, active: bool) -> ActivityFeedRowTone {
    if active {
        ActivityFeedRowTone::Primary
    } else {
        chain_tone(severity)
    }
}

/// All generated visualizations that currently have data, as Activity OUTPUT feed
/// rows. Empty when nothing has been generated yet, so the live feed stands alone.
#[cfg(test)]
#[allow(dead_code)]
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
#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
#[allow(dead_code)]
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

#[cfg(test)]
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
#[cfg(test)]
const DFD_DIAGRAM_MIN_WIDTH: usize = 56;

#[cfg(test)]
#[allow(dead_code)]
fn dfd_rows(app: &ShellApp, width: usize) -> Vec<ActivityFeedPaneRow> {
    match threat_model_doc(app) {
        Some(doc) => dfd_rows_for_doc(&doc, width),
        None => Vec::new(),
    }
}

#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
fn heatmap_cells(module: &ModuleRisk) -> String {
    let cells: String = module
        .counts
        .iter()
        .map(|count| format!(" {}", cell(*count)))
        .collect();
    format!("  {:<16}{cells}", truncate(&module.module, 16))
}

#[cfg(test)]
fn cell(count: u32) -> String {
    if count == 0 {
        "·".to_string()
    } else {
        format!("{}{count}", "█".repeat((count as usize).min(3)))
    }
}

// ── exploit chain / attack tree ──

#[cfg(test)]
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

fn finding_list_tone(tone: SeverityTone, active: bool) -> ActivityFeedRowTone {
    if active {
        ActivityFeedRowTone::Primary
    } else {
        finding_tone(tone)
    }
}

fn finding_tone(tone: SeverityTone) -> ActivityFeedRowTone {
    match tone {
        SeverityTone::Critical => ActivityFeedRowTone::Danger,
        SeverityTone::High => ActivityFeedRowTone::Warn,
        SeverityTone::Medium | SeverityTone::Low => ActivityFeedRowTone::Muted,
        SeverityTone::Info | SeverityTone::Unknown => ActivityFeedRowTone::Subtle,
    }
}

fn empty_deck_rows(title: &str, hint: &str, width: usize) -> Vec<ActivityFeedPaneRow> {
    vec![
        row(rule(title, width), ActivityFeedRowTone::Success),
        row(format!("  {hint}"), ActivityFeedRowTone::Muted),
    ]
}

fn selected_module(modules: &[ModuleRisk], cursor: usize) -> Option<&ModuleRisk> {
    modules.get(selected_index(modules.len(), cursor))
}

fn selected_index(len: usize, cursor: usize) -> usize {
    if len == 0 {
        0
    } else {
        cursor.min(len - 1)
    }
}

fn visible_window(len: usize, cursor: usize) -> std::ops::Range<usize> {
    let index = selected_index(len, cursor);
    let half = DECK_WINDOW_ROWS / 2;
    let start = index.saturating_sub(half);
    let end = (start + DECK_WINDOW_ROWS).min(len);
    let start = start.min(end.saturating_sub(DECK_WINDOW_ROWS));
    start..end
}

fn module_window_rows(
    modules: &[ModuleRisk],
    selected: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    visible_window(modules.len(), selected)
        .map(|index| {
            let module = &modules[index];
            let active = index == selected;
            row(
                format!(
                    "  {} {:02} {:<16} {}  {}",
                    selection_marker(active),
                    index + 1,
                    truncate(&module.module, 16),
                    risk_bar(module),
                    truncate(&severity_counts(&module.counts), width.saturating_sub(34))
                ),
                activity_selection_tone(active),
            )
        })
        .collect()
}

fn selected_module_rows(
    title: &str,
    selected: &ModuleRisk,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    vec![
        row(format!("  {title}"), ActivityFeedRowTone::Primary),
        row(
            format!(
                "  module: {} · score {:.1}",
                truncate(&selected.module, width.saturating_sub(24)),
                selected.score
            ),
            ActivityFeedRowTone::Muted,
        ),
        row(
            format!("  severity: {}", severity_counts(&selected.counts)),
            ActivityFeedRowTone::Subtle,
        ),
        row(
            "  action: Enter keeps task focus · o opens full visualization".to_string(),
            ActivityFeedRowTone::Subtle,
        ),
    ]
}

fn risk_bar(module: &ModuleRisk) -> String {
    let blocks = (module.score / 10.0).ceil().clamp(1.0, 10.0) as usize;
    format!("{:<10}", "█".repeat(blocks))
}

fn severity_counts(counts: &[u32; 5]) -> String {
    let labels = ["crit", "high", "med", "low", "info"];
    labels
        .iter()
        .zip(counts)
        .filter_map(|(label, count)| (*count > 0).then(|| format!("{label} {count}")))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn flow_window_rows(model: &DfdModel, selected: usize, width: usize) -> Vec<ActivityFeedPaneRow> {
    visible_window(model.flows.len(), selected)
        .map(|index| {
            let flow = &model.flows[index];
            let active = index == selected;
            let arrow = if flow.crosses {
                "══▶"
            } else {
                "──▶"
            };
            row(
                format!(
                    "  {} {:02} {} {arrow} {} · {}",
                    selection_marker(active),
                    index + 1,
                    truncate(&flow.from, 18),
                    truncate(&flow.to, 18),
                    truncate(&flow.label, width.saturating_sub(52))
                ),
                activity_selection_tone(active),
            )
        })
        .collect()
}

fn selected_flow_rows(
    model: &DfdModel,
    flow: &DfdFlowModel,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    vec![
        row("  SELECTED FLOW".to_string(), ActivityFeedRowTone::Primary),
        row(
            format!(
                "  {} -> {}",
                truncate(&flow.from, 24),
                truncate(&flow.to, 24)
            ),
            ActivityFeedRowTone::Muted,
        ),
        row(
            format!(
                "  boundary: {} -> {}{}",
                node_zone(model, &flow.from),
                node_zone(model, &flow.to),
                if flow.crosses { " · crossing" } else { "" }
            ),
            if flow.crosses {
                ActivityFeedRowTone::Warn
            } else {
                ActivityFeedRowTone::Subtle
            },
        ),
        row(
            format!("  data: {}", truncate(&flow.label, width.saturating_sub(8))),
            ActivityFeedRowTone::Subtle,
        ),
    ]
}

fn dfd_node_rows(model: &DfdModel, cursor: usize, width: usize) -> Vec<ActivityFeedPaneRow> {
    if model.nodes.is_empty() {
        return empty_deck_rows("DATA FLOW", "threat model has no DFD nodes", width);
    }
    let index = selected_index(model.nodes.len(), cursor);
    let mut rows = vec![row("  NODES".to_string(), ActivityFeedRowTone::Primary)];
    rows.extend(visible_window(model.nodes.len(), index).map(|row_index| {
        let node = &model.nodes[row_index];
        let active = row_index == index;
        row(
            format!(
                "  {} {:02} {} · {}",
                selection_marker(active),
                row_index + 1,
                truncate(&node.name, 30),
                node.zone
            ),
            activity_selection_tone(active),
        )
    }));
    rows
}

fn node_zone<'a>(model: &'a DfdModel, node_name: &str) -> &'a str {
    model
        .nodes
        .iter()
        .find(|node| node.name == node_name)
        .map(|node| node.zone.as_str())
        .unwrap_or("?")
}

fn selection_marker(active: bool) -> &'static str {
    if active {
        ">"
    } else {
        " "
    }
}

fn activity_selection_tone(active: bool) -> ActivityFeedRowTone {
    if active {
        ActivityFeedRowTone::Primary
    } else {
        ActivityFeedRowTone::Muted
    }
}

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
