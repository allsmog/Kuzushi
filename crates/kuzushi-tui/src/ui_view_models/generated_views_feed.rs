//! Builds the Activity OUTPUT view strip. Pages project real persisted security
//! state from `ShellApp` (findings, threat-model DFD, taint flow, exploit
//! chains) into a compact selectable list plus inspector. Live trace rows live
//! in the TASKS pane.

use super::activity_feed_rows::{ActivityFeedPaneRow, ActivityFeedRowTone};
use super::findings::{findings_model, FindingListRow};
use super::viz_data::{
    attack_tree, dfd_model, findings_heatmap, risk_by_module, taint_flow_path, AttackTree,
    DfdFlowModel, DfdModel, FindingsHeatmap, ModuleRisk, RiskByModule, TaintFlowPath,
};
use super::SeverityTone;
use crate::{ActivityDeckPage, ActivitySession, ChainSeverity, ShellApp};

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
    activity_deck_page_rows(app, session, width)
}

pub(crate) fn activity_deck_plain_extra_rows(
    app: &ShellApp,
    session: &ActivitySession,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    activity_deck_page_rows(app, session, width)
}

fn activity_deck_page_rows(
    app: &ShellApp,
    session: &ActivitySession,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = activity_deck_header_rows(app, session, width);
    rows.extend(match session.deck_page {
        ActivityDeckPage::Findings => findings_deck_rows(app, session.deck_cursor, width),
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
    if !deck_page_has_content(app, page) {
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
        ActivityDeckPage::Findings => !app.findings.is_empty(),
        ActivityDeckPage::AttackSurface | ActivityDeckPage::Heatmap => !app.findings.is_empty(),
        ActivityDeckPage::Dfd => dfd_model(app).empty_hint.is_none(),
        ActivityDeckPage::AttackPath => app.taint_flow.is_some(),
        ActivityDeckPage::ExploitChain => !app.exploit_chains.is_empty(),
    }
}

fn deck_hint(page: ActivityDeckPage, width: usize) -> String {
    let hint = match page {
        ActivityDeckPage::Findings => {
            "[/] views · j/k item · o open findings · dots mean no artifact"
        }
        _ => "[/] views · j/k item · f findings · o open · dots mean no artifact",
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
    let mut rows = vec![
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
    ];
    if let Some(snippet) = &selected.snippet {
        rows.push(row(
            format!("  snippet: {}", truncate(snippet, width.saturating_sub(11))),
            ActivityFeedRowTone::Subtle,
        ));
    }
    rows
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
    let mut rows = selected_chain_header_rows(selected, width);
    rows.extend(selected_chain_context_rows(selected, width));
    rows.extend(selected_chain_precondition_rows(selected, width));
    rows.extend(selected_chain_step_rows(selected));
    rows
}

fn selected_chain_header_rows(
    selected: &super::viz_data::AttackChain,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    vec![
        row("  SELECTED CHAIN".to_string(), ActivityFeedRowTone::Primary),
        row(
            format!(
                "  {} · {}",
                truncate(&selected.title, width.saturating_sub(10)),
                severity_label(selected.severity)
            ),
            chain_tone(selected.severity),
        ),
    ]
}

fn selected_chain_context_rows(
    selected: &super::viz_data::AttackChain,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = Vec::new();
    if let Some(impact) = &selected.impact_description {
        rows.push(row(
            format!("  impact: {}", truncate(impact, width.saturating_sub(10))),
            ActivityFeedRowTone::Warn,
        ));
    }
    if let Some(narrative) = &selected.narrative {
        rows.push(row(
            format!(
                "  narrative: {}",
                truncate(narrative, width.saturating_sub(13))
            ),
            ActivityFeedRowTone::Muted,
        ));
    }
    rows
}

fn selected_chain_precondition_rows(
    selected: &super::viz_data::AttackChain,
    width: usize,
) -> impl Iterator<Item = ActivityFeedPaneRow> + '_ {
    selected
        .preconditions
        .iter()
        .take(3)
        .map(move |precondition| {
            row(
                format!(
                    "  precondition: {}",
                    truncate(precondition, width.saturating_sub(18))
                ),
                ActivityFeedRowTone::Muted,
            )
        })
}

fn selected_chain_step_rows(
    selected: &super::viz_data::AttackChain,
) -> impl Iterator<Item = ActivityFeedPaneRow> + '_ {
    selected
        .steps
        .iter()
        .map(|step| row(format!("    → {step}"), ActivityFeedRowTone::Subtle))
}

fn chain_list_tone(severity: ChainSeverity, active: bool) -> ActivityFeedRowTone {
    if active {
        ActivityFeedRowTone::Primary
    } else {
        chain_tone(severity)
    }
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
