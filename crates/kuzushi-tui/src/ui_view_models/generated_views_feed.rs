//! Builds the Activity OUTPUT view strip. Pages project real persisted security
//! state from `ShellApp` (findings, threat-model DFD, taint flow, exploit
//! chains) into a compact selectable list plus inspector. Live trace rows live
//! in the TASKS pane.

use super::activity_feed_rows::{
    activity_feed_pane_rows, ActivityFeedPaneRow, ActivityFeedRowTone,
};
use super::findings::{findings_model, FindingListRow};
use super::viz_data::{
    attack_tree, cached_findings_heatmap, cached_risk_by_module, dfd_model, taint_flow_path,
    AttackTree, DfdFlowModel, DfdModel, FindingsHeatmap, ModuleRisk, RiskByModule, TaintFlowPath,
};
use super::SeverityTone;
use crate::{
    ActivityDeckPage, ActivityRouteState, ActivitySession, ChainSeverity, ReconSnapshot, ShellApp,
};
use kuzushi_core::RunSummary;
use std::time::Instant;

const DECK_WINDOW_ROWS: usize = 7;

/// The Activity right pane as a navigable view strip. Every page renders one
/// real persisted model with a selected item inspector instead of dumping all
/// generated views below the task stream.
pub(crate) fn activity_deck_rows(
    app: &ShellApp,
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    running_tool: Option<&str>,
) -> Vec<ActivityFeedPaneRow> {
    activity_deck_page_rows(app, session, route, width, running_tool)
}

pub(crate) fn activity_deck_plain_extra_rows(
    app: &ShellApp,
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    running_tool: Option<&str>,
) -> Vec<ActivityFeedPaneRow> {
    activity_deck_page_rows(app, session, route, width, running_tool)
}

fn activity_deck_page_rows(
    app: &ShellApp,
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    running_tool: Option<&str>,
) -> Vec<ActivityFeedPaneRow> {
    if running_tool == Some("context:build") {
        return context_build_trace_rows(session, route, width, running_tool);
    }
    let Some(page) = effective_deck_page(app, route.deck_page) else {
        return no_artifact_rows(app, session, width);
    };
    let mut rows = activity_deck_header_rows(app, session, page);
    rows.extend(match page {
        ActivityDeckPage::Findings => findings_deck_rows(app, route.deck_cursor, width),
        ActivityDeckPage::AttackSurface => {
            attack_surface_deck_rows(&cached_risk_by_module(app), route.deck_cursor, width)
        }
        ActivityDeckPage::Dfd => dfd_deck_rows(&dfd_model(app), route.deck_cursor, width),
        ActivityDeckPage::Heatmap => {
            heatmap_deck_rows(&cached_findings_heatmap(app), route.deck_cursor, width)
        }
        ActivityDeckPage::AttackPath => {
            attack_path_deck_rows(&taint_flow_path(app), route.deck_cursor, width)
        }
        ActivityDeckPage::ExploitChain => {
            exploit_chain_deck_rows(&attack_tree(app), route.deck_cursor, width)
        }
        ActivityDeckPage::Recon => {
            recon_deck_rows(app.domain().recon_snapshot(), route.deck_cursor, width)
        }
    });
    rows.into_iter()
        .map(|paned| row(clip(paned.text, width), paned.tone))
        .collect()
}

fn activity_deck_header_rows(
    app: &ShellApp,
    session: &ActivitySession,
    active: ActivityDeckPage,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = vec![row(deck_tabs(app, active), ActivityFeedRowTone::Primary)];
    if let Some(status) = artifact_source_status_row(app, session) {
        rows.push(status);
    }
    rows
}

fn deck_tabs(app: &ShellApp, active: ActivityDeckPage) -> String {
    let labels = ActivityDeckPage::ALL
        .iter()
        .copied()
        .filter(|page| deck_page_has_content(app, *page))
        .map(|page| deck_tab(page, active))
        .collect::<Vec<_>>()
        .join(" ");
    format!("views  {labels}")
}

fn deck_tab(page: ActivityDeckPage, active: ActivityDeckPage) -> String {
    let label = page.label();
    if page == active {
        format!("[{label}]")
    } else {
        format!(" {label} ")
    }
}

fn effective_deck_page(app: &ShellApp, requested: ActivityDeckPage) -> Option<ActivityDeckPage> {
    deck_page_has_content(app, requested)
        .then_some(requested)
        .or_else(|| {
            ActivityDeckPage::ALL
                .iter()
                .copied()
                .find(|page| deck_page_has_content(app, *page))
        })
}

fn no_artifact_rows(
    app: &ShellApp,
    session: &ActivitySession,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = vec![row(
        "views  [no artifacts yet]".to_string(),
        ActivityFeedRowTone::Muted,
    )];
    if let Some(status) = artifact_source_status_row(app, session) {
        rows.push(status);
    }
    let hint = if session.tasks.is_empty() {
        "  This run has not produced a generated artifact."
    } else {
        "  No generated artifacts yet — live progress remains in TASKS."
    };
    rows.extend([
        row(rule("OUTPUT", width), ActivityFeedRowTone::Subtle),
        row(hint.to_string(), ActivityFeedRowTone::Muted),
    ]);
    rows
}

fn context_build_trace_rows(
    session: &ActivitySession,
    route: &ActivityRouteState,
    width: usize,
    running_tool: Option<&str>,
) -> Vec<ActivityFeedPaneRow> {
    let mut rows = vec![
        row(
            "views  [build trace]".to_string(),
            ActivityFeedRowTone::Primary,
        ),
        row(rule("CONTEXT BUILD", width), ActivityFeedRowTone::Success),
        row(
            format!("  CURRENT  {}", current_context_stage(session)),
            ActivityFeedRowTone::Primary,
        ),
    ];
    rows.extend(context_build_stage_ladder(session));
    rows.push(row(
        "  RECENT SIGNALS".to_string(),
        ActivityFeedRowTone::Muted,
    ));
    rows.extend(activity_feed_pane_rows(
        session,
        route,
        width.saturating_sub(2),
        running_tool,
        Instant::now(),
    ));
    rows.into_iter()
        .map(|paned| row(clip(paned.text, width), paned.tone))
        .collect()
}

fn current_context_stage(session: &ActivitySession) -> String {
    session
        .events
        .back()
        .map(|event| event.step.label.clone())
        .or_else(|| {
            session
                .tasks
                .get("context:build")
                .map(|task| task.last_label.clone())
        })
        .filter(|label| !label.trim().is_empty())
        .unwrap_or_else(|| "waiting for the first progress signal".to_string())
}

fn context_build_stage_ladder(session: &ActivitySession) -> Vec<ActivityFeedPaneRow> {
    const STAGES: [&str; 5] = [
        "scan repository files",
        "infer repository context",
        "build repository inventory",
        "map attack surface",
        "write context snapshot",
    ];
    let current = context_build_stage_position(&current_context_stage(session));
    STAGES
        .iter()
        .enumerate()
        .map(|(index, label)| context_build_stage_row(index + 1, current, label))
        .collect()
}

fn context_build_stage_position(label: &str) -> usize {
    label
        .split_whitespace()
        .nth(1)
        .and_then(|fraction| fraction.split('/').next())
        .and_then(|position| position.parse::<usize>().ok())
        .filter(|position| (1..=5).contains(position))
        .unwrap_or(1)
}

fn context_build_stage_row(position: usize, current: usize, label: &str) -> ActivityFeedPaneRow {
    let (glyph, tone) = match position.cmp(&current) {
        std::cmp::Ordering::Less => ("✓", ActivityFeedRowTone::Success),
        std::cmp::Ordering::Equal => ("▸", ActivityFeedRowTone::Primary),
        std::cmp::Ordering::Greater => ("·", ActivityFeedRowTone::Subtle),
    };
    row(format!("  {glyph} {position}/5  {label}"), tone)
}

fn deck_page_has_content(app: &ShellApp, page: ActivityDeckPage) -> bool {
    match page {
        ActivityDeckPage::Findings => !app.findings().is_empty(),
        ActivityDeckPage::AttackSurface | ActivityDeckPage::Heatmap => !app.findings().is_empty(),
        ActivityDeckPage::Dfd => dfd_model(app).empty_hint.is_none(),
        ActivityDeckPage::AttackPath => app.domain().taint_flow().is_some(),
        ActivityDeckPage::ExploitChain => app.domain().has_exploit_chains(),
        ActivityDeckPage::Recon => app
            .domain()
            .recon_snapshot()
            .is_some_and(ReconSnapshot::has_evidence),
    }
}

fn artifact_source_status_row(
    app: &ShellApp,
    session: &ActivitySession,
) -> Option<ActivityFeedPaneRow> {
    let summary = active_run_summary(app, session)?;
    let status = summary.status.trim().to_ascii_lowercase();
    artifact_source_status_text(&status, summary.error.as_deref()).map(|text| {
        let tone = artifact_source_status_tone(&status);
        row(
            format!("  artifact source: run {} {text}", session.run_id),
            tone,
        )
    })
}

fn active_run_summary(app: &ShellApp, session: &ActivitySession) -> Option<RunSummary> {
    let target = app.target()?;
    let crate::app::ViewDataState::Ready(index) = app
        .workbench_cache()
        .borrow()
        .cached_run_summary_index(Some(target))
    else {
        return None;
    };
    index.get(&session.run_id).cloned()
}

fn artifact_source_status_text(status: &str, reason: Option<&str>) -> Option<String> {
    let label = artifact_source_status_label(status)?;
    let mut text = format!("{label}; output may be incomplete");
    if let Some(reason) = reason.map(str::trim).filter(|reason| !reason.is_empty()) {
        text.push_str(&format!(" · reason: {reason}"));
    }
    Some(text)
}

fn artifact_source_status_label(status: &str) -> Option<String> {
    match status {
        "partial" => Some("is partial".to_string()),
        "failed" => Some("failed".to_string()),
        "interrupted" => Some("was interrupted".to_string()),
        "canceled" | "cancelled" => Some("was canceled".to_string()),
        "paused" => Some("was paused or canceled".to_string()),
        "skipped" => Some("was skipped".to_string()),
        other if terminal_but_not_success(other) => Some(format!("ended as {other}")),
        _ => None,
    }
}

fn terminal_but_not_success(status: &str) -> bool {
    !status.is_empty() && !matches!(status, "running" | "queued" | "started" | "completed")
}

fn artifact_source_status_tone(status: &str) -> ActivityFeedRowTone {
    if status == "failed" {
        ActivityFeedRowTone::Danger
    } else {
        ActivityFeedRowTone::Warn
    }
}

// ── Activity artifact pages ───────────────────────────────────────────────

fn recon_deck_rows(
    snapshot: Option<&ReconSnapshot>,
    cursor: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let Some(snapshot) = snapshot.filter(|snapshot| snapshot.has_evidence()) else {
        return empty_deck_rows("RECON EVIDENCE", "no recon evidence captured yet", width);
    };
    let model = super::recon_snapshot_activity_model(snapshot, usize::MAX);
    let index = selected_index(model.rows.len(), cursor);
    let mut rows = recon_header_rows(snapshot, width);
    rows.extend(recon_window_rows(&model.rows, index, width));
    rows.push(row(String::new(), ActivityFeedRowTone::Subtle));
    rows.extend(selected_recon_rows(&model.rows[index], snapshot, width));
    rows
}

fn recon_header_rows(snapshot: &ReconSnapshot, width: usize) -> Vec<ActivityFeedPaneRow> {
    vec![
        row(rule("RECON EVIDENCE", width), ActivityFeedRowTone::Success),
        row(
            format!(
                "  {} hosts · {} services · {} notes · {}",
                snapshot.hosts.len(),
                snapshot.services.len(),
                snapshot.notes.len(),
                snapshot.last_tool.as_deref().unwrap_or("recon")
            ),
            ActivityFeedRowTone::Subtle,
        ),
        row(
            "  IMPORTED EVIDENCE".to_string(),
            ActivityFeedRowTone::Primary,
        ),
    ]
}

fn recon_window_rows(
    evidence: &[super::ModuleActivityRow],
    selected: usize,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    visible_window(evidence.len(), selected)
        .map(|index| recon_list_row(&evidence[index], index == selected, width))
        .collect()
}

fn recon_list_row(
    evidence: &super::ModuleActivityRow,
    active: bool,
    width: usize,
) -> ActivityFeedPaneRow {
    let [first, second, third, fourth] = &evidence.cells;
    let text = match evidence.kind {
        super::ModuleActivityKind::ReconService => {
            format!("service  {first}:{second} · {third} · {fourth}")
        }
        super::ModuleActivityKind::ReconHost => format!("host     {first} · {second}"),
        super::ModuleActivityKind::ReconNote => format!("note     {first} · {third}"),
        _ => format!("{first} · {second}"),
    };
    row(
        format!(
            "  {} {}",
            selection_marker(active),
            truncate(&text, width.saturating_sub(5))
        ),
        activity_selection_tone(active),
    )
}

fn selected_recon_rows(
    evidence: &super::ModuleActivityRow,
    snapshot: &ReconSnapshot,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    let [first, second, third, fourth] = &evidence.cells;
    let detail = [first, second, third, fourth]
        .into_iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join(" · ");
    vec![
        row(
            "  SELECTED RECON EVIDENCE".to_string(),
            ActivityFeedRowTone::Primary,
        ),
        row(
            format!("  {}", truncate(&detail, width.saturating_sub(2))),
            ActivityFeedRowTone::Muted,
        ),
        row(
            format!(
                "  target: {}",
                snapshot.last_target.as_deref().unwrap_or("workspace")
            ),
            ActivityFeedRowTone::Subtle,
        ),
        row(
            "  action: o opens full recon detail".to_string(),
            ActivityFeedRowTone::Subtle,
        ),
    ]
}

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
            format!(
                "  attacker goal · {} chains",
                model.chains.len() + model.hidden_chain_count
            ),
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

fn selected_chain_step_rows(selected: &super::viz_data::AttackChain) -> Vec<ActivityFeedPaneRow> {
    let mut rows = selected
        .steps
        .iter()
        .map(|step| row(format!("    → {step}"), ActivityFeedRowTone::Subtle))
        .collect::<Vec<_>>();
    if selected.hidden_step_count > 0 {
        rows.push(row(
            format!("    +{} more steps", selected.hidden_step_count),
            ActivityFeedRowTone::Muted,
        ));
    }
    rows
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
        row(rule(title, width), ActivityFeedRowTone::Label),
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
        .filter(|(_, count)| **count > 0)
        .map(|(label, count)| format!("{label} {count}"))
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
    use super::*;
    use kuzushi_core::{
        write_run_summary, ReconHost, ReconNote, ReconService, V2Config, WorkspaceTarget,
    };

    #[test]
    fn live_context_build_uses_one_truthful_build_trace_instead_of_empty_artifact_tabs() {
        let app = ShellApp::new(V2Config::default(), None);
        let mut session = ActivitySession::new("context-run");
        session.apply_step(
            kuzushi_core::RunTraceStep::new(
                1,
                "tool-progress",
                "stage 3/5 · building repository inventory",
            )
            .with_module_id("context")
            .with_verb("build"),
        );
        let route = ActivityRouteState::default();

        let rows = activity_deck_page_rows(&app, &session, &route, 120, Some("context:build"));
        let rendered = rows
            .iter()
            .map(|row| row.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("views  [build trace]"), "{rendered}");
        assert!(rendered.contains("CONTEXT BUILD"), "{rendered}");
        assert!(
            rendered.contains("building repository inventory"),
            "{rendered}"
        );
        assert!(rendered.contains("✓ 2/5"), "{rendered}");
        assert!(rendered.contains("▸ 3/5"), "{rendered}");
        assert_eq!(rows[0].text, "views  [build trace]");
    }

    #[test]
    fn output_without_artifacts_does_not_advertise_empty_generated_views() {
        let app = ShellApp::new(V2Config::default(), None);
        let session = ActivitySession::new("empty-run");
        let route = ActivityRouteState::default();

        let rows = activity_deck_page_rows(&app, &session, &route, 120, None);
        let rendered = rows
            .iter()
            .map(|row| row.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("[no artifacts yet]"), "{rendered}");
        assert!(!rendered.contains("findings·"), "{rendered}");
        assert!(!rendered.contains("surface·"), "{rendered}");
    }

    #[test]
    fn recon_deck_renders_imported_host_service_and_note_evidence() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.domain_mut().set_recon_snapshot(recon_snapshot());
        let session = ActivitySession::new("run-recon");
        let mut route = ActivityRouteState::default();
        route.set_deck_page(ActivityDeckPage::Recon);

        let rows = activity_deck_page_rows(&app, &session, &route, 120, None);
        let rendered = rows
            .iter()
            .map(|row| row.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("RECON EVIDENCE"), "{rendered}");
        assert!(rendered.contains("acme.example:443"), "{rendered}");
        assert!(rendered.contains("httpx"), "{rendered}");
        assert!(rendered.contains("status-code"), "{rendered}");
    }

    #[test]
    fn activity_deck_labels_partial_run_artifacts() {
        let fixture = app_with_run_summary("run-partial", |mut summary| {
            summary.status = "partial".to_string();
            summary.error = Some("scanner timeout after collecting partial findings".to_string());
            summary
        });

        let rows =
            activity_deck_page_rows(&fixture.app, &fixture.session, &fixture.route, 160, None);

        let status = artifact_source_status(&rows).expect("artifact source status row");
        assert_eq!(status.tone, ActivityFeedRowTone::Warn);
        assert!(
            status.text.contains("run run-partial is partial"),
            "{status:?}"
        );
        assert!(
            status.text.contains("output may be incomplete"),
            "{status:?}"
        );
        assert!(status.text.contains("scanner timeout"), "{status:?}");
    }

    #[test]
    fn activity_deck_labels_failed_run_artifacts_as_danger() {
        let fixture = app_with_run_summary("run-failed", |summary| {
            summary.failed("semgrep exited nonzero")
        });

        let rows =
            activity_deck_page_rows(&fixture.app, &fixture.session, &fixture.route, 160, None);

        let status = artifact_source_status(&rows).expect("artifact source status row");
        assert_eq!(status.tone, ActivityFeedRowTone::Danger);
        assert!(status.text.contains("run run-failed failed"), "{status:?}");
        assert!(status.text.contains("semgrep exited nonzero"), "{status:?}");
    }

    #[test]
    fn activity_deck_omits_artifact_warning_for_completed_runs() {
        let fixture = app_with_run_summary("run-completed", kuzushi_core::RunSummary::complete);

        let rows =
            activity_deck_page_rows(&fixture.app, &fixture.session, &fixture.route, 160, None);

        assert!(artifact_source_status(&rows).is_none(), "{rows:?}");
    }

    fn app_with_run_summary(
        run_id: &str,
        update: impl FnOnce(RunSummary) -> RunSummary,
    ) -> ActivityDeckFixture {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let summary = update(RunSummary::running(
            run_id,
            "scan",
            Some("sast:scan".to_string()),
            workspace.root().display().to_string(),
        ));
        write_run_summary(workspace.root(), &summary).unwrap();

        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.hydrate_all_view_data_for_test();
        let session = ActivitySession::new(run_id);
        ActivityDeckFixture {
            _temp: temp,
            app,
            session,
            route: ActivityRouteState::default(),
        }
    }

    struct ActivityDeckFixture {
        _temp: tempfile::TempDir,
        app: ShellApp,
        session: ActivitySession,
        route: ActivityRouteState,
    }

    fn artifact_source_status(rows: &[ActivityFeedPaneRow]) -> Option<&ActivityFeedPaneRow> {
        rows.iter()
            .find(|row| row.text.contains("artifact source:"))
    }

    fn recon_snapshot() -> ReconSnapshot {
        ReconSnapshot {
            hosts: vec![ReconHost {
                id: "h1".to_string(),
                workspace_id: "ws".to_string(),
                address: "192.0.2.10".to_string(),
                hostname: Some("acme.example".to_string()),
                state: "alive".to_string(),
            }],
            services: vec![ReconService {
                id: "s1".to_string(),
                host_id: "h1".to_string(),
                port: 443,
                proto: "tcp".to_string(),
                name: Some("https".to_string()),
                banner: Some("HTTP/2".to_string()),
                state: "open".to_string(),
            }],
            notes: vec![ReconNote {
                id: "n1".to_string(),
                workspace_id: "ws".to_string(),
                host_id: Some("h1".to_string()),
                service_id: Some("s1".to_string()),
                ntype: "httpx".to_string(),
                data: serde_json::json!({ "status-code": 200 }),
            }],
            last_tool: Some("recon:import".to_string()),
            last_target: Some("httpx.json".to_string()),
        }
    }
}
