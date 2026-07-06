use super::*;
use crate::renderer::views::scene::diagrams::{attack_path_lines, heatmap_lines};
use crate::ui_view_models::{
    attack_tree, cached_findings_heatmap_with_selection, selected_taint_flow_path, threat_dfd_view,
    AttackTree, CodePaneModel, CodePaneRow, DfdLineKind, WorkbenchCenter, WorkbenchCenterBody,
};
use ratatui::prelude::{Line, Span};

pub(in crate::renderer::views::workbench) fn center_pane_lines(
    app: &ShellApp,
    center: &WorkbenchCenter,
    width: usize,
) -> Vec<Line<'static>> {
    match &center.body {
        WorkbenchCenterBody::Code(Some(code)) => code_pane_lines(code, width),
        WorkbenchCenterBody::Code(None) => code_empty_lines(),
        WorkbenchCenterBody::Dfd { empty_hint } => {
            dfd_pane_lines(app, empty_hint.as_deref(), width)
        }
        WorkbenchCenterBody::Chain { empty_hint } => {
            chain_pane_lines(app, empty_hint.as_deref(), width)
        }
        WorkbenchCenterBody::Flow { .. } => {
            attack_path_lines(width, &selected_taint_flow_path(app))
        }
        WorkbenchCenterBody::Risk { .. } => heatmap_lines(
            width,
            &cached_findings_heatmap_with_selection(app, app.selected_finding.as_ref()),
        ),
    }
}

fn code_empty_lines() -> Vec<Line<'static>> {
    pane_empty_state(
        "no finding selected",
        &["select a finding to show source context."],
        &[
            ("scan", "populate findings"),
            ("open <id>", "pin a finding"),
        ],
    )
}

fn dfd_pane_lines(app: &ShellApp, empty_hint: Option<&str>, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = empty_hint {
        return pane_empty_state(
            "no data-flow diagram",
            &[hint],
            &[("threat-model:build", "map trust zones and flows")],
        );
    }
    match threat_dfd_view(app, width.max(8)) {
        Some(diagram) => diagram.into_iter().map(dfd_line).collect(),
        None => pane_empty_state(
            "no data-flow nodes",
            &["threat model present but has no data-flow nodes."],
            &[("threat-model:build", "refresh the data-flow model")],
        ),
    }
}

pub(super) fn chain_pane_lines(
    app: &ShellApp,
    empty_hint: Option<&str>,
    width: usize,
) -> Vec<Line<'static>> {
    if let Some(hint) = empty_hint {
        return pane_empty_state(
            "no exploit chain",
            &[hint],
            &[("exploit-chain:scan", "build entry-to-impact chains")],
        );
    }
    chain_tree_lines(&attack_tree(app), width)
}

fn chain_tree_lines(model: &AttackTree, width: usize) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("ATTACK TREE · {} chains", model.chains.len()),
        theme::accent(),
    )])];
    for (index, chain) in model.chains.iter().enumerate() {
        lines.push(Line::from(vec![Span::styled(
            fit(
                &format!(
                    "  {}. [{}] {}",
                    index + 1,
                    chain.severity.label(),
                    chain.title
                ),
                width,
            ),
            theme::primary(),
        )]));
        lines.extend(chain.steps.iter().enumerate().map(|(step_index, step)| {
            Line::from(vec![Span::styled(
                fit(&format!("      {}. {}", step_index + 1, step), width),
                theme::muted(),
            )])
        }));
    }
    lines
}

fn code_pane_lines(code: &CodePaneModel, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = &code.empty_hint {
        return pane_empty_state(
            "source unavailable",
            &[hint],
            &[("open <id>", "select another finding with source context")],
        );
    }
    code.rows
        .iter()
        .map(|row| code_row_line(row, width))
        .collect()
}

fn code_row_line(row: &CodePaneRow, width: usize) -> Line<'static> {
    let code_budget = width.saturating_sub(10).max(8);
    let style = code_row_style(row);
    Line::from(vec![
        Span::styled(code_row_marker(row), style),
        Span::raw(" "),
        Span::styled(format!("{:>4}", row.number), theme::subtle()),
        Span::styled(" │ ", theme::subtle()),
        Span::styled(fit(&row.text, code_budget), style),
    ])
}

fn code_row_marker(row: &CodePaneRow) -> &'static str {
    if row.highlighted {
        "▶"
    } else if row.evidence {
        "•"
    } else {
        " "
    }
}

fn code_row_style(row: &CodePaneRow) -> ratatui::style::Style {
    if row.highlighted {
        theme::warn()
    } else if row.evidence {
        theme::accent()
    } else {
        theme::primary()
    }
}

fn dfd_line(line: crate::ui_view_models::DfdDiagramLine) -> Line<'static> {
    Line::from(Span::styled(line.text, dfd_style(line.kind)))
}

fn dfd_style(kind: DfdLineKind) -> ratatui::style::Style {
    match kind {
        DfdLineKind::Title | DfdLineKind::Zone => theme::accent(),
        DfdLineKind::Boundary => theme::warn(),
        DfdLineKind::Flow => theme::muted(),
        DfdLineKind::Node | DfdLineKind::Summary => theme::subtle(),
    }
}
