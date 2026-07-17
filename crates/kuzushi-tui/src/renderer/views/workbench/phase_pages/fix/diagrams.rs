use super::*;
use crate::ui_view_models::{AttackTree, DfdModel};

pub(super) fn attack_tree_lines(model: &AttackTree, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = model.empty_hint.as_deref() {
        return empty_state_panel(
            "no exploit chain",
            &[hint],
            &[("exploit-chain:scan", "build entry-to-impact chains")],
        );
    }
    let mut lines = vec![Line::styled("◇ OR — any one chain", theme::accent())];
    for chain in model.chains.iter().take(3) {
        lines.push(Line::styled(
            fit(
                &format!("{}  {}", chain.severity.label(), chain.title),
                width,
            ),
            chain_style(chain.severity.label()),
        ));
        lines.extend(
            chain
                .steps
                .iter()
                .take(3)
                .map(|step| Line::styled(fit(&format!("  └ {step}"), width), theme::muted())),
        );
    }
    append_hidden_chains(&mut lines, model.hidden_chain_count, width);
    lines
}

fn append_hidden_chains(lines: &mut Vec<Line<'static>>, hidden: usize, width: usize) {
    if hidden > 0 {
        lines.push(Line::styled(
            fit(&format!("+{hidden} more chains"), width),
            theme::muted(),
        ));
    }
}

fn chain_style(severity: &str) -> ratatui::style::Style {
    match severity {
        "CRIT" => theme::danger(),
        "HIGH" => theme::warn(),
        _ => theme::primary(),
    }
}

pub(super) fn dfd_lines(model: &DfdModel, width: usize) -> Vec<Line<'static>> {
    if let Some(hint) = model.empty_hint.as_deref() {
        return empty_state_panel(
            "no data-flow diagram",
            &[hint],
            &[("threat-model:build", "map trust zones and flows")],
        );
    }
    let crossings = model.flows.iter().filter(|flow| flow.crosses).count();
    let mut lines = vec![Line::styled(
        fit(
            &format!(
                "{} zones · {} nodes · {} flows · {crossings} boundary crossings",
                model.zones.len(),
                model.nodes.len(),
                model.flows.len()
            ),
            width,
        ),
        theme::primary(),
    )];
    lines.extend(model.flows.iter().take(5).map(|flow| {
        let marker = if flow.crosses { "▶" } else { "→" };
        let label = nonempty_label(&flow.label);
        Line::styled(
            fit(
                &format!("{marker} {} → {}{label}", flow.from, flow.to),
                width,
            ),
            if flow.crosses {
                theme::warn()
            } else {
                theme::muted()
            },
        )
    }));
    lines
}

fn nonempty_label(label: &str) -> String {
    let label = label.trim();
    if label.is_empty() {
        String::new()
    } else {
        format!(" · {label}")
    }
}
