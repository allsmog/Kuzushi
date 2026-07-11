use super::*;
use crate::ui_view_models::{TaintFlowPath, TaintStageModel};
use ratatui::prelude::{Line, Span};

pub(in crate::renderer::views::workbench) fn flow_ladder_lines(
    model: &TaintFlowPath,
    width: usize,
) -> Vec<Line<'static>> {
    if let Some(hint) = model.empty_hint.as_deref() {
        return super::panes::pane_empty_state(
            "no data-flow ladder",
            &[hint],
            &[(
                "taint-iris-next:hunt",
                "generate a selected source-to-sink path",
            )],
        );
    }
    let mut lines = vec![flow_ladder_summary(model, width)];
    for (index, stage) in model.stages.iter().enumerate() {
        lines.extend(flow_stage_lines(index, model.stages.len(), stage, width));
    }
    lines
}

fn flow_ladder_summary(model: &TaintFlowPath, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::styled("DATA-FLOW LADDER  ", theme::label()),
        Span::styled(
            fit(
                &format!(
                    "{} · {} · {} stages",
                    model.cwe,
                    model.severity.to_ascii_uppercase(),
                    model.stages.len()
                ),
                width.saturating_sub(18),
            ),
            theme::muted(),
        ),
    ])
}

fn flow_stage_lines(
    index: usize,
    total: usize,
    stage: &TaintStageModel,
    width: usize,
) -> Vec<Line<'static>> {
    let marker = stage_marker(index, total);
    let marker_style = stage_style(index, total);
    let title_width = width.saturating_sub(8).max(8);
    let mut lines = vec![Line::from(vec![
        Span::styled(format!(" {marker} "), marker_style),
        Span::styled(fit(&stage.title, title_width), theme::heading()),
    ])];
    lines.push(Line::from(vec![
        Span::styled("   │ ", theme::subtle()),
        Span::styled(fit(&stage.location, title_width), marker_style),
    ]));
    if let Some(snippet) = stage
        .snippet
        .as_deref()
        .map(str::trim)
        .filter(|snippet| !snippet.is_empty())
    {
        lines.push(Line::from(vec![
            Span::styled("   │ ", theme::subtle()),
            Span::styled(fit(snippet, title_width), theme::muted()),
        ]));
    }
    if index + 1 < total {
        lines.push(Line::styled("   ▼", theme::subtle()));
    }
    lines
}

fn stage_marker(index: usize, total: usize) -> &'static str {
    if index == 0 {
        "◇"
    } else if index + 1 == total {
        "◆"
    } else {
        "○"
    }
}

fn stage_style(index: usize, total: usize) -> ratatui::style::Style {
    if index == 0 {
        theme::warn()
    } else if index + 1 == total {
        theme::danger()
    } else {
        theme::accent()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_names_source_hops_and_sink_without_clipping() {
        let model = TaintFlowPath {
            cwe: "CWE-918".to_string(),
            severity: "critical".to_string(),
            stages: vec![
                stage("request", "handler.rs:21"),
                stage("parse", "request.rs:41"),
                stage("dial", "net.rs:64"),
            ],
            empty_hint: None,
        };
        let lines = flow_ladder_lines(&model, 40);
        let text = lines
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("DATA-FLOW LADDER"));
        assert!(text.contains("◇ request"));
        assert!(text.contains("○ parse"));
        assert!(text.contains("◆ dial"));
        assert!(lines.iter().all(|line| line.width() <= 40));
    }

    #[test]
    fn empty_ladder_is_honest() {
        let model = TaintFlowPath {
            empty_hint: Some("selected finding has no flow".to_string()),
            ..TaintFlowPath::default()
        };
        let text = flow_ladder_lines(&model, 60)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("no data-flow ladder"));
        assert!(text.contains("selected finding has no flow"));
    }

    fn stage(title: &str, location: &str) -> TaintStageModel {
        TaintStageModel {
            title: title.to_string(),
            location: location.to_string(),
            snippet: None,
        }
    }
}
