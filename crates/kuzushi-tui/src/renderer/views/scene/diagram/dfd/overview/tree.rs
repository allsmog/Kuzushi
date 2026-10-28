use super::{count_label, diagram_muted, diagram_primary, diagram_style};
use crate::theme;
use crate::ui_view_models::{
    dfd_overview_component_count, display_target, DfdContextCounts, DfdKind, DfdModel, DfdOverview,
    DfdOverviewComponent, DfdOverviewFlow, DfdOverviewZone,
};
use ratatui::text::Line;

pub(super) struct ComponentTreeDocument {
    pub lines: Vec<Line<'static>>,
    pub selected_start: usize,
    pub selected_end: usize,
    pub selected_zone: String,
    pub selection: usize,
    pub total: usize,
}

pub(super) fn component_tree_document(
    model: &DfdModel,
    overview: &DfdOverview,
    selection: usize,
) -> ComponentTreeDocument {
    let total = dfd_overview_component_count(overview);
    let selection = selection.min(total.saturating_sub(1));
    let mut builder = TreeBuilder::new(root_line(model), selection, total);
    for (index, zone) in overview.zones.iter().enumerate() {
        builder.append_zone(zone, index + 1 == overview.zones.len());
    }
    builder.finish()
}

struct TreeBuilder {
    lines: Vec<Line<'static>>,
    component_index: usize,
    selected_start: usize,
    selected_end: usize,
    selected_zone: String,
    selection: usize,
    total: usize,
}

impl TreeBuilder {
    fn new(root: Line<'static>, selection: usize, total: usize) -> Self {
        Self {
            lines: vec![root],
            component_index: 0,
            selected_start: 0,
            selected_end: 1,
            selected_zone: "no components".to_string(),
            selection,
            total,
        }
    }

    fn append_zone(&mut self, zone: &DfdOverviewZone, last: bool) {
        self.lines.push(zone_line(zone, last));
        let zone_indent = if last { "   " } else { "│  " };
        for (index, component) in zone.components.iter().enumerate() {
            let component_last = index + 1 == zone.components.len();
            self.append_component(component, &zone.name, zone_indent, component_last);
        }
    }

    fn append_component(
        &mut self,
        component: &DfdOverviewComponent,
        zone: &str,
        zone_indent: &str,
        last: bool,
    ) {
        let selected = self.component_index == self.selection;
        let start = self.lines.len();
        self.lines
            .push(component_line(component, zone_indent, last, selected));
        append_component_detail(&mut self.lines, component, zone_indent, last);
        if selected {
            self.selected_start = start;
            self.selected_end = self.lines.len();
            self.selected_zone = zone.to_string();
        }
        self.component_index += 1;
    }

    fn finish(self) -> ComponentTreeDocument {
        ComponentTreeDocument {
            lines: self.lines,
            selected_start: self.selected_start,
            selected_end: self.selected_end,
            selected_zone: self.selected_zone,
            selection: self.selection,
            total: self.total,
        }
    }
}

fn root_line(model: &DfdModel) -> Line<'static> {
    Line::styled(
        format!(
            "◇ {} · {}",
            display_target(model),
            count_label(model.nodes.len(), "component")
        ),
        theme::heading(),
    )
}

fn zone_line(zone: &DfdOverviewZone, last: bool) -> Line<'static> {
    let branch = if last { "└─" } else { "├─" };
    Line::styled(
        format!(
            "{branch} {} · {}",
            zone.name,
            count_label(zone.components.len(), "component")
        ),
        theme::accent(),
    )
}

fn component_line(
    component: &DfdOverviewComponent,
    zone_indent: &str,
    last: bool,
    selected: bool,
) -> Line<'static> {
    let branch = if last { "└─" } else { "├─" };
    let marker = if selected { "› " } else { "  " };
    let text = format!(
        "{zone_indent}{branch} {marker}◇ {} · {} · in {} · out {}",
        component.name,
        kind_label(component.kind),
        component.inbound_count,
        component.outgoing.len()
    );
    let style = if selected {
        theme::selection()
    } else {
        diagram_style(diagram_primary())
    };
    Line::styled(text, style)
}

fn append_component_detail(
    lines: &mut Vec<Line<'static>>,
    component: &DfdOverviewComponent,
    zone_indent: &str,
    last: bool,
) {
    let indent = format!("{zone_indent}{}  ", if last { " " } else { "│" });
    let children = component_children(component);
    let child_count = children.len();
    for (index, (text, crossing)) in children.into_iter().enumerate() {
        lines.extend(child_lines(
            &indent,
            &text,
            crossing,
            index + 1 == child_count,
        ));
    }
}

fn child_lines(indent: &str, text: &str, crossing: bool, last: bool) -> Vec<Line<'static>> {
    let continuation = if last { "   " } else { "│  " };
    text.split('\n')
        .enumerate()
        .map(|(index, paragraph)| {
            if index == 0 {
                return child_line(indent, paragraph, crossing, last);
            }
            Line::styled(
                format!("{indent}{continuation}{paragraph}"),
                child_style(crossing),
            )
        })
        .collect()
}

fn child_line(indent: &str, text: &str, crossing: bool, last: bool) -> Line<'static> {
    let branch = if last { "└─" } else { "├─" };
    Line::styled(format!("{indent}{branch} {text}"), child_style(crossing))
}

fn child_style(crossing: bool) -> ratatui::style::Style {
    let color = if crossing {
        theme::SEV_HIGH
    } else {
        diagram_muted()
    };
    diagram_style(color)
}

fn component_children(component: &DfdOverviewComponent) -> Vec<(String, bool)> {
    let mut children = vec![
        (description_label(component), false),
        (purpose_label(component), false),
    ];
    children.extend(
        component
            .topology_notice()
            .map(|notice| (format!("flows · {notice}"), false)),
    );
    children.extend(component.outgoing.iter().map(flow_child));
    if let Some(context) = context_label(component.context) {
        children.push((context, false));
    }
    children
}

fn description_label(component: &DfdOverviewComponent) -> String {
    format!(
        "does · {}",
        component
            .description
            .as_deref()
            .unwrap_or("not recorded in the threat model")
    )
}

fn purpose_label(component: &DfdOverviewComponent) -> String {
    format!(
        "purpose · {}",
        component
            .purpose
            .as_deref()
            .unwrap_or("not recorded; rebuild the threat model")
    )
}

fn flow_child(flow: &DfdOverviewFlow) -> (String, bool) {
    let crossing = if flow.crosses { " · boundary" } else { "" };
    let label = if flow.label.trim().is_empty() {
        "data flow"
    } else {
        flow.label.as_str()
    };
    (
        format!(
            "→ {} [{}] · {label}{crossing}",
            flow.target, flow.target_zone
        ),
        flow.crosses,
    )
}

fn context_label(counts: DfdContextCounts) -> Option<String> {
    let entries = [
        (counts.entry_points, "entry"),
        (counts.role_gates, "gate"),
        (counts.external_sinks, "sink"),
        (counts.trusted_callers, "caller"),
        (counts.assets, "asset"),
        (counts.threats, "threat"),
    ]
    .into_iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| count_label(count, label))
    .collect::<Vec<_>>();
    (!entries.is_empty()).then(|| format!("context · {}", entries.join(" · ")))
}

fn kind_label(kind: DfdKind) -> &'static str {
    match kind {
        DfdKind::Entity => "entity",
        DfdKind::Process => "process",
        DfdKind::Store => "store",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{dfd_overview, DfdFlowModel, DfdNodeModel};

    #[test]
    fn tree_lists_flows_and_marks_the_selected_component() {
        let model = sample_model();
        let document = component_tree_document(&model, &dfd_overview(&model), 1);
        let text = document
            .lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        assert_eq!(text.matches("→ API [app]").count(), 1);
        assert!(text.contains("does · Receives browser requests"));
        assert!(text.contains("purpose · Why API exists"));
        assert!(text.contains("edge · 1 component"));
        assert!(text.contains("› ◇ API"));
        assert_eq!(
            document.lines[document.selected_start].style,
            theme::selection()
        );
        assert_eq!(document.selected_zone, "app");
        assert_eq!((document.selection, document.total), (1, 2));
    }

    #[test]
    fn component_paragraphs_keep_rows_and_the_selected_tree_anchor() {
        let mut model = sample_model();
        model.nodes[1].description = Some("First paragraph.\n\nSecond paragraph.".into());
        let overview = crate::ui_view_models::dfd_overview(&model);
        let tree = component_tree_document(&model, &overview, 1);
        let rows = tree.lines.iter().map(Line::to_string).collect::<Vec<_>>();
        let first = rows
            .iter()
            .position(|row| row.contains("First paragraph."))
            .unwrap();
        let second = rows
            .iter()
            .position(|row| row.contains("Second paragraph."))
            .unwrap();
        assert_eq!(second, first + 2);
        assert!(tree.selected_start < first && tree.selected_end > second);
        assert!(!rows[first + 1].chars().any(char::is_alphanumeric));
        assert!(!rows.iter().any(|row| row.contains('\n')));
    }

    fn sample_model() -> DfdModel {
        DfdModel {
            target_name: "sample".into(),
            zones: vec!["edge".into(), "app".into()],
            nodes: vec![
                node(
                    "browser",
                    "Browser",
                    "Supplies untrusted input",
                    "edge",
                    DfdKind::Entity,
                ),
                node(
                    "api",
                    "API",
                    "Receives browser requests",
                    "app",
                    DfdKind::Process,
                ),
            ],
            flows: vec![DfdFlowModel {
                key: "request".into(),
                from_id: "browser".into(),
                to_id: "api".into(),
                from: "Browser".into(),
                to: "API".into(),
                crosses: true,
                label: "request".into(),
                boundary_ids: vec!["edge".into()],
            }],
            ..Default::default()
        }
    }

    fn node(key: &str, name: &str, description: &str, zone: &str, kind: DfdKind) -> DfdNodeModel {
        DfdNodeModel {
            key: key.into(),
            name: name.into(),
            description: Some(description.into()),
            purpose: Some(format!("Why {name} exists")),
            zone: zone.into(),
            kind,
        }
    }
}
