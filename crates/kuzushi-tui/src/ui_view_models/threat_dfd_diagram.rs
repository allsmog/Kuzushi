//! Draws the threat model's data-flow diagram as ASCII boxes grouped by trust
//! zone, with the flows listed as labelled arrows below. Pure projection over
//! the persisted `threat-model.json` (`/dfd/{nodes,flows}`); both the Activity
//! OUTPUT pane and the Threat view's DFD tab render the same lines.

use super::activity_feed_rows::{ActivityFeedPaneRow, ActivityFeedRowTone};

const MAX_NODES: usize = 18;
const MAX_FLOWS: usize = 14;
const INDENT: usize = 2;
const BOX_GAP: usize = 2;

/// The semantic role of a diagram line, so each call site can pick a tone/style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DfdLineKind {
    Title,
    Zone,
    Node,
    Boundary,
    Flow,
    Summary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdDiagramLine {
    pub(crate) text: String,
    pub(crate) kind: DfdLineKind,
}

struct DfdNode {
    id: String,
    name: String,
    zone: String,
}

struct DfdFlow {
    source: String,
    target: String,
    label: String,
    crosses: bool,
}

/// Render the DFD as role-tagged lines, or `None` when the artifact has no nodes.
pub(crate) fn threat_dfd_diagram_lines(
    doc: &serde_json::Value,
    width: usize,
) -> Option<Vec<DfdDiagramLine>> {
    let nodes = parse_nodes(doc);
    if nodes.is_empty() {
        return None;
    }
    let flows = parse_flows(doc, &nodes);
    let zones = zones_in_order(&nodes);
    let crossings = flows.iter().filter(|flow| flow.crosses).count();

    let mut lines = vec![title_line(nodes.len(), flows.len(), width)];
    lines.extend(zone_bands(&nodes, &zones, width));
    lines.extend(flow_lines(&flows));
    lines.push(summary_line(zones.len(), flows.len(), crossings));
    Some(lines)
}

/// The same diagram, mapped to Activity OUTPUT-pane feed rows.
pub(crate) fn threat_dfd_diagram_feed_rows(
    doc: &serde_json::Value,
    width: usize,
) -> Vec<ActivityFeedPaneRow> {
    match threat_dfd_diagram_lines(doc, width) {
        Some(lines) => lines.into_iter().map(diagram_feed_row).collect(),
        None => Vec::new(),
    }
}

fn diagram_feed_row(line: DfdDiagramLine) -> ActivityFeedPaneRow {
    ActivityFeedPaneRow {
        text: line.text,
        tone: diagram_tone(line.kind),
    }
}

fn diagram_tone(kind: DfdLineKind) -> ActivityFeedRowTone {
    match kind {
        DfdLineKind::Title => ActivityFeedRowTone::Primary,
        DfdLineKind::Zone => ActivityFeedRowTone::Success,
        DfdLineKind::Boundary => ActivityFeedRowTone::Warn,
        DfdLineKind::Flow => ActivityFeedRowTone::Muted,
        DfdLineKind::Node | DfdLineKind::Summary => ActivityFeedRowTone::Subtle,
    }
}

fn line(kind: DfdLineKind, text: String) -> DfdDiagramLine {
    DfdDiagramLine { text, kind }
}

fn parse_nodes(doc: &serde_json::Value) -> Vec<DfdNode> {
    doc.pointer("/dfd/nodes")
        .and_then(serde_json::Value::as_array)
        .map(|nodes| nodes.iter().filter_map(node_from_value).take(MAX_NODES).collect())
        .unwrap_or_default()
}

fn node_from_value(value: &serde_json::Value) -> Option<DfdNode> {
    let id = string_field(value, "id")?;
    let name = string_field(value, "name").unwrap_or_else(|| id.clone());
    let zone = string_field(value, "trustZone").unwrap_or_else(|| "unzoned".to_string());
    Some(DfdNode { id, name, zone })
}

fn parse_flows(doc: &serde_json::Value, nodes: &[DfdNode]) -> Vec<DfdFlow> {
    doc.pointer("/dfd/flows")
        .and_then(serde_json::Value::as_array)
        .map(|flows| {
            flows
                .iter()
                .filter_map(|flow| flow_from_value(flow, nodes))
                .take(MAX_FLOWS)
                .collect()
        })
        .unwrap_or_default()
}

fn flow_from_value(value: &serde_json::Value, nodes: &[DfdNode]) -> Option<DfdFlow> {
    let source_id = string_field(value, "sourceId")?;
    let target_id = string_field(value, "targetId")?;
    let source_zone = zone_of(nodes, &source_id);
    let target_zone = zone_of(nodes, &target_id);
    Some(DfdFlow {
        source: display_name(nodes, &source_id),
        target: display_name(nodes, &target_id),
        label: string_field(value, "description").unwrap_or_default(),
        crosses: source_zone != target_zone,
    })
}

fn zones_in_order(nodes: &[DfdNode]) -> Vec<String> {
    let mut zones: Vec<String> = Vec::new();
    for node in nodes {
        if !zones.iter().any(|zone| zone == &node.zone) {
            zones.push(node.zone.clone());
        }
    }
    zones
}

fn zone_bands(nodes: &[DfdNode], zones: &[String], width: usize) -> Vec<DfdDiagramLine> {
    let mut out = Vec::new();
    for (index, zone) in zones.iter().enumerate() {
        if index > 0 {
            out.push(line(DfdLineKind::Boundary, boundary_text(width)));
        }
        out.extend(zone_band_lines(zone, &names_in_zone(nodes, zone), width));
    }
    out
}

fn zone_band_lines(zone: &str, names: &[String], width: usize) -> Vec<DfdDiagramLine> {
    let mut out = vec![line(DfdLineKind::Zone, zone_rule(zone, width))];
    for chunk in pack_boxes(names, width) {
        let [top, mid, bot] = box_triplet(&chunk);
        out.push(line(DfdLineKind::Node, top));
        out.push(line(DfdLineKind::Node, mid));
        out.push(line(DfdLineKind::Node, bot));
    }
    out
}

fn box_triplet(names: &[String]) -> [String; 3] {
    let indent = " ".repeat(INDENT);
    let mut rows = [indent.clone(), indent.clone(), indent];
    for (index, name) in names.iter().enumerate() {
        let gap = " ".repeat(if index > 0 { BOX_GAP } else { 0 });
        let inner = name.chars().count() + 2;
        rows[0].push_str(&format!("{gap}┌{}┐", "─".repeat(inner)));
        rows[1].push_str(&format!("{gap}│ {name} │"));
        rows[2].push_str(&format!("{gap}└{}┘", "─".repeat(inner)));
    }
    rows
}

fn pack_boxes(names: &[String], width: usize) -> Vec<Vec<String>> {
    let budget = width.saturating_sub(INDENT).max(box_width("x"));
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    let mut used = 0;
    for name in names {
        let cost = box_width(name) + gap_before(current.is_empty());
        if !current.is_empty() && used + cost > budget {
            rows.push(std::mem::take(&mut current));
            used = 0;
        }
        used += box_width(name) + gap_before(current.is_empty());
        current.push(name.clone());
    }
    if !current.is_empty() {
        rows.push(current);
    }
    rows
}

fn gap_before(is_first: bool) -> usize {
    if is_first {
        0
    } else {
        BOX_GAP
    }
}

fn box_width(name: &str) -> usize {
    name.chars().count() + 4
}

fn flow_lines(flows: &[DfdFlow]) -> Vec<DfdDiagramLine> {
    if flows.is_empty() {
        return Vec::new();
    }
    let mut out = vec![line(DfdLineKind::Zone, "FLOWS".to_string())];
    out.extend(flows.iter().map(|flow| line(DfdLineKind::Flow, flow_text(flow))));
    out
}

fn flow_text(flow: &DfdFlow) -> String {
    let arrow = if flow.crosses { "══▶" } else { "──▶" };
    if flow.label.is_empty() {
        format!("  {} {arrow} {}", flow.source, flow.target)
    } else {
        format!("  {} {arrow} {}  · {}", flow.source, flow.target, flow.label)
    }
}

fn title_line(node_count: usize, flow_count: usize, width: usize) -> DfdDiagramLine {
    let label = format!("DATA-FLOW DIAGRAM · {node_count} nodes · {flow_count} flows");
    line(DfdLineKind::Title, rule(&label, width))
}

fn summary_line(zone_count: usize, flow_count: usize, crossings: usize) -> DfdDiagramLine {
    line(
        DfdLineKind::Summary,
        format!("  {zone_count} zones · {flow_count} flows · {crossings} boundary crossings"),
    )
}

fn zone_rule(zone: &str, width: usize) -> String {
    rule(&zone.to_uppercase(), width)
}

fn rule(label: &str, width: usize) -> String {
    let prefix = format!("── {label} ");
    let used = prefix.chars().count();
    let fill = width.saturating_sub(used).min(40);
    format!("{prefix}{}", "─".repeat(fill))
}

fn boundary_text(width: usize) -> String {
    let label = " trust boundary ";
    let dashes = width.saturating_sub(label.chars().count() + INDENT) / 2;
    let side = "· ".repeat(dashes / 2);
    format!("  {side}{label}{side}")
}

fn names_in_zone(nodes: &[DfdNode], zone: &str) -> Vec<String> {
    nodes
        .iter()
        .filter(|node| node.zone == zone)
        .map(|node| node.name.clone())
        .collect()
}

fn zone_of(nodes: &[DfdNode], id: &str) -> String {
    nodes
        .iter()
        .find(|node| node.id == id)
        .map(|node| node.zone.clone())
        .unwrap_or_default()
}

fn display_name(nodes: &[DfdNode], id: &str) -> String {
    nodes
        .iter()
        .find(|node| node.id == id)
        .map(|node| node.name.clone())
        .unwrap_or_else(|| id.to_string())
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_doc() -> serde_json::Value {
        json!({
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "trustZone": "internet"},
                    {"id": "api", "name": "API server", "trustZone": "app-tier"},
                    {"id": "db", "name": "Postgres", "trustZone": "data-tier"}
                ],
                "flows": [
                    {"id": "f1", "sourceId": "user", "targetId": "api", "description": "https"},
                    {"id": "f2", "sourceId": "api", "targetId": "db", "description": "sql"}
                ]
            }
        })
    }

    #[test]
    fn diagram_lines_draw_boxes_zones_and_flows() {
        let lines = threat_dfd_diagram_lines(&sample_doc(), 70).expect("diagram");
        let kinds: Vec<DfdLineKind> = lines.iter().map(|l| l.kind).collect();

        assert_eq!(lines[0].kind, DfdLineKind::Title);
        assert!(lines[0].text.contains("3 nodes · 2 flows"));
        assert!(kinds.contains(&DfdLineKind::Boundary));
        assert!(lines.iter().any(|l| l.text.contains("┌") && l.text.contains("┐")));
        assert!(lines.iter().any(|l| l.text.contains("│ Browser │")));
        assert!(lines
            .iter()
            .any(|l| l.kind == DfdLineKind::Flow && l.text.contains("Browser ══▶ API server")));
        let summary = lines.last().expect("summary");
        assert_eq!(summary.kind, DfdLineKind::Summary);
        assert!(summary.text.contains("3 zones · 2 flows · 2 boundary crossings"));
    }

    #[test]
    fn diagram_lines_none_without_nodes() {
        assert!(threat_dfd_diagram_lines(&json!({}), 70).is_none());
        assert!(threat_dfd_diagram_lines(&json!({"dfd": {"nodes": []}}), 70).is_none());
    }

    #[test]
    fn feed_rows_carry_tones() {
        let rows = threat_dfd_diagram_feed_rows(&sample_doc(), 70);
        assert!(!rows.is_empty());
        assert_eq!(rows[0].tone, ActivityFeedRowTone::Primary);
        assert!(rows
            .iter()
            .any(|row| row.tone == ActivityFeedRowTone::Success && row.text.contains("INTERNET")));
    }

    #[test]
    fn boxes_wrap_to_width() {
        let names: Vec<String> = (0..6).map(|i| format!("node{i}")).collect();
        let rows = pack_boxes(&names, 30);
        assert!(rows.len() > 1, "narrow width should wrap boxes onto multiple rows");
    }
}
