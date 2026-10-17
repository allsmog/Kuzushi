use super::{DfdFlowModel, DfdKind, DfdModel, DfdNodeModel, DfdSecurityKind};

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DfdOverview {
    pub executive_summary: String,
    pub zone_flows: Vec<DfdZoneFlow>,
    pub zones: Vec<DfdOverviewZone>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdZoneFlow {
    pub from_zone: String,
    pub to_zone: String,
    pub flow_count: usize,
    pub crossing_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdOverviewZone {
    pub name: String,
    pub components: Vec<DfdOverviewComponent>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DfdOverviewComponent {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub kind: DfdKind,
    pub inbound_count: usize,
    pub outgoing: Vec<DfdOverviewFlow>,
    pub context: DfdContextCounts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DfdOverviewFlow {
    pub target: String,
    pub target_zone: String,
    pub label: String,
    pub crosses: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DfdContextCounts {
    pub entry_points: usize,
    pub role_gates: usize,
    pub external_sinks: usize,
    pub trusted_callers: usize,
    pub assets: usize,
    pub threats: usize,
}

pub(crate) fn dfd_overview(model: &DfdModel) -> DfdOverview {
    DfdOverview {
        executive_summary: executive_summary(model),
        zone_flows: aggregate_zone_flows(model),
        zones: model
            .zones
            .iter()
            .map(|zone| overview_zone(model, zone))
            .collect(),
    }
}

pub(crate) fn dfd_overview_component_count(overview: &DfdOverview) -> usize {
    overview
        .zones
        .iter()
        .map(|zone| zone.components.len())
        .sum()
}

pub(crate) fn dfd_overview_component_at(
    overview: &DfdOverview,
    selection: usize,
) -> Option<(&DfdOverviewZone, &DfdOverviewComponent)> {
    let mut remaining = selection;
    for zone in &overview.zones {
        if let Some(component) = zone.components.get(remaining) {
            return Some((zone, component));
        }
        remaining = remaining.saturating_sub(zone.components.len());
    }
    None
}

fn executive_summary(model: &DfdModel) -> String {
    if let Some(context) = model.system_context.as_deref() {
        return context.to_string();
    }
    let process_names = model
        .nodes
        .iter()
        .filter(|node| node.kind == DfdKind::Process)
        .take(2)
        .map(|node| node.name.as_str())
        .collect::<Vec<_>>();
    let crossings = model.flows.iter().filter(|flow| flow.crosses).count();
    let process_summary = match process_names.as_slice() {
        [] => "No process components are recorded".to_string(),
        [one] => format!("The primary process component is {one}"),
        [first, second, ..] => {
            format!("Primary process components include {first}; {second}")
        }
    };
    let crossing_verb = if crossings == 1 { "crosses" } else { "cross" };
    format!(
        "{}: purpose not recorded in this threat model. {process_summary}. {} exchange data over {} across {}; {} {crossing_verb} a declared boundary. Rebuild to add a source-grounded product summary.",
        display_target(model),
        count_label(model.nodes.len(), "component"),
        count_label(model.flows.len(), "flow"),
        count_label(model.zones.len(), "trust zone"),
        count_label(crossings, "flow"),
    )
}

pub(crate) fn display_target(model: &DfdModel) -> &str {
    if model.target_name.trim().is_empty() {
        "modeled system"
    } else {
        &model.target_name
    }
}

fn count_label(count: usize, singular: &str) -> String {
    let suffix = if count == 1 { "" } else { "s" };
    format!("{count} {singular}{suffix}")
}

fn aggregate_zone_flows(model: &DfdModel) -> Vec<DfdZoneFlow> {
    let mut aggregates = Vec::<DfdZoneFlow>::new();
    for flow in &model.flows {
        let Some((from_zone, to_zone)) = flow_zones(model, flow) else {
            continue;
        };
        if let Some(existing) = aggregates
            .iter_mut()
            .find(|item| item.from_zone == from_zone && item.to_zone == to_zone)
        {
            existing.flow_count += 1;
            existing.crossing_count += usize::from(flow.crosses);
            continue;
        }
        aggregates.push(DfdZoneFlow {
            from_zone: from_zone.to_string(),
            to_zone: to_zone.to_string(),
            flow_count: 1,
            crossing_count: usize::from(flow.crosses),
        });
    }
    aggregates
}

fn flow_zones<'a>(model: &'a DfdModel, flow: &DfdFlowModel) -> Option<(&'a str, &'a str)> {
    Some((
        node_for_key(model, &flow.from_id)?.zone.as_str(),
        node_for_key(model, &flow.to_id)?.zone.as_str(),
    ))
}

fn overview_zone(model: &DfdModel, zone: &str) -> DfdOverviewZone {
    DfdOverviewZone {
        name: zone.to_string(),
        components: model
            .nodes
            .iter()
            .filter(|node| node.zone == zone)
            .map(|node| overview_component(model, node))
            .collect(),
    }
}

fn overview_component(model: &DfdModel, node: &DfdNodeModel) -> DfdOverviewComponent {
    DfdOverviewComponent {
        key: node.key.clone(),
        name: node.name.clone(),
        description: node.description.clone(),
        purpose: node.purpose.clone(),
        kind: node.kind,
        inbound_count: model
            .flows
            .iter()
            .filter(|flow| flow.to_id == node.key)
            .count(),
        outgoing: model
            .flows
            .iter()
            .filter(|flow| flow.from_id == node.key)
            .map(|flow| overview_flow(model, flow))
            .collect(),
        context: context_counts(model, &node.key),
    }
}

fn overview_flow(model: &DfdModel, flow: &DfdFlowModel) -> DfdOverviewFlow {
    let target = node_for_key(model, &flow.to_id);
    DfdOverviewFlow {
        target: target.map_or_else(|| flow.to.clone(), |node| node.name.clone()),
        target_zone: target.map_or_else(|| "unknown".to_string(), |node| node.zone.clone()),
        label: flow.label.clone(),
        crosses: flow.crosses,
    }
}

fn node_for_key<'a>(model: &'a DfdModel, key: &str) -> Option<&'a DfdNodeModel> {
    model.nodes.iter().find(|node| node.key == key)
}

fn context_counts(model: &DfdModel, node_key: &str) -> DfdContextCounts {
    let mut counts = DfdContextCounts::default();
    for item in model
        .security_context
        .iter()
        .filter(|item| item.target_element_ids.iter().any(|key| key == node_key))
    {
        increment_context_count(&mut counts, item.kind);
    }
    counts
}

fn increment_context_count(counts: &mut DfdContextCounts, kind: DfdSecurityKind) {
    match kind {
        DfdSecurityKind::EntryPoint => counts.entry_points += 1,
        DfdSecurityKind::RoleGate => counts.role_gates += 1,
        DfdSecurityKind::ExternalSink => counts.external_sinks += 1,
        DfdSecurityKind::TrustedCaller => counts.trusted_callers += 1,
        DfdSecurityKind::Asset => counts.assets += 1,
        DfdSecurityKind::Threat => counts.threats += 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{DfdFlowModel, DfdSecurityItem};

    #[test]
    fn overview_aggregates_zone_flows_and_preserves_component_context() {
        let model = DfdModel {
            zones: vec!["edge".into(), "app".into()],
            nodes: vec![
                node("Browser", "browser", "edge", DfdKind::Entity),
                node("API", "api", "app", DfdKind::Process),
            ],
            flows: vec![DfdFlowModel {
                key: "request".into(),
                from_id: "browser".into(),
                to_id: "api".into(),
                from: "Browser".into(),
                to: "API".into(),
                crosses: true,
                label: "HTTPS request".into(),
                boundary_ids: vec!["internet-edge".into()],
            }],
            security_context: vec![DfdSecurityItem {
                key: "EP-1".into(),
                kind: DfdSecurityKind::EntryPoint,
                label: "POST /api".into(),
                detail: String::new(),
                evidence: String::new(),
                evidence_paths: Vec::new(),
                file_paths: Vec::new(),
                target_element_ids: vec!["api".into()],
            }],
            ..Default::default()
        };

        let overview = dfd_overview(&model);

        assert_eq!(overview.zone_flows.len(), 1);
        assert_eq!(overview.zone_flows[0].crossing_count, 1);
        assert!(overview
            .executive_summary
            .contains("The primary process component is API"));
        assert_eq!(overview.zones[1].components[0].inbound_count, 1);
        assert_eq!(overview.zones[1].components[0].context.entry_points, 1);
        assert_eq!(dfd_overview_component_count(&overview), 2);
        assert_eq!(
            dfd_overview_component_at(&overview, 1)
                .map(|(zone, component)| (zone.name.as_str(), component.key.as_str())),
            Some(("app", "api"))
        );
        assert!(dfd_overview_component_at(&overview, 2).is_none());
    }

    fn node(name: &str, key: &str, zone: &str, kind: DfdKind) -> DfdNodeModel {
        DfdNodeModel {
            key: key.into(),
            name: name.into(),
            description: Some(format!("{name} summary")),
            purpose: Some(format!("Why {name} exists")),
            zone: zone.into(),
            kind,
        }
    }
}
