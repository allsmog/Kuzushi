use super::*;

pub(super) fn append_actor_flows(lines: &mut Vec<String>, hunt: &ActorHunt) {
    if hunt.flows.is_empty() {
        lines.push("- (none linked)".to_string());
    } else {
        for flow in hunt.flows.iter().take(12) {
            lines.push(actor_flow_line(flow));
        }
    }
}

fn actor_flow_line(flow: &DfdFlow) -> String {
    format!(
        "- {}: {} -> {} - {}{}",
        flow.id,
        flow.source_id,
        flow.target_id,
        flow.description,
        actor_flow_details_suffix(flow)
    )
}

fn actor_flow_details_suffix(flow: &DfdFlow) -> String {
    let details = actor_flow_details(flow);
    if details.is_empty() {
        String::new()
    } else {
        format!(" ({details})")
    }
}

fn actor_flow_details(flow: &DfdFlow) -> String {
    [
        non_empty_flow_detail("protocol", flow.protocol.as_deref()),
        non_empty_flow_detail("classification", flow.data_classification.as_deref()),
        (!flow.trust_boundary_ids.is_empty())
            .then(|| format!("crosses={}", flow.trust_boundary_ids.join(", "))),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ; ")
}

fn non_empty_flow_detail(label: &str, value: Option<&str>) -> Option<String> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| format!("{label}={value}"))
}
