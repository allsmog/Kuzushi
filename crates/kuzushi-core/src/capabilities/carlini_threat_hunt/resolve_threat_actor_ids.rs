use super::*;

pub(crate) fn resolve_threat_actor_ids(
    threat: &Value,
    actor_ids: &BTreeSet<String>,
    actors_by_id: &BTreeMap<String, DfdNode>,
    nodes_by_id: &BTreeMap<String, DfdNode>,
    flows_by_id: &BTreeMap<String, DfdFlow>,
) -> Vec<String> {
    first_non_empty_actor_ids([
        direct_actor_ids(threat, actor_ids),
        semantic_actor_ids(threat, actors_by_id),
        flow_actor_ids(threat, actor_ids, flows_by_id),
        target_element_actor_ids(threat, nodes_by_id),
    ])
}

fn first_non_empty_actor_ids(candidates: [Vec<String>; 4]) -> Vec<String> {
    candidates
        .into_iter()
        .find(|candidate| !candidate.is_empty())
        .unwrap_or_default()
}

fn direct_actor_ids(threat: &Value, actor_ids: &BTreeSet<String>) -> Vec<String> {
    unique_strings(
        object_string_array(threat, &["actorIds", "actor_ids", "actors"])
            .into_iter()
            .filter(|actor_id| actor_ids.contains(actor_id))
            .collect(),
    )
}

fn flow_actor_ids(
    threat: &Value,
    actor_ids: &BTreeSet<String>,
    flows_by_id: &BTreeMap<String, DfdFlow>,
) -> Vec<String> {
    let mut from_flows = Vec::new();
    for flow_id in object_string_array(threat, &["flowIds", "flow_ids", "flows"]) {
        append_flow_actor_ids(&mut from_flows, actor_ids, flows_by_id.get(&flow_id));
    }
    unique_strings(from_flows)
}

fn append_flow_actor_ids(
    output: &mut Vec<String>,
    actor_ids: &BTreeSet<String>,
    flow: Option<&DfdFlow>,
) {
    let Some(flow) = flow else {
        return;
    };
    for endpoint in [&flow.source_id, &flow.target_id] {
        if actor_ids.contains(endpoint) {
            output.push(endpoint.clone());
        }
    }
}

fn target_element_actor_ids(
    threat: &Value,
    nodes_by_id: &BTreeMap<String, DfdNode>,
) -> Vec<String> {
    unique_strings(
        object_string_array(
            threat,
            &[
                "targetElementIds",
                "target_element_ids",
                "entrypointIds",
                "entrypoint_ids",
            ],
        )
        .into_iter()
        .filter(|node_id| is_external_entity_node(nodes_by_id.get(node_id)))
        .collect(),
    )
}

fn is_external_entity_node(node: Option<&DfdNode>) -> bool {
    node.is_some_and(|node| node.node_type == "external-entity")
}

pub(crate) fn semantic_actor_ids(
    threat: &Value,
    actors_by_id: &BTreeMap<String, DfdNode>,
) -> Vec<String> {
    let haystack = threat_search_text(threat);
    if haystack.is_empty() {
        return Vec::new();
    }
    let mut scored = actors_by_id
        .values()
        .filter_map(|actor| {
            let score = actor_semantic_score(actor, &haystack);
            (score >= 2).then(|| (actor.id.clone(), score))
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    scored.into_iter().take(3).map(|(id, _)| id).collect()
}
