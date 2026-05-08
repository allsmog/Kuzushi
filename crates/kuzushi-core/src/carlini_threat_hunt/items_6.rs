use super::prelude::*;
use super::*;

pub(crate) fn resolve_threat_actor_ids(
    threat: &Value,
    actor_ids: &BTreeSet<String>,
    actors_by_id: &BTreeMap<String, DfdNode>,
    nodes_by_id: &BTreeMap<String, DfdNode>,
    flows_by_id: &BTreeMap<String, DfdFlow>,
) -> Vec<String> {
    let direct = unique_strings(
        object_string_array(threat, &["actorIds", "actor_ids", "actors"])
            .into_iter()
            .filter(|actor_id| actor_ids.contains(actor_id))
            .collect(),
    );
    if !direct.is_empty() {
        return direct;
    }

    let semantic = semantic_actor_ids(threat, actors_by_id);
    if !semantic.is_empty() {
        return semantic;
    }

    let mut from_flows = Vec::new();
    for flow_id in object_string_array(threat, &["flowIds", "flow_ids", "flows"]) {
        let Some(flow) = flows_by_id.get(&flow_id) else {
            continue;
        };
        for endpoint in [&flow.source_id, &flow.target_id] {
            if actor_ids.contains(endpoint) {
                from_flows.push(endpoint.clone());
            }
        }
    }
    let from_flows = unique_strings(from_flows);
    if !from_flows.is_empty() {
        return from_flows;
    }

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
        .filter(|node_id| {
            nodes_by_id
                .get(node_id)
                .is_some_and(|node| node.node_type == "external-entity")
        })
        .collect(),
    )
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
