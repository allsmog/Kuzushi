use super::prelude::*;
use super::*;

#[derive(Debug, Clone)]
pub(crate) struct DfdFlow {
    pub(crate) id: String,
    pub(crate) source_id: String,
    pub(crate) target_id: String,
    pub(crate) description: String,
    pub(crate) trust_boundary_ids: Vec<String>,
    pub(crate) protocol: Option<String>,
    pub(crate) data_classification: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ActorHunt {
    pub(crate) actor: DfdNode,
    pub(crate) threats: Vec<Value>,
    pub(crate) flows: Vec<DfdFlow>,
}

#[derive(Debug, Clone)]
pub(crate) struct ActorsResult {
    pub(crate) prioritized: Vec<ActorHunt>,
    pub(crate) all_actors: Vec<DfdNode>,
}

pub(crate) fn actors_from_document(document: &Value) -> ActorsResult {
    let nodes = document
        .pointer("/dfd/nodes")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_node).collect::<Vec<_>>())
        .unwrap_or_default();
    let flows = document
        .pointer("/dfd/flows")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(parse_flow).collect::<Vec<_>>())
        .unwrap_or_default();
    let threats = document
        .get("threats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let all_actors = nodes
        .iter()
        .filter(|node| node.node_type == "external-entity")
        .cloned()
        .collect::<Vec<_>>();
    let actor_ids = all_actors
        .iter()
        .map(|actor| actor.id.clone())
        .collect::<BTreeSet<_>>();
    let actors_by_id = all_actors
        .iter()
        .cloned()
        .map(|actor| (actor.id.clone(), actor))
        .collect::<BTreeMap<_, _>>();
    let nodes_by_id = nodes
        .iter()
        .cloned()
        .map(|node| (node.id.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let flows_by_id = flows
        .iter()
        .cloned()
        .map(|flow| (flow.id.clone(), flow))
        .collect::<BTreeMap<_, _>>();

    let mut high_threats = BTreeMap::<String, Vec<Value>>::new();
    for threat in threats {
        let impact = object_string_value(&threat, &["impact"])
            .unwrap_or_else(|| "medium".to_string())
            .to_ascii_lowercase();
        if !matches!(impact.as_str(), "critical" | "high") {
            continue;
        }
        for actor_id in resolve_threat_actor_ids(
            &threat,
            &actor_ids,
            &actors_by_id,
            &nodes_by_id,
            &flows_by_id,
        ) {
            high_threats
                .entry(actor_id)
                .or_default()
                .push(threat.clone());
        }
    }

    let mut prioritized = all_actors
        .iter()
        .filter_map(|actor| {
            let threats = high_threats.get(&actor.id)?.clone();
            Some(ActorHunt {
                actor: actor.clone(),
                flows: flows_for_actor(&actor.id, &threats, &flows, &flows_by_id),
                threats,
            })
        })
        .collect::<Vec<_>>();
    prioritized.sort_by(|left, right| {
        critical_count(&right.threats)
            .cmp(&critical_count(&left.threats))
            .then_with(|| right.threats.len().cmp(&left.threats.len()))
            .then_with(|| left.actor.id.cmp(&right.actor.id))
    });

    ActorsResult {
        prioritized,
        all_actors,
    }
}
