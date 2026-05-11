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

    // External-facing actors come from one of three places the LLM might
    // emit, in order of preference:
    //   1. Nodes with the documented `external-entity` type (STRIDE/PASTA
    //      canon).
    //   2. Nodes the LLM declared on the "untrusted" side of a trust
    //      boundary — common when the model used `process` for every node
    //      and encoded externality in `trust_zone` instead.
    //   3. Fallback: any non-data-store node — better than returning zero
    //      actors and silently doing nothing, which is what we used to do
    //      when the threat-model output diverged from the expected shape.
    let canonical_actors = nodes
        .iter()
        .filter(|node| node.node_type == "external-entity")
        .cloned()
        .collect::<Vec<_>>();
    let untrusted_actors = nodes
        .iter()
        .filter(|node| node.node_type != "external-entity" && is_untrusted_zone(&node.trust_zone))
        .cloned()
        .collect::<Vec<_>>();
    let process_actors = nodes
        .iter()
        .filter(|node| node.node_type != "data-store")
        .cloned()
        .collect::<Vec<_>>();
    let all_actors = if !canonical_actors.is_empty() {
        canonical_actors
    } else if !untrusted_actors.is_empty() {
        untrusted_actors
    } else {
        process_actors
    };
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
        // `impact` was modeled as the {critical|high|medium|low} enum but
        // LLM outputs frequently use a free-text impact description ("Data
        // corruption, arbitrary code execution") and put the enum in
        // `severity`/`likelihood` instead. Accept either, and read free-text
        // for severity keywords so we don't silently drop every threat the
        // model produced.
        if !threat_is_high_or_critical(&threat) {
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

fn is_untrusted_zone(trust_zone: &str) -> bool {
    let zone = trust_zone.to_ascii_lowercase();
    zone.contains("untrust")
        || zone.contains("external")
        || zone.contains("internet")
        || zone.contains("public")
        || zone == "outside"
}

/// Treat a threat as high-severity if any of `severity`, `impact`,
/// `likelihood`, or a free-text impact description signals critical/high.
/// The strict-enum check used to drop every threat when the LLM emitted
/// "Data corruption, arbitrary code execution" instead of "high".
fn threat_is_high_or_critical(threat: &Value) -> bool {
    let candidates = [
        object_string_value(threat, &["severity"]),
        object_string_value(threat, &["impact"]),
        object_string_value(threat, &["likelihood"]),
    ];
    for raw in candidates.iter().flatten() {
        let lower = raw.to_ascii_lowercase();
        if matches!(lower.as_str(), "critical" | "high") {
            return true;
        }
        if contains_high_severity_keyword(&lower) {
            return true;
        }
    }
    false
}

fn contains_high_severity_keyword(impact: &str) -> bool {
    const SIGNALS: &[&str] = &[
        "arbitrary code execution",
        "remote code execution",
        "memory corruption",
        "buffer overflow",
        "heap overflow",
        "use-after-free",
        "use after free",
        "privilege escalation",
        "authentication bypass",
        "complete system compromise",
        "complete compromise",
        "code execution",
    ];
    SIGNALS.iter().any(|signal| impact.contains(signal))
}
