use super::*;

pub(crate) fn flows_for_actor(
    actor_id: &str,
    threats: &[Value],
    all_flows: &[DfdFlow],
    flows_by_id: &BTreeMap<String, DfdFlow>,
) -> Vec<DfdFlow> {
    let mut linked = BTreeMap::<String, DfdFlow>::new();
    for flow in all_flows {
        if flow.source_id == actor_id || flow.target_id == actor_id {
            linked.insert(flow.id.clone(), flow.clone());
        }
    }
    for threat in threats {
        for flow_id in object_string_array(threat, &["flowIds", "flow_ids", "flows"]) {
            if let Some(flow) = flows_by_id.get(&flow_id) {
                linked.insert(flow.id.clone(), flow.clone());
            }
        }
    }
    linked.into_values().collect()
}
