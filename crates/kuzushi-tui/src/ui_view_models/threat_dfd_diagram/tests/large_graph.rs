use super::*;
use crate::ui_view_models::{
    dfd_security_items_for_selection, dfd_selectable_count, dfd_selected_item,
    dfd_selection_for_key, DfdLinkState, DfdSelected,
};

fn document(count: usize) -> serde_json::Value {
    let nodes = (0..count)
        .map(|i| {
            json!({
                "id":format!("component-{i:03}"),"name":format!("Component {i:03}"),
                "type":"process","trustZone":format!("zone-{}",i % 3)
            })
        })
        .collect::<Vec<_>>();
    let flows = (1..count).map(|i| json!({
        "id":format!("flow-{i:03}"),"sourceId":format!("component-{:03}",i-1),
        "targetId":format!("component-{i:03}"),"description":format!("Declared transfer {i:03}")
    })).collect::<Vec<_>>();
    json!({
        "title":"Owned large diagram fixture","systemContext":"Manually declared topology for UI checks; no runtime flow or vulnerability claim.",
        "dfd":{"nodes":nodes,"flows":flows,"trustBoundaries":[{
            "id":"tail-boundary","name":"Tail boundary","innerZone":"zone-2","outerZone":"zone-1",
            "crossingFlowIds":[format!("flow-{:03}",count-1)]
        }]},
        "attackSurface":{"entryPoints":[{
            "id":"tail-evidence","name":"Tail source","path":"modules/tail.py",
            "targetElementIds":[format!("component-{:03}",count-1),format!("flow-{:03}",count-1),"tail-boundary"]
        }]}
    })
}

#[test]
fn every_component_and_flow_survives_parsing_beyond_the_old_sixty_four_limit() {
    let doc = document(1_024);
    let nodes = parse_nodes(&doc);
    let flows = parse_flows(&doc, &nodes);

    assert_eq!(nodes.len(), 1_024);
    assert_eq!(flows.len(), 1_023);
    assert_eq!(nodes.last().unwrap().id, "component-1023");
    let last = flows.last().unwrap();
    assert_eq!(last.id, "flow-1023");
    assert_eq!(last.source, "Component 1022");
    assert_eq!(last.target, "Component 1023");
    assert!(last.crosses);
    assert_eq!(zones_in_order(&nodes), ["zone-0", "zone-1", "zone-2"]);
}

#[test]
fn tail_node_flow_and_boundary_retain_selection_and_linked_source() {
    let doc = document(96);
    let model = crate::ui_view_models::study_context::context_diagram_model(&doc, None);

    assert_eq!(model.nodes.len(), 96);
    assert_eq!(model.flows.len(), 95);
    assert_eq!(dfd_selectable_count(&model), 192);
    assert_eq!(model.link_state, DfdLinkState::Complete);
    for key in ["component-095", "flow-095", "tail-boundary"] {
        let selected =
            dfd_selection_for_key(&model, key).expect("Every recorded element must be reachable");
        assert_eq!(
            model.file_paths_for_selection(selected, None),
            ["modules/tail.py"]
        );
        assert_eq!(dfd_security_items_for_selection(&model, selected).len(), 1);
        match dfd_selected_item(&model, selected).unwrap() {
            DfdSelected::Node(node) => assert_eq!(node.key, key),
            DfdSelected::Flow(flow) => assert_eq!(flow.key, key),
            DfdSelected::Boundary(boundary) => assert_eq!(boundary.key, key),
        }
    }
}

#[test]
fn indexed_flow_names_keep_the_first_duplicate_id_in_legacy_documents() {
    let doc = json!({"dfd":{
        "nodes":[
            {"id":"source","name":"Original source","trustZone":"outside"},
            {"id":"source","name":"Later duplicate","trustZone":"inside"},
            {"id":"target","name":"Target","trustZone":"inside"}
        ],
        "flows":[{"sourceId":"source","targetId":"target"},{"sourceId":"unknown","targetId":"target"}]
    }});
    let nodes = parse_nodes(&doc);
    let flows = parse_flows(&doc, &nodes);

    assert_eq!(flows[0].source, "Original source");
    assert!(flows[0].crosses);
    assert_eq!(flows[1].source, "unknown");
    assert_eq!(zones_in_order(&nodes), ["outside", "inside"]);
}
