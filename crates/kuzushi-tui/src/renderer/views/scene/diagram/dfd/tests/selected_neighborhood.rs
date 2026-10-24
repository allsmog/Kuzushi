use super::*;

fn large_neighborhood() -> DfdModel {
    let mut nodes = (1..=94)
        .map(|i| node(&format!("worker-{i:03}"), "application"))
        .collect::<Vec<_>>();
    nodes.push(node("tail-worker", "isolated"));
    DfdModel {
        zones: vec!["application".into(), "isolated".into()],
        nodes,
        flows: vec![flow("worker-094", "tail-worker", "tail transfer")],
        boundaries: vec![DfdBoundaryModel {
            key: "tb-1".into(),
            name: "Tail boundary".into(),
            inner_zone: "isolated".into(),
            outer_zone: "application".into(),
            crossing_flow_ids: Vec::new(),
        }],
        ..Default::default()
    }
}

#[test]
fn selected_tail_node_pages_its_immediate_source_into_wide_and_stacked_graphs() {
    let model = large_neighborhood();
    for (width, height) in [(120, 36), (160, 48), (96, 89), (80, 24)] {
        let rendered = render_selection(&model, 94, 0, width, height);
        assert!(rendered.contains("◇ worker-094"), "{width}: {rendered}");
        assert!(rendered.contains("◇ tail-worker"), "{width}: {rendered}");
        assert!(!rendered.contains("◇ worker-001"), "{width}: {rendered}");
        assert!(rendered.contains(['▼', '▲', '▶']), "{width}: {rendered}");
    }
}

#[test]
fn selected_tail_boundary_pages_its_recorded_crossing_endpoints_into_view() {
    let model = large_neighborhood();
    let selected = model.nodes.len() + model.flows.len();
    let rendered = render_selection(&model, selected, 0, 120, 36);
    assert!(rendered.contains("◇ worker-094"), "{rendered}");
    assert!(rendered.contains("◇ tail-worker"), "{rendered}");
    assert!(rendered.contains("Tail boundary"), "{rendered}");
}

#[test]
fn stacked_flow_direction_follows_the_recorded_source_when_selection_reorders_zones() {
    let model = DfdModel {
        zones: vec!["outside".into(), "inside".into()],
        nodes: vec![node("source", "outside"), node("target", "inside")],
        flows: vec![flow("source", "target", "recorded transfer")],
        ..Default::default()
    };
    for (selected, arrow) in [(0, "▼"), (1, "▲")] {
        let rendered = render_selection(&model, selected, 0, 96, 36);
        assert!(
            rendered.contains(&format!("{arrow} recorded transfer")),
            "{rendered}"
        );
    }
}
