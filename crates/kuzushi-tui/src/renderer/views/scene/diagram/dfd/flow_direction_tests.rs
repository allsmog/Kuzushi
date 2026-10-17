use super::*;

fn anchor(col: usize, left: u16, top: u16) -> Anchor {
    Anchor {
        col,
        cx: left + 5,
        top,
        bottom: top + 2,
        left,
        right: left + 10,
    }
}

#[test]
fn one_row_gap_preserves_both_vertical_flow_directions() {
    let area = Rect::new(0, 0, 40, 20);
    let upper = anchor(0, 2, 2);
    let lower = anchor(0, 2, 6);
    let mut down = Buffer::empty(area);
    draw_flow(&mut down, area, &upper, &lower, Color::White);
    assert_eq!(down[(7, 5)].symbol(), "▼");
    let mut up = Buffer::empty(area);
    draw_flow(&mut up, area, &lower, &upper, Color::White);
    assert_eq!(up[(7, 5)].symbol(), "▲");
}

#[test]
fn reverse_cross_zone_flows_point_to_the_actual_left_destination() {
    let area = Rect::new(0, 0, 50, 30);
    for target_row in [2, 6, 10] {
        let source = anchor(1, 30, 6);
        let target = anchor(0, 2, target_row);
        let mut buffer = Buffer::empty(area);
        draw_flow(&mut buffer, area, &source, &target, Color::White);
        assert_eq!(buffer[(target.right + 1, target.mid())].symbol(), "◀");
        assert!(!buffer.content().iter().any(|cell| cell.symbol() == "▶"));
    }
}

fn internal_nodes() -> Vec<DfdNodeModel> {
    ["first", "second"]
        .into_iter()
        .map(|name| DfdNodeModel {
            key: name.into(),
            name: name.into(),
            zone: "application".into(),
            kind: DfdKind::Process,
            description: None,
            purpose: None,
        })
        .collect()
}

#[test]
fn shared_widget_keeps_an_internal_flow_visible_after_node_boxes_are_painted() {
    for (from, to, arrow) in [("first", "second", "▼"), ("second", "first", "▲")] {
        let model = DfdModel {
            zones: vec!["application".into()],
            nodes: internal_nodes(),
            flows: vec![DfdFlowModel {
                key: "flow".into(),
                from_id: from.into(),
                to_id: to.into(),
                from: from.into(),
                to: to.into(),
                crosses: false,
                label: "recorded data".into(),
                boundary_ids: vec![],
            }],
            ..Default::default()
        };
        let area = Rect::new(0, 0, 120, 30);
        let mut buffer = Buffer::empty(area);
        DfdDiagram {
            model,
            selection: Some(0),
            detail_scroll: 0,
            focused: false,
            context_selection: 0,
        }
        .render(area, &mut buffer);
        assert!(
            buffer.content().iter().any(|cell| cell.symbol() == arrow),
            "missing {arrow}"
        );
    }
}

#[test]
fn boundary_context_counts_include_evidence_on_its_recorded_crossing_flows() {
    use crate::ui_view_models::DfdSecurityItem;
    let model = DfdModel {
        boundaries: vec![DfdBoundaryModel {
            key: "edge".into(),
            name: "Request boundary".into(),
            inner_zone: "application".into(),
            outer_zone: "public".into(),
            crossing_flow_ids: vec!["request".into()],
        }],
        security_context: vec![DfdSecurityItem {
            key: "AS-input".into(),
            kind: DfdSecurityKind::EntryPoint,
            label: "Recorded input".into(),
            detail: String::new(),
            evidence: "reader.py:1".into(),
            evidence_paths: vec![],
            file_paths: vec![],
            target_element_ids: vec!["request".into()],
        }],
        link_state: DfdLinkState::Complete,
        ..Default::default()
    };
    assert_eq!(
        linked_context_summary(&model, "edge"),
        "linked · 1 · 1 entry"
    );
}
