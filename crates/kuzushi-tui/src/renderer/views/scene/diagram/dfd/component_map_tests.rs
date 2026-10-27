use super::*;
use crate::renderer::tests::component_map::component_model;
const SIZES: [(u16, u16); 6] = [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)];

#[test]
fn component_summary_renders_known_context_and_unknown_relationships_at_every_size() {
    for (width, height) in SIZES {
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
        DfdSummary {
            model: component_model(),
            component_selection: 0,
            scroll: 0,
        }
        .render(buffer.area, &mut buffer);
        let text = crate::renderer::tests::rendered_buffer_rows(&buffer).join("\n");
        assert!(
            text.contains("Owned dependency metadata"),
            "{width}x{height}: {text}"
        );
        let mut full = Buffer::empty(Rect::new(0, 0, width, height));
        DfdSummary {
            model: component_model(),
            component_selection: 0,
            scroll: 4,
        }
        .render(full.area, &mut full);
        let paged = crate::renderer::tests::rendered_buffer_rows(&full).join("\n");
        assert!(
            text.contains("Component map only.") || paged.contains("Component map only."),
            "{width}x{height}: {text}\n{paged}"
        );
        assert!(!text.contains("no system summary"), "{text}");
    }
}

#[test]
fn single_node_diagram_has_reachable_details_and_no_invented_connectors() {
    for (width, height) in SIZES {
        let mut buffer = Buffer::empty(Rect::new(0, 0, width, height));
        DfdDiagram {
            model: component_model(),
            selection: Some(0),
            detail_scroll: 0,
            focused: false,
            context_selection: 0,
        }
        .render(buffer.area, &mut buffer);
        let text = crate::renderer::tests::rendered_buffer_rows(&buffer).join("\n");
        assert!(
            text.contains("Declared lockfile"),
            "{width}x{height}: {text}"
        );
        assert!(!text.contains("no data-flow diagram"), "{text}");
        assert!(
            !text.contains('▶') && !text.contains('▼'),
            "invented flow: {text}"
        );
    }
}

fn mixed_topology() -> DfdModel {
    let mut model = component_model();
    let original = model.nodes[0].clone();
    for key in ["receiver", "records"] {
        let mut connected = original.clone();
        connected.key = key.into();
        connected.name = key.into();
        model.nodes.push(connected);
    }
    model.flows.push(DfdFlowModel {
        key: "recorded-link".into(),
        from_id: "receiver".into(),
        to_id: "records".into(),
        from: "receiver".into(),
        to: "records".into(),
        crosses: false,
        label: "Owned recorded flow".into(),
        boundary_ids: Vec::new(),
    });
    model
}

#[test]
fn mixed_topology_discloses_the_component_without_recorded_flows() {
    let model = mixed_topology();
    assert!(model
        .topology_notice()
        .unwrap_or_default()
        .contains("1 component has no recorded flows"));
    assert_eq!(model.flows.len(), 1);
    let detail = node_detail_content(&model, &model.nodes[0], 80);
    let text = detail
        .lines
        .iter()
        .map(Line::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("No incoming or outgoing flows recorded"),
        "{text}"
    );
    let connected = node_detail_content(&model, &model.nodes[1], 80);
    let text = connected
        .lines
        .iter()
        .map(Line::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !text.contains("No incoming or outgoing flows recorded"),
        "{text}"
    );
}

#[test]
fn mixed_topology_summary_and_selected_detail_remain_reachable_at_every_size() {
    let model = mixed_topology();
    for (width, height) in SIZES {
        let mut summary = String::new();
        let mut detail = String::new();
        for scroll in 0usize..40 {
            let mut buf = Buffer::empty(Rect::new(0, 0, width, height));
            DfdSummary {
                model: model.clone(),
                component_selection: 0,
                scroll: scroll as i32,
            }
            .render(buf.area, &mut buf);
            summary.push_str(&crate::renderer::tests::rendered_buffer_rows(&buf).join(" "));
            let mut buf = Buffer::empty(Rect::new(0, 0, width, height));
            DfdDiagram {
                model: model.clone(),
                selection: Some(0),
                detail_scroll: scroll,
                focused: false,
                context_selection: 0,
            }
            .render(buf.area, &mut buf);
            detail.push_str(&crate::renderer::tests::rendered_buffer_rows(&buf).join(" "));
        }
        let summary = summary.split_whitespace().collect::<Vec<_>>().join(" ");
        let detail = detail.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            summary.contains("1 component has no recorded flows"),
            "{width}x{height}: {summary}"
        );
        assert!(
            (detail.contains("No incoming or outgoing") && detail.contains("recorded."))
                || detail.contains("no recorded flows"),
            "{width}x{height}: {detail:.1400}"
        );
    }
}

#[test]
fn detail_fields_preserve_paragraphs_and_blank_lines() {
    let mut lines = Vec::new();
    append_detail_lines(
        &mut lines,
        "does",
        "First paragraph.\n\nSecond paragraph.",
        80,
    );
    let values = lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .skip(1)
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    assert_eq!(values, vec!["First paragraph.", "", "Second paragraph."]);
}

#[test]
fn compact_reader_cue_replaces_the_entire_long_flow_caption() {
    let mut model = mixed_topology();
    model.flows[0].key = "long-recorded-flow-identifier-".repeat(8);
    let area = Rect::new(0, 0, 60, 11);
    let mut buffer = Buffer::empty(area);
    DfdDiagram {
        model,
        selection: Some(1),
        detail_scroll: 0,
        focused: false,
        context_selection: 0,
    }
    .render(area, &mut buffer);
    let rows = crate::renderer::tests::rendered_buffer_rows(&buffer);
    assert_eq!(rows[0].trim(), "Resize to read selected details");
}
