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
