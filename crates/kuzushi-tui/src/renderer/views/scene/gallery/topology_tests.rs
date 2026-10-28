use super::*;

#[test]
fn plain_summary_retains_partial_connectivity_and_component_specific_notices() {
    let mut model = crate::renderer::tests::component_map::component_model();
    let original = model.nodes[0].clone();
    for key in ["caller", "receiver"] {
        let mut node = original.clone();
        node.key = key.into();
        node.name = format!("Owned {key}");
        model.nodes.push(node);
    }
    model.flows.push(crate::ui_view_models::DfdFlowModel {
        key: "recorded-transfer".into(),
        from_id: "caller".into(),
        to_id: "receiver".into(),
        from: "Owned caller".into(),
        to: "Owned receiver".into(),
        crosses: false,
        label: "Recorded fixture transfer".into(),
        boundary_ids: Vec::new(),
    });
    for width in [40, 60, 80, 96, 120, 160] {
        let text = summary_plain_lines(width, &model)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            text.contains("1 component has no recorded flows"),
            "{width}: {text}"
        );
        assert!(
            text.contains("No incoming or outgoing flows recorded"),
            "{width}: {text}"
        );
        assert!(
            text.contains("Owned caller")
                && text.contains("Owned receiver")
                && text.contains("Declared lockfile")
        );
        assert_eq!(
            text.matches("No incoming or outgoing flows recorded")
                .count(),
            1
        );
    }
    assert_eq!(model.flows.len(), 1);
}
