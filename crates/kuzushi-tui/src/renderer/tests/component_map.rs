use super::*;

const SIZES: [(u16, u16); 6] = [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)];

pub(in crate::renderer) fn component_model() -> crate::ui_view_models::DfdModel {
    let (_root, app) = component_app();
    crate::ui_view_models::dfd_model(&app)
}

fn component_app() -> (tempfile::TempDir, ShellApp) {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join(".kuzushi")).unwrap();
    std::fs::write(root.path().join(crate::ui_view_models::threat_model_relative_path()),serde_json::to_vec(&serde_json::json!({
        "systemContext":"Owned dependency metadata; no runtime claim.",
        "dfd":{"nodes":[{"id":"lock","name":"Declared lockfile","type":"data-store","trustZone":"repository","description":"Cargo.lock metadata","purpose":"Owner review"}],"flows":[],"trustBoundaries":[]},"threats":[]
    })).unwrap()).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(root.path().to_path_buf()));
    app.set_shell_view(ShellView::Scene);
    app.router
        .scene_mut()
        .set_page(crate::scene3d::VizPage::Summary);
    app.hydrate_all_view_data_for_test();
    (root, app)
}

#[test]
fn component_plain_summary_preserves_all_details_without_claiming_missing_artifacts() {
    let (_root, app) = component_app();
    for (width, _) in SIZES {
        let text = crate::renderer::render_plain_app(&app, width as usize);
        assert!(text.contains("Declared lockfile"), "{text}");
        assert!(text.contains("Component map only."), "{text}");
        assert!(
            text.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("no runtime claim"),
            "{text}"
        );
    }
}
