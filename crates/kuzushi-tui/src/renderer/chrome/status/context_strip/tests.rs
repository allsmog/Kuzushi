use super::*;
use kuzushi_core::V2Config;

fn full_header(model: &ContextStripModel) -> String {
    context_strip_spans(model)
        .into_iter()
        .map(|span| span.content.to_string())
        .collect()
}

#[test]
fn full_header_keeps_the_recorded_index_freshness() {
    let app = ShellApp::new(V2Config::default(), None);
    let mut model = context_strip_model(&app);
    model.context_present = true;
    for (state, label) in [
        ("current", "repo index ready"),
        ("stale", "repo index stale"),
        ("unverified", "repo index unverified"),
        ("malformed", "repo index malformed"),
    ] {
        model.context_state = state;
        let header = full_header(&model);
        assert!(header.contains(label), "{state}: {header}");
        assert!(!header.contains("not built"), "{state}: {header}");
    }
}

#[test]
fn full_header_shows_the_first_index_build_in_progress() {
    let app = ShellApp::new(V2Config::default(), None);
    let mut model = context_strip_model(&app);
    model.context_building = true;
    let header = full_header(&model);
    assert!(header.contains("repo index building"), "{header}");
    assert!(!header.contains("not built"), "{header}");
}

fn indexed_model() -> ContextStripModel {
    let app = ShellApp::new(V2Config::default(), None);
    let mut model = context_strip_model(&app);
    model.view = "logs".into();
    model.target = "./fixture-target".into();
    model.phase = Some("Map 1/3".into());
    model.context_present = true;
    model.context_state = "current";
    model
}

fn row_text(lines: &[Line<'_>]) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect()
        })
        .collect()
}

#[test]
fn compact_header_keeps_index_cost_and_model_visible_when_height_permits() {
    let model = indexed_model();
    for width in [80, 96] {
        let rows = row_text(&compact_context_strip_lines(
            &model,
            Rect::new(0, 0, width, 20),
        ));
        assert_eq!(rows.len(), 2, "{width}: {rows:?}");
        assert!(rows[0].contains("target:./fixture-target"), "{rows:?}");
        assert!(rows[1].contains("repo index ready"), "{rows:?}");
        assert!(rows[1].contains("session:$0.00"), "{rows:?}");
        assert!(rows[1].contains("model:unconfigured"), "{rows:?}");
    }
}

#[test]
fn compact_header_keeps_unknown_cost_whole_before_a_long_model() {
    let mut model = indexed_model();
    model.cost = Some("unknown (metering incomplete)".into());
    model.model = format!("openai:{} [auth missing]", "a".repeat(100));
    for width in [40, 80] {
        let rows = row_text(&compact_context_strip_lines(
            &model,
            Rect::new(0, 0, width, 20),
        ));
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(
            rows[1].contains("session:unknown (metering incomplete)"),
            "{width}: {rows:?}"
        );
        assert!(!rows[1].contains("model:"), "Partial model field: {rows:?}");
        assert!(!rows[1].contains("$0.00"), "{rows:?}");
    }
}

#[test]
fn compact_header_keeps_the_short_reading_area() {
    let model = indexed_model();
    for height in [0, 8, 12, 16] {
        let rows = compact_context_strip_lines(&model, Rect::new(0, 0, 80, height));
        assert_eq!(rows.len(), 1, "height {height}: {rows:?}");
    }
}
