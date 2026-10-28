use super::*;
use crate::ui_view_models::PhaseSurfaceId;

#[test]
fn scan_page_up_moves_from_the_visible_tail_instead_of_a_hidden_overscroll() {
    for (columns, rows) in [(160, 48), (120, 36), (96, 89), (80, 24), (60, 20), (40, 12)] {
        let mut fixture = ResultCardFixture::open(WorkflowPhase::Scan, "sast:scan");
        let app = &mut fixture.app;
        app.set_viewport(crate::TerminalViewport::new(columns, rows));
        app.router
            .workbench_mut()
            .set_focus(PhaseSurfaceId::ScanEngines);
        app.editor_mut().set_input("keep this draft");
        app.scroll_to_bottom();
        // Recover an offset left by an older view or a taller wrapped document.
        app.router
            .workbench_mut()
            .scroll_mut()
            .set(PhaseSurfaceId::ScanEngines, u16::MAX);
        assert!(
            app.reduce_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE))
                .handled
        );
        let offset = app
            .router
            .workbench()
            .scroll()
            .get(PhaseSurfaceId::ScanEngines);
        assert!(
            offset < 24,
            "{columns}x{rows}: stored offset {offset} still hides the visible tail"
        );
        assert_eq!(app.input(), "keep this draft");
        assert_eq!(app.input_mode(), InputMode::Navigate);
        assert!(fixture.attempt_is_unresolved(WorkflowPhase::Scan));
    }
}

pub(super) fn scan_result_data(target: &std::path::Path) -> Value {
    let engines = (0..24)
        .map(|index| {
            serde_json::json!({
                "engine": format!("Fixture engine {index:02}"), "outcome": "complete"
            })
        })
        .collect::<Vec<_>>();
    let receipt = serde_json::json!({
        "phase": "scan", "outcome": "completed", "runRefs": ["run-result-card"],
        "scan": {
            "scope": {"target": target.display().to_string()},
            "plan": {"selection": "manual", "engines": []},
            "engines": engines, "findingDelta": {"added": 0, "updated": 0},
            "durationMs": 1,
            "targetSnapshot": kuzushi_core::workflow_attempts::PhaseTargetSnapshot::capture(target)
        }
    });
    serde_json::json!({"snapshot": {"filesIndexed": 1}, "phaseStages": [receipt]})
}
