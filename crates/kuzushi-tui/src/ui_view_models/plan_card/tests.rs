use super::*;
use crate::{PlanChange, ShellApp};
use kuzushi_core::V2Config;

#[test]
fn plan_card_model_marks_cursor_skips_and_counts_active_changes() {
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_pending_plan(PlanProposal {
        goal: "reduce risk".to_string(),
        summary: "two proposed edits".to_string(),
        changes: vec![
            PlanChange::Note {
                text: "keep this".to_string(),
            },
            PlanChange::Ask {
                question: "should we continue?".to_string(),
            },
        ],
        unsupported: vec!["manual follow-up".to_string()],
    });
    app.toggle_plan_change_skip();
    app.move_plan_cursor(1);

    let model = plan_card_model(&app).expect("pending plan model");

    assert_eq!(model.goal, "reduce risk");
    assert_eq!(model.summary, "two proposed edits");
    assert_eq!(model.active_count, 1);
    assert_eq!(model.total_count, 2);
    assert_eq!(model.changes[0].label, "note keep this");
    assert!(model.changes[0].skipped);
    assert!(!model.changes[0].selected);
    assert_eq!(model.changes[1].label, "ask should we continue?");
    assert!(!model.changes[1].skipped);
    assert!(model.changes[1].selected);
    assert_eq!(model.unsupported, vec!["manual follow-up"]);
}
