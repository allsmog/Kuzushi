use super::document::{
    regeneration_title, render_diagnostic_controls, render_generation_controls,
    render_regeneration_controls,
};
use super::*;

pub(super) fn generation_controls_area(
    area: Rect,
    body: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> Rect {
    let height = if generation.has_text_editor() || generation.supports_brief_guidance() {
        3
    } else {
        2
    };
    Rect::new(
        body.x,
        area.bottom().saturating_sub(height + 1),
        body.width,
        height,
    )
}

pub(super) fn render_generation_state_controls(
    frame: &mut Frame<'_>,
    controls: Rect,
    generation: &crate::app::StudyContextGeneration,
    position: (usize, usize),
) {
    if render_generation_reader_controls(frame, controls, generation) {
        return;
    }
    if generation.supports_result_overview() {
        render_context_result_controls(frame, controls, generation, position);
        return;
    }
    if render_generation_editor_controls(frame, controls, generation) {
        return;
    }
    render_generation_controls(
        frame,
        controls,
        position.0,
        position.1,
        has_inspection_action(generation),
        generation.is_scope_proposal(),
        generation.rejected_available,
        generation.receipt.is_none(),
    );
}

fn has_inspection_action(generation: &crate::app::StudyContextGeneration) -> bool {
    generation.has_result() || (generation.is_scope_proposal() && generation.result_error.is_some())
}

fn render_context_result_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
    position: (usize, usize),
) {
    let navigation = context_result_navigation(generation);
    let action = if generation.generated.is_some() {
        "Enter inspect · n new · Esc back"
    } else {
        "Enter outcome · n new · Esc back"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(navigation, theme::muted()),
            Line::styled(
                format!("b goal · PgUp/Dn {}/{}", position.0 + 1, position.1 + 1),
                theme::muted(),
            ),
            Line::styled(action, theme::accent()),
        ]),
        area,
    );
}

fn context_result_navigation(generation: &crate::app::StudyContextGeneration) -> String {
    let panel = if generation.shows_result_plan() {
        "p result"
    } else {
        "p plan"
    };
    if generation.generated.is_some() {
        return format!("m Map · {panel} · Tab options");
    }
    if generation.rejected_available {
        return format!("{panel} · Tab options · d output");
    }
    format!("{panel} · Tab options")
}

fn render_generation_reader_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> bool {
    if generation.show_brief_guidance {
        frame.render_widget(Paragraph::new("PgUp/Dn read\nEsc back · frozen goal"), area);
        return true;
    }
    if generation.show_rejected {
        render_diagnostic_controls(
            frame,
            area,
            generation.is_scope_proposal(),
            generation.has_corrected_scopes(),
        );
        return true;
    }
    false
}

fn render_generation_editor_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> bool {
    if generation.is_question() {
        render_question_controls(frame, area, generation);
        return true;
    }
    render_other_generation_editor_controls(frame, area, generation)
}

fn render_other_generation_editor_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> bool {
    if generation.is_workflow_proposal() {
        frame.render_widget(Paragraph::new("Enter next · G goal · M model\nt calls · r review · n new draft\nTab options · Esc back · PgUp/PgDn read"), area);
        return true;
    }
    render_remaining_generation_editor_controls(frame, area, generation)
}

fn render_remaining_generation_editor_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) -> bool {
    if generation.supports_brief_guidance() {
        render_goal_generation_controls(frame, area, generation);
        return true;
    }
    if generation.is_regeneration() {
        render_regeneration_controls(frame, area, generation.has_result());
        return true;
    }
    if generation.is_lesson() {
        render_lesson_controls(frame, area, generation.has_result());
        return true;
    }
    false
}

fn render_question_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) {
    if generation.show_answer {
        frame.render_widget(
            Paragraph::new("Esc plan · PgUp/PgDn read\nn new question"),
            area,
        );
        return;
    }
    let primary = if generation.receipt.is_some() {
        "Enter continue · Tab options"
    } else {
        "Enter continue · G edit question · M model"
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(primary),
            Line::from("t total calls · r protected Review"),
            Line::from("n new question · Tab options · Esc back"),
        ]),
        area,
    );
}

fn render_goal_generation_controls(
    frame: &mut Frame<'_>,
    area: Rect,
    generation: &crate::app::StudyContextGeneration,
) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled(goal_generation_primary(generation), theme::muted()),
            Line::styled(goal_generation_navigation(generation), theme::muted()),
            Line::styled(
                if generation.has_result() {
                    "Enter inspect · n new · Esc back"
                } else {
                    "Enter next · n new · Esc back"
                },
                theme::accent(),
            ),
        ]),
        area,
    );
}

fn goal_generation_primary(generation: &crate::app::StudyContextGeneration) -> &'static str {
    if generation.rejected_available {
        return "d output · b goal · Tab · PgUp/Dn";
    }
    if generation.has_result() && !generation.is_scope_context() {
        return "m Map · b goal · Tab · PgUp/Dn";
    }
    if generation.context_input.get("sourcePaths").is_some() {
        return "t calls · r review · M model";
    }
    "t calls · r review · s retention"
}

fn goal_generation_navigation(generation: &crate::app::StudyContextGeneration) -> &'static str {
    match (
        generation.context_input.get("sourcePaths").is_some(),
        generation.receipt.is_none(),
    ) {
        (true, true) => "g guide · b goal · s retention · Tab",
        (true, false) => "s retention · b goal · Tab · PgUp/Dn",
        (false, true) => "g guide · b goal · Tab · PgUp/Dn",
        (false, false) => "b goal · Tab options · PgUp/Dn",
    }
}

pub(super) fn generation_title_override(
    generation: &crate::app::StudyContextGeneration,
) -> Option<&'static str> {
    if generation.show_rejected || generation.result_error.is_some() {
        return None;
    }
    if generation.context_input.get("sourcePaths").is_some() {
        return Some(if generation.has_result() {
            " EVIDENCE CONTEXT DRAFT "
        } else {
            " PLAN EVIDENCE CONTEXT "
        });
    }
    if generation.is_workflow_proposal() {
        return Some(" WORKFLOW PROPOSAL PLAN ");
    }
    remaining_generation_title_override(generation)
}

fn remaining_generation_title_override(
    generation: &crate::app::StudyContextGeneration,
) -> Option<&'static str> {
    if generation.is_question() {
        return Some(if generation.show_answer {
            " CONTEXT ANSWER "
        } else {
            " ASK ABOUT CONTEXT "
        });
    }
    if generation.is_scope_context() {
        return Some(if generation.has_result() {
            " FILE-GROUP CONTEXT DRAFT "
        } else {
            " GENERATE FILE-GROUP CONTEXT "
        });
    }
    if generation.is_lesson() {
        return Some(if generation.has_result() {
            " GENERATED LESSON DRAFT "
        } else {
            " GENERATE LESSON DRAFT "
        });
    }
    generation
        .is_regeneration()
        .then(|| regeneration_title(generation.has_result()))
}

fn render_lesson_controls(frame: &mut Frame<'_>, area: Rect, has_result: bool) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("t calls · r review · M model", theme::muted()),
            Line::styled("G guidance · Tab options · PgUp/Dn", theme::muted()),
            Line::styled(
                if has_result {
                    "Enter inspect lesson · n new · Esc back"
                } else {
                    "Enter next · n new · Esc back"
                },
                theme::accent(),
            ),
        ]),
        area,
    );
}
