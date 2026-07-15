use super::*;
use crate::app::{
    OperatorQuestion, OperatorQuestionEnvelope, OperatorQuestionOption, OperatorQuestionRequest,
    PendingOperatorQuestion, WorkerGeneration,
};
use crate::ui_view_models::OperatorQuestionKeyHints;
use std::sync::mpsc::sync_channel;

fn card() -> PendingOperatorQuestion {
    let (control, _receiver) = sync_channel(8);
    PendingOperatorQuestion::new(OperatorQuestionEnvelope {
        request: OperatorQuestionRequest {
            request_id: "question-1".to_string(),
            run_id: "run-compact".to_string(),
            questions: vec![OperatorQuestion {
                id: "scope".to_string(),
                header: "Scope".to_string(),
                prompt: "What should Scan inspect?".to_string(),
                options: vec![
                    OperatorQuestionOption {
                        label: "Changed files".to_string(),
                        description: "Fast focused scan".to_string(),
                        recommended: true,
                    },
                    OperatorQuestionOption {
                        label: "Repository".to_string(),
                        description: "Broad scan".to_string(),
                        recommended: false,
                    },
                ],
            }],
            auto_resolution_ms: None,
        },
        generation: WorkerGeneration::new(1),
        control,
    })
}

fn hints() -> OperatorQuestionKeyHints {
    OperatorQuestionKeyHints {
        segments: vec!["Enter submit".to_string(), "Tab Other".to_string()],
        editor_segments: vec!["Enter submit".to_string(), "Esc return".to_string()],
        other_binding: Some("Tab".to_string()),
    }
}

fn text(lines: Vec<Line<'static>>) -> String {
    lines
        .into_iter()
        .flat_map(|line| line.spans.into_iter())
        .map(|span| span.content.into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn compact_question_keeps_prompt_selection_and_next_action_visible() {
    let rendered = text(operator_question_lines_for_height(&card(), &hints(), 40, 4));

    assert!(rendered.contains("What should Scan inspect?"), "{rendered}");
    assert!(rendered.contains("Changed files"), "{rendered}");
    assert!(rendered.contains("Enter submit"), "{rendered}");
}

#[test]
fn compact_other_editor_uses_editor_specific_hints() {
    let mut card = card();
    card.open_other();
    assert!(card.paste_other("first\nsecond"));

    let rendered = text(operator_question_lines_for_height(&card, &hints(), 40, 4));

    assert!(rendered.contains("Other"), "{rendered}");
    assert!(rendered.contains("paste #1"), "{rendered}");
    assert!(rendered.contains("Esc return"), "{rendered}");
    assert!(!rendered.contains("Tab Other"), "{rendered}");
}
