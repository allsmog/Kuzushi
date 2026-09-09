use super::*;

pub(super) fn build_document(
    chat: Option<&AgentChatView>,
    width: usize,
    index: usize,
) -> AnswerDocument {
    let mut doc = AnswerDocument::default();
    let Some(chat) = chat.filter(|chat| !chat.question.is_empty() || !chat.history.is_empty())
    else {
        return empty_document(chat.and_then(|chat| chat.recovery_note.as_deref()), width);
    };
    doc.context_label = context_label(chat);
    doc.scope_label = chat
        .screen_context_scope
        .clone()
        .unwrap_or_else(|| "Context receipt: Home".to_string());
    if let Some(note) = &chat.recovery_note {
        append(&mut doc, note, width, AnswerLineKind::Context);
    }
    append_context(&mut doc, chat, width, index);
    for turn in &chat.history {
        append_turn(
            &mut doc,
            &turn.question,
            turn.answer.as_deref(),
            turn.error.as_deref(),
            &turn.partial_answer,
            width,
        );
    }
    append_current_turn(&mut doc, chat, width);
    doc
}

fn empty_document(note: Option<&str>, width: usize) -> AnswerDocument {
    let mut doc = AnswerDocument {
        context_label: "Current workspace".into(),
        ..Default::default()
    };
    if let Some(note) = note {
        append(&mut doc, note, width, AnswerLineKind::Context);
    }
    append(
        &mut doc,
        "Ask about the current workspace. Enter starts a question.",
        width,
        AnswerLineKind::Context,
    );
    doc
}

fn append_current_turn(doc: &mut AnswerDocument, chat: &AgentChatView, width: usize) {
    doc.current_start = doc.lines.len();
    append_turn(
        doc,
        &chat.question,
        chat.answer.as_deref(),
        chat.error.as_deref(),
        "",
        width,
    );
    append_partial_answer(doc, &chat.partial_answer, chat.running, width);
    append_waiting_state(doc, chat, width);
}

fn append_waiting_state(doc: &mut AnswerDocument, chat: &AgentChatView, width: usize) {
    if chat.running {
        let state = if chat.abort_requested {
            "Canceling Ask…"
        } else if !chat.partial_answer.is_empty() {
            "Receiving response… · Ctrl+C cancels Ask"
        } else {
            "Waiting for the model… · Ctrl+C cancels Ask"
        };
        append(doc, state, width, AnswerLineKind::Context);
    }
}

fn context_label(chat: &AgentChatView) -> String {
    let Some(key) = &chat.thread_context_key else {
        return "Context not yet bound".to_string();
    };
    let revision = key.target_revision.chars().take(12).collect::<String>();
    let model = key
        .threat_model_ref
        .as_ref()
        .map(|model| {
            let suffix = model
                .revision_id
                .as_str()
                .chars()
                .rev()
                .take(8)
                .collect::<String>();
            format!(" · Map {}", suffix.chars().rev().collect::<String>())
        })
        .unwrap_or_default();
    let target = key
        .canonical_target
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let restored = if chat.recovery_note.is_some() {
        "Restored · "
    } else {
        ""
    };
    format!("{restored}Captured {revision}{model} · {target}")
}

fn append_context(doc: &mut AnswerDocument, chat: &AgentChatView, width: usize, index: usize) {
    let label = if index == 0 {
        "Captured context"
    } else {
        "Earlier conversation · read-only context"
    };
    append(doc, label, width, AnswerLineKind::Context);
    if let Some(key) = &chat.thread_context_key {
        append(
            doc,
            &format!(
                "{} · revision {}",
                key.canonical_target.display(),
                key.target_revision
            ),
            width,
            AnswerLineKind::Context,
        );
        if let Some(model) = &key.threat_model_ref {
            append(
                doc,
                &format!(
                    "Map {} @ {}",
                    model.model_id.as_str(),
                    model.revision_id.as_str()
                ),
                width,
                AnswerLineKind::Context,
            );
        }
    }
    if let Some(scope) = &chat.screen_context_scope {
        append(doc, scope, width, AnswerLineKind::Context);
    }
}

fn append_turn(
    doc: &mut AnswerDocument,
    question: &str,
    answer: Option<&str>,
    error: Option<&str>,
    partial: &str,
    width: usize,
) {
    append(doc, "YOU", width, AnswerLineKind::Context);
    append(doc, question, width, AnswerLineKind::Question);
    if let Some(answer) = answer {
        append(doc, "ANSWER", width, AnswerLineKind::Context);
        append_answer(doc, answer, width);
    }
    append_partial_answer(doc, partial, false, width);
    if let Some(error) = error {
        append(doc, error, width, AnswerLineKind::Error);
    }
    append(doc, "", width, AnswerLineKind::Context);
}

fn append_partial_answer(doc: &mut AnswerDocument, text: &str, running: bool, width: usize) {
    if text.is_empty() {
        return;
    }
    let label = if running {
        "RESPONSE IN PROGRESS"
    } else {
        "INCOMPLETE RESPONSE"
    };
    append(doc, label, width, AnswerLineKind::Context);
    append_answer(doc, text, width);
}

fn append_answer(doc: &mut AnswerDocument, answer: &str, width: usize) {
    doc.lines.extend(
        crate::renderer::shared::markdown::answer_markdown(answer, width)
            .into_iter()
            .map(|content| AnswerLine {
                content,
                kind: AnswerLineKind::Answer,
            }),
    );
}

fn append(doc: &mut AnswerDocument, text: &str, width: usize, kind: AnswerLineKind) {
    doc.lines.extend(
        crate::renderer::shared::text::wrap_text(text, width.max(1))
            .into_iter()
            .map(|text| AnswerLine {
                content: text.into(),
                kind,
            }),
    );
}
