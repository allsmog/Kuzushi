mod document;
use crate::app::{AgentChatView, AnswerFocus, ShellApp, ShellView};
use document::build_document;
use ratatui::layout::Rect;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerLineKind {
    Context,
    Question,
    Answer,
    Error,
}

#[derive(Debug, Clone)]
pub(crate) struct AnswerLine {
    pub(crate) content: ratatui::text::Line<'static>,
    pub(crate) kind: AnswerLineKind,
}

#[derive(Debug, Default)]
pub(crate) struct AnswerDocument {
    pub(crate) lines: Vec<AnswerLine>,
    pub(crate) current_start: usize,
    pub(crate) context_label: String,
    pub(crate) scope_label: String,
}

pub(crate) type AnswerDocumentCache = ((u64, usize, usize), Arc<AnswerDocument>);

pub(crate) fn answers_host_view(view: ShellView) -> bool {
    matches!(
        view,
        ShellView::Workbench
            | ShellView::Scene
            | ShellView::Home
            | ShellView::Activity
            | ShellView::Threat
            | ShellView::Campaign
            | ShellView::Logs
            | ShellView::Trace
            | ShellView::Replay
    )
}

pub(crate) fn answers_available(app: &ShellApp) -> bool {
    answers_host_view(app.shell_view()) && !answers_suspended(app)
}

fn answers_suspended(app: &ShellApp) -> bool {
    let question = app.shell_view() == ShellView::Activity
        && app
            .activity()
            .is_some_and(|session| session.operator_question.is_some());
    question || app.guided_scan_question_model().is_some() || app.batch_config_open()
}

pub(crate) fn answers_visible(app: &ShellApp) -> bool {
    answers_available(app) && app.router.answers().visible
}

pub(crate) fn answers_own_input(app: &ShellApp) -> bool {
    answers_available(app)
        && answers_visible(app)
        && app.router.answers().focus != AnswerFocus::Workspace
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AnswersLayout {
    pub(crate) workspace: Rect,
    pub(crate) answers: Option<Rect>,
    pub(crate) compact: bool,
}

pub(crate) fn answers_layout(app: &ShellApp, area: Rect) -> AnswersLayout {
    if !answers_visible(app) {
        return AnswersLayout {
            workspace: area,
            answers: None,
            compact: false,
        };
    }
    if area.width >= 120 {
        let width = (area.width.saturating_mul(2) / 5).min(64);
        return split_answers(area, width, false);
    }
    if area.height >= 32 {
        return split_answers(area, area.height / 2, true);
    }
    compact_answers_layout(app, area)
}

fn compact_answers_layout(app: &ShellApp, area: Rect) -> AnswersLayout {
    if app.router.answers().focus != AnswerFocus::Workspace {
        return AnswersLayout {
            workspace: Rect::default(),
            answers: Some(area),
            compact: false,
        };
    }
    let mut layout = split_answers(area, 2.min(area.height), true);
    layout.compact = true;
    layout
}

fn split_answers(area: Rect, size: u16, vertical: bool) -> AnswersLayout {
    let (workspace, answers) = if vertical {
        let height = area.height.saturating_sub(size);
        (
            Rect { height, ..area },
            Rect::new(area.x, area.y + height, area.width, size),
        )
    } else {
        let width = area.width.saturating_sub(size);
        (
            Rect { width, ..area },
            Rect::new(area.x + width, area.y, size, area.height),
        )
    };
    AnswersLayout {
        workspace,
        answers: Some(answers),
        compact: false,
    }
}

pub(crate) fn answer_document(app: &ShellApp, width: usize) -> Arc<AnswerDocument> {
    let index = app.router.answers().history;
    let key = (app.agent_chat_generation(), width, index);
    if let Some((cached_key, document)) = &app.workbench_cache().borrow().answer_document {
        if *cached_key == key {
            return Arc::clone(document);
        }
    }
    let document = Arc::new(build_document(selected_thread(app, index), width, index));
    app.workbench_cache().borrow_mut().answer_document = Some((key, Arc::clone(&document)));
    document
}

fn selected_thread(app: &ShellApp, index: usize) -> Option<&AgentChatView> {
    if index == 0 {
        return app.agent_chat();
    }
    app.agent_chat_history().iter().rev().nth(index - 1)
}

pub(crate) fn answer_scroll_start(app: &ShellApp, doc: &AnswerDocument, height: usize) -> usize {
    let route = app.router.answers();
    let default_start = if route.follow_response && route.history == 0 {
        doc.lines.len().saturating_sub(height)
    } else {
        doc.current_start
    };
    route
        .scroll
        .unwrap_or(default_start)
        .min(doc.lines.len().saturating_sub(height))
}
