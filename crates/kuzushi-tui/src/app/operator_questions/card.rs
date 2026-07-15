use super::{
    OperatorQuestion, OperatorQuestionAnswer, OperatorQuestionRequest, OperatorQuestionResolution,
    OperatorQuestionResolutionKind,
};
use crate::app::{EditorState, WorkerGeneration};
use crossterm::event::KeyCode;
use std::sync::mpsc::SyncSender;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub(crate) enum OperatorQuestionControl {
    SnoozeAutoResolution {
        request_id: String,
        run_id: String,
        generation: WorkerGeneration,
    },
    Resolve {
        resolution: OperatorQuestionResolution,
        run_id: String,
        generation: WorkerGeneration,
    },
    Cancel {
        request_id: String,
        run_id: String,
        generation: WorkerGeneration,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct OperatorQuestionEnvelope {
    pub request: OperatorQuestionRequest,
    pub generation: WorkerGeneration,
    pub control: SyncSender<OperatorQuestionControl>,
}

#[derive(Debug, Clone)]
pub(crate) struct PendingOperatorQuestion {
    request: OperatorQuestionRequest,
    generation: WorkerGeneration,
    control: SyncSender<OperatorQuestionControl>,
    active_question: usize,
    option_cursors: Vec<usize>,
    answers: Vec<Option<OperatorQuestionAnswer>>,
    other_editor: Option<EditorState>,
    auto_resolution_snoozed: bool,
    submitting: bool,
    opened_at: Instant,
}

impl PendingOperatorQuestion {
    pub(crate) fn new(envelope: OperatorQuestionEnvelope) -> Self {
        let len = envelope.request.questions.len();
        let option_cursors = envelope
            .request
            .questions
            .iter()
            .map(recommended_option_index)
            .collect();
        Self {
            request: envelope.request,
            generation: envelope.generation,
            control: envelope.control,
            active_question: 0,
            option_cursors,
            answers: vec![None; len],
            other_editor: None,
            auto_resolution_snoozed: false,
            submitting: false,
            opened_at: Instant::now(),
        }
    }

    pub(crate) fn request(&self) -> &OperatorQuestionRequest {
        &self.request
    }

    pub(crate) fn active_question_index(&self) -> usize {
        self.active_question
    }

    pub(crate) fn active_question(&self) -> &OperatorQuestion {
        &self.request.questions[self.active_question]
    }

    pub(crate) fn selected_option_index(&self) -> usize {
        self.option_cursors[self.active_question]
    }

    pub(crate) fn other_editor(&self) -> Option<&str> {
        self.other_editor.as_ref().map(EditorState::input)
    }

    pub(crate) fn other_cursor(&self) -> Option<usize> {
        self.other_editor.as_ref().map(EditorState::cursor)
    }

    pub(crate) fn is_submitting(&self) -> bool {
        self.submitting
    }

    pub(crate) fn auto_resolution_seconds_remaining(&self) -> Option<u64> {
        if self.auto_resolution_snoozed || self.submitting {
            return None;
        }
        let timeout = Duration::from_millis(self.request.auto_resolution_ms?);
        let remaining = timeout.saturating_sub(self.opened_at.elapsed());
        Some(
            remaining
                .as_secs()
                .saturating_add(u64::from(remaining.subsec_nanos() > 0)),
        )
    }

    pub(crate) fn move_option(&mut self, delta: isize) {
        self.snooze_auto_resolution();
        if self.other_editor.is_some() {
            return;
        }
        let len = self.active_question().options.len();
        self.option_cursors[self.active_question] =
            wrap_index(self.option_cursors[self.active_question], delta, len);
    }

    pub(crate) fn select_number(&mut self, number: usize) -> bool {
        self.snooze_auto_resolution();
        if number == 0 || number > self.active_question().options.len() {
            return false;
        }
        self.option_cursors[self.active_question] = number - 1;
        true
    }

    pub(crate) fn move_question(&mut self, delta: isize) {
        self.snooze_auto_resolution();
        if self.other_editor.is_none() {
            self.active_question =
                wrap_index(self.active_question, delta, self.request.questions.len());
        }
    }

    pub(crate) fn open_other(&mut self) {
        self.snooze_auto_resolution();
        self.other_editor.get_or_insert_with(EditorState::default);
    }

    pub(crate) fn edit_other(&mut self, code: KeyCode) {
        self.snooze_auto_resolution();
        let Some(editor) = self.other_editor.as_mut() else {
            return;
        };
        match code {
            KeyCode::Backspace => editor.backspace(),
            KeyCode::Delete => editor.delete_forward(),
            KeyCode::Left => editor.move_cursor_left(),
            KeyCode::Right => editor.move_cursor_right(),
            KeyCode::Home => editor.move_cursor_home(),
            KeyCode::End => editor.move_cursor_end(),
            KeyCode::Char(ch) => editor.insert_char_at_cursor(ch),
            _ => {}
        }
    }

    pub(crate) fn delete_other_word_left(&mut self) {
        self.snooze_auto_resolution();
        if let Some(editor) = self.other_editor.as_mut() {
            editor.delete_word_left();
        }
    }

    pub(crate) fn paste_other(&mut self, text: &str) -> bool {
        if self.other_editor.is_none() {
            return false;
        }
        self.snooze_auto_resolution();
        let editor = self.other_editor.as_mut().expect("checked Other editor");
        if text.contains('\n') {
            editor.insert_multiline_paste(text);
        } else {
            editor.insert_str_at_cursor(text);
        }
        true
    }

    pub(crate) fn leave_other(&mut self) -> bool {
        self.other_editor.take().is_some()
    }

    pub(crate) fn submit_current(&mut self) -> bool {
        if self.submitting {
            return false;
        }
        self.snooze_auto_resolution();
        if self
            .other_editor
            .as_ref()
            .is_some_and(|editor| editor.input().trim().is_empty())
        {
            return false;
        }
        let answer = self.current_answer();
        self.answers[self.active_question] = Some(answer);
        self.other_editor = None;
        if self.answers.iter().all(Option::is_some) {
            self.submitting = self.send_resolution(OperatorQuestionResolutionKind::Submitted);
            return self.submitting;
        }
        self.active_question = self.next_unanswered_index();
        false
    }

    pub(crate) fn cancel(&mut self) -> bool {
        if self.submitting {
            return false;
        }
        self.snooze_auto_resolution();
        self.submitting = self
            .control
            .send(OperatorQuestionControl::Cancel {
                request_id: self.request.request_id.clone(),
                run_id: self.request.run_id.clone(),
                generation: self.generation,
            })
            .is_ok();
        self.submitting
    }

    fn current_answer(&self) -> OperatorQuestionAnswer {
        let question = self.active_question();
        if let Some(editor) = self.other_editor.as_ref() {
            return OperatorQuestionAnswer::Freeform {
                question_id: question.id.clone(),
                text: editor.expanded_input().trim().to_string(),
            };
        }
        let option = &question.options[self.selected_option_index()];
        OperatorQuestionAnswer::Predefined {
            question_id: question.id.clone(),
            label: option.label.clone(),
        }
    }

    fn next_unanswered_index(&self) -> usize {
        (1..=self.answers.len())
            .map(|offset| (self.active_question + offset) % self.answers.len())
            .find(|index| self.answers[*index].is_none())
            .unwrap_or(self.active_question)
    }

    fn send_resolution(&self, kind: OperatorQuestionResolutionKind) -> bool {
        let resolution = OperatorQuestionResolution {
            request_id: self.request.request_id.clone(),
            kind,
            answers: self.answers.iter().flatten().cloned().collect(),
        };
        self.control
            .send(OperatorQuestionControl::Resolve {
                resolution,
                run_id: self.request.run_id.clone(),
                generation: self.generation,
            })
            .is_ok()
    }

    fn snooze_auto_resolution(&mut self) {
        if self.auto_resolution_snoozed || self.submitting {
            return;
        }
        self.auto_resolution_snoozed = self
            .control
            .send(OperatorQuestionControl::SnoozeAutoResolution {
                request_id: self.request.request_id.clone(),
                run_id: self.request.run_id.clone(),
                generation: self.generation,
            })
            .is_ok();
    }
}

fn recommended_option_index(question: &OperatorQuestion) -> usize {
    question
        .options
        .iter()
        .position(|option| option.recommended)
        .unwrap_or(0)
}

fn wrap_index(current: usize, delta: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    (current as isize + delta).rem_euclid(len as isize) as usize
}
