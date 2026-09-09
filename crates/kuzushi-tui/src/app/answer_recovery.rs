use super::*;
use kuzushi_core::session_transcript::{
    ConversationSnapshot, SessionEvent, SessionTranscriptStore,
};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};

mod snapshot;

#[derive(Debug, Default)]
pub(super) struct AnswerRecovery {
    requested: Option<PathBuf>,
    pending: Option<Receiver<RecoveryResult>>,
}

#[derive(Debug)]
struct RecoveryResult {
    target: PathBuf,
    generation: u64,
    result: Result<Option<ConversationSnapshot>, String>,
}

impl AnswerRecovery {
    fn start(&mut self, target: PathBuf, generation: u64, path: PathBuf) -> anyhow::Result<()> {
        self.requested = Some(target.clone());
        let (send, receive) = mpsc::channel();
        std::thread::Builder::new()
            .name("ask-history".into())
            .spawn(move || {
                let result =
                    recover_from_session_root(&path, &target).map_err(|error| error.to_string());
                let _ = send.send(RecoveryResult {
                    target,
                    generation,
                    result,
                });
            })?;
        self.pending = Some(receive);
        Ok(())
    }

    fn take_ready(&mut self) -> Option<RecoveryResult> {
        let value = self.pending.as_ref()?.try_recv().ok()?;
        self.pending = None;
        Some(value)
    }
}

fn recover_from_session_root(
    path: &std::path::Path,
    target: &std::path::Path,
) -> anyhow::Result<Option<ConversationSnapshot>> {
    let root = path
        .ancestors()
        .nth(4)
        .ok_or_else(|| anyhow::anyhow!("session root is unavailable"))?;
    SessionTranscriptStore::from_root(root).recover_conversation(target, path)
}

impl ShellApp {
    pub(crate) fn wait_for_answer_recovery(&mut self, question: &str) -> bool {
        self.apply_answer_recovery();
        let target = self.target_owned();
        let state = &self.domain.agent_chat_state_mut().recovery;
        if state.pending.is_none() || state.requested != target {
            return false;
        }
        self.router
            .answers_mut()
            .restore_failed_question(target.clone(), target, question);
        self.router.answers_mut().open();
        self.router.answers_mut().reply();
        self.set_info_notice(
            "answers",
            "Loading saved Ask history. Your question is kept; press Enter when loading finishes.",
        );
        true
    }

    pub(crate) fn start_answer_recovery(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let Some(path) = self
            .session
            .transcript()
            .map(|value| value.path().to_path_buf())
        else {
            return;
        };
        if !self.should_recover_answers(&target) {
            return;
        }
        self.set_agent_chat(Some(AgentChatView {
            recovery_note: Some("Loading saved Ask history…".into()),
            ..Default::default()
        }));
        let generation = self.agent_chat_generation();
        let result = self
            .domain
            .agent_chat_state_mut()
            .recovery
            .start(target, generation, path);
        if let Err(error) = result {
            self.set_answer_recovery_note(format!("Ask history could not load: {error}"));
        }
    }

    fn should_recover_answers(&mut self, target: &std::path::Path) -> bool {
        if self.agent_chat().is_some_and(|chat| chat.running) {
            return false;
        }
        if self
            .agent_chat()
            .and_then(|chat| chat.thread_context_key.as_ref())
            .is_some_and(|key| key.canonical_target == target)
        {
            return false;
        }
        self.domain
            .agent_chat_state_mut()
            .recovery
            .requested
            .as_deref()
            != Some(target)
    }

    pub(crate) fn apply_answer_recovery(&mut self) -> bool {
        let Some(recovered) = self.domain.agent_chat_state_mut().recovery.take_ready() else {
            return false;
        };
        if self.target() != Some(recovered.target.as_path())
            || self.agent_chat_generation() != recovered.generation
        {
            return false;
        }
        self.install_recovered_answer(recovered.result);
        true
    }

    fn install_recovered_answer(&mut self, result: Result<Option<ConversationSnapshot>, String>) {
        match result {
            Ok(Some(snapshot)) => self.install_answer_snapshot(snapshot),
            Ok(None) => self.set_answer_recovery_note(
                "No recoverable Ask history in recent sessions. Older transcripts remain available with kuzushi sessions.".into()
            ),
            Err(error) => self.set_answer_recovery_note(format!("Ask history could not load: {error}. Start a new question or inspect kuzushi sessions.")),
        }
    }

    fn install_answer_snapshot(&mut self, saved: ConversationSnapshot) {
        let restored = snapshot::restore(saved);
        if restored.error.is_some() {
            let target = restored
                .thread_context_key
                .as_ref()
                .map(|key| key.canonical_target.clone());
            let active = self.target_owned();
            self.router
                .answers_mut()
                .restore_failed_question(target, active, &restored.question);
        }
        self.set_agent_chat(Some(restored));
    }

    fn set_answer_recovery_note(&mut self, note: String) {
        self.agent_chat_or_default_mut().recovery_note = Some(note);
    }

    pub(crate) fn persist_answer_conversation(&mut self) {
        let Some(saved) = self.agent_chat().and_then(snapshot::capture) else {
            return;
        };
        if let Err(error) = saved.validate() {
            self.record_session_event(SessionEvent::AgentConversationCleared {
                target: saved.context.canonical_target,
            });
            self.set_info_notice(
                "answers",
                format!("Ask can continue, but restart history was not saved: {error}"),
            );
            return;
        }
        self.record_session_event(SessionEvent::AgentConversation { snapshot: saved });
    }

    pub(crate) fn record_cleared_answer_conversation(&mut self) {
        if let Some(target) = self.target_owned() {
            self.record_session_event(SessionEvent::AgentConversationCleared { target });
        }
    }
}

#[cfg(test)]
mod tests;
