use super::*;
use crate::app::state_transitions::InputUpdate;
use crossterm::event::{Event, KeyEvent, MouseEvent};

pub(crate) enum Msg {
    Term(TermEvent),
    Tick(Instant),
    Job(ShellEvent),
    WorkspaceChanged(Vec<kuzushi_core::incremental_index::WorkspaceChange>),
    Cmd(ShellCommand),
}

pub(crate) enum TermEvent {
    Key(KeyEvent),
    Paste(String),
    Mouse(MouseEvent),
    Resize { columns: u16, rows: u16 },
}

#[derive(Default)]
pub(crate) struct UpdateResult {
    pub(crate) changed: bool,
    pub(crate) effects: Vec<ShellEffect>,
}

pub(crate) fn update(app: &mut ShellApp, msg: Msg) -> UpdateResult {
    match msg {
        Msg::Term(event) => update_terminal(app, event),
        Msg::Tick(now) => UpdateResult::changed(app.tick_at(now)),
        Msg::Job(event) => {
            let effects = app.apply_job_event(event);
            UpdateResult {
                changed: true,
                effects,
            }
        }
        Msg::WorkspaceChanged(changes) => {
            app.apply_workspace_changes(&changes);
            UpdateResult::changed(true)
        }
        Msg::Cmd(command) => update_command(app, command),
    }
}

pub(crate) fn update_and_execute_effects(app: &mut ShellApp, msg: Msg) -> bool {
    let result = update(app, msg);
    let changed = result.changed || !result.effects.is_empty();
    EffectRuntime::execute(app, result.effects);
    changed
}

impl UpdateResult {
    fn changed(changed: bool) -> Self {
        Self {
            changed,
            effects: Vec::new(),
        }
    }

    fn from_input(update: InputUpdate) -> Self {
        Self {
            changed: update.handled,
            effects: update.effects,
        }
    }
}

fn update_command(app: &mut ShellApp, command: ShellCommand) -> UpdateResult {
    let command_update = app.reduce_command_message(command);
    UpdateResult {
        changed: command_update.handled,
        effects: command_update.effects,
    }
}

impl TermEvent {
    pub(crate) fn from_crossterm(event: Event) -> Option<Self> {
        match event {
            Event::Key(key) => Some(Self::Key(key)),
            Event::Paste(text) => Some(Self::Paste(text)),
            Event::Mouse(mouse) => Some(Self::Mouse(mouse)),
            Event::Resize(columns, rows) => Some(Self::Resize { columns, rows }),
            _ => None,
        }
    }
}

fn update_terminal(app: &mut ShellApp, event: TermEvent) -> UpdateResult {
    match event {
        TermEvent::Key(key) => UpdateResult::from_input(app.reduce_key(key)),
        TermEvent::Paste(text) => UpdateResult::from_input(app.reduce_paste(&text)),
        TermEvent::Mouse(mouse) => UpdateResult::from_input(app.reduce_mouse(mouse)),
        TermEvent::Resize { columns, rows } => {
            UpdateResult::from_input(app.reduce_resize(columns, rows))
        }
    }
}

#[cfg(test)]
mod tests;
