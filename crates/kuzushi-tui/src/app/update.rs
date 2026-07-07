use super::*;
use crossterm::event::{Event, KeyEvent, MouseEvent};

pub(crate) enum Msg {
    Term(TermEvent),
    Tick(Instant),
    Job(ShellEvent),
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
        Msg::Term(event) => UpdateResult::changed(update_terminal(app, event)),
        Msg::Tick(now) => UpdateResult::changed(app.tick_at(now)),
        Msg::Job(event) => {
            app.apply_job_event(event);
            UpdateResult::changed(true)
        }
        Msg::Cmd(command) => update_command(app, command),
    }
}

pub(crate) fn update_and_execute_effects(app: &mut ShellApp, msg: Msg) -> bool {
    let result = update(app, msg);
    let changed = result.changed || !result.effects.is_empty();
    app.execute_effects(result.effects);
    changed
}

impl UpdateResult {
    fn changed(changed: bool) -> Self {
        Self {
            changed,
            effects: Vec::new(),
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

fn update_terminal(app: &mut ShellApp, event: TermEvent) -> bool {
    match event {
        TermEvent::Key(key) => app.handle_key(key),
        TermEvent::Paste(text) => app.handle_paste(&text),
        TermEvent::Mouse(mouse) => app.handle_mouse(mouse),
        TermEvent::Resize { columns, rows } => {
            let _ = (columns, rows);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers};
    use kuzushi_core::V2Config;

    #[test]
    fn update_routes_terminal_key_events() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(
            &mut app,
            Msg::Term(TermEvent::Key(KeyEvent::new(
                KeyCode::Char('x'),
                KeyModifiers::empty(),
            ))),
        );

        assert!(result.changed);
        assert_eq!(app.input, "x");
    }

    #[test]
    fn update_routes_command_messages() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(&mut app, Msg::Cmd(ShellCommand::Help(None)));

        assert!(result.changed);
        assert!(result.effects.is_empty());
        assert_eq!(app.shell_view, ShellView::Help);
    }

    #[test]
    fn update_returns_command_effects_without_executing_them() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(&mut app, Msg::Cmd(ShellCommand::Quit));

        assert!(result.changed);
        assert_eq!(result.effects.len(), 1);
        assert!(matches!(result.effects[0], ShellEffect::Quit));
        assert!(!app.should_quit);
    }

    #[test]
    fn handle_command_executes_command_effects() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.handle_command(ShellCommand::Quit);

        assert!(app.should_quit);
    }

    #[test]
    fn update_and_execute_effects_runs_returned_effects() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let changed = update_and_execute_effects(&mut app, Msg::Cmd(ShellCommand::Quit));

        assert!(changed);
        assert!(app.should_quit);
    }

    #[test]
    fn update_routes_tick_messages() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let now = Instant::now();
        app.ctrl_c_armed_at = Some(now - CTRL_C_ARM_WINDOW - Duration::from_millis(1));

        let result = update(&mut app, Msg::Tick(now));

        assert!(result.changed);
        assert_eq!(app.ctrl_c_armed_at, None);
    }
}
