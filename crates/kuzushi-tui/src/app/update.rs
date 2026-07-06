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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UpdateResult {
    pub(crate) changed: bool,
}

pub(crate) fn update(app: &mut ShellApp, msg: Msg) -> UpdateResult {
    let changed = match msg {
        Msg::Term(event) => update_terminal(app, event),
        Msg::Tick(now) => app.tick_at(now),
        Msg::Job(event) => {
            app.apply_job_event(event);
            true
        }
        Msg::Cmd(command) => {
            app.handle_command(command);
            true
        }
    };
    UpdateResult { changed }
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
        assert_eq!(app.shell_view, ShellView::Help);
    }
}
