use super::*;
use crate::app::state_transitions::InputUpdate;
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
        Msg::Term(event) => update_terminal(app, event),
        Msg::Tick(now) => UpdateResult::changed(app.tick_at(now)),
        Msg::Job(event) => {
            let effects = app.apply_job_event(event);
            UpdateResult {
                changed: true,
                effects,
            }
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

pub(crate) fn update_many_and_execute_effects(
    app: &mut ShellApp,
    messages: impl IntoIterator<Item = Msg>,
) -> bool {
    let result = update_many(app, messages);
    let changed = result.changed || !result.effects.is_empty();
    EffectRuntime::execute(app, result.effects);
    changed
}

pub(crate) fn update_many(
    app: &mut ShellApp,
    messages: impl IntoIterator<Item = Msg>,
) -> UpdateResult {
    let mut batch = UpdateResult::default();
    for msg in messages {
        batch.merge(update(app, msg));
    }
    batch
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

    fn merge(&mut self, next: Self) {
        self.changed |= next.changed;
        self.effects.extend(next.effects);
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
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
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
        assert_eq!(app.input(), "x");
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
    fn update_routes_scripted_scan_as_effect_data() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(
            &mut app,
            Msg::Cmd(ShellCommand::ScriptedScan(Some(tmp.path().to_path_buf()))),
        );

        assert!(result.changed);
        assert_eq!(result.effects.len(), 1);
        assert!(matches!(result.effects[0], ShellEffect::PrepareScan(_)));
        assert!(app.scan().is_none());
        assert!(!app.jobs.is_running(JobKind::Run));
    }

    #[test]
    fn update_returns_command_effects_without_executing_them() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(&mut app, Msg::Cmd(ShellCommand::Quit));

        assert!(result.changed);
        assert_eq!(result.effects.len(), 1);
        assert!(matches!(result.effects[0], ShellEffect::Quit));
        assert!(!app.should_quit());
    }

    #[test]
    fn update_many_accumulates_effects_without_executing_them() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update_many(
            &mut app,
            [
                Msg::Cmd(ShellCommand::Quit),
                Msg::Term(TermEvent::Key(KeyEvent::new(
                    KeyCode::Char('x'),
                    KeyModifiers::empty(),
                ))),
            ],
        );

        assert!(result.changed);
        assert_eq!(result.effects.len(), 1);
        assert!(matches!(result.effects[0], ShellEffect::Quit));
        assert_eq!(app.input(), "x");
        assert!(!app.should_quit());
    }

    #[test]
    fn update_terminal_enter_returns_submit_effects_without_executing_them() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let history_path = tmp.path().join(".kuzushi/v3/shell-history.txt");
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.shell_view = ShellView::Home;
        app.set_input("tools");
        app.set_cursor(app.input().chars().count());

        let result = update(
            &mut app,
            Msg::Term(TermEvent::Key(KeyEvent::new(
                KeyCode::Enter,
                KeyModifiers::empty(),
            ))),
        );

        assert!(result.changed);
        assert_eq!(app.input(), "");
        assert_eq!(app.shell_view, ShellView::Tools);
        assert!(result
            .effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::PersistCommandHistory)));
        assert!(!history_path.exists());
    }

    #[test]
    fn update_terminal_picker_demo_key_returns_effect_without_executing_it() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::ModelPicker;

        let result = update(
            &mut app,
            Msg::Term(TermEvent::Key(KeyEvent::new(
                KeyCode::Char('d'),
                KeyModifiers::empty(),
            ))),
        );

        assert!(result.changed);
        assert_eq!(result.effects.len(), 1);
        assert!(matches!(
            result.effects[0],
            ShellEffect::StartOfflineDemoFixtureScan
        ));
        assert!(app.scan_is_none());
        assert!(!app.jobs.is_running(JobKind::Run));
    }

    #[test]
    fn update_terminal_pending_plan_accept_returns_effect_without_executing_it() {
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());
        let mut app = ShellApp::new(config, None);
        app.set_pending_plan(PlanProposal {
            goal: "g".to_string(),
            summary: "s".to_string(),
            changes: vec![PlanChange::Ask {
                question: "inspect authz drift".to_string(),
            }],
            unsupported: vec![],
        });

        let result = update(
            &mut app,
            Msg::Term(TermEvent::Key(KeyEvent::new(
                KeyCode::Char('y'),
                KeyModifiers::empty(),
            ))),
        );

        assert!(result.changed);
        assert!(!app.engagement.has_pending_plan());
        assert!(result
            .effects
            .iter()
            .any(|effect| matches!(effect, ShellEffect::DispatchAgent(_))));
        assert!(!app.jobs.is_running(JobKind::Agent));
    }

    #[test]
    fn update_terminal_paste_returns_changed_without_effects() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(&mut app, Msg::Term(TermEvent::Paste("hello".to_string())));

        assert!(result.changed);
        assert!(result.effects.is_empty());
        assert_eq!(app.input(), "hello");
    }

    #[test]
    fn update_terminal_empty_paste_is_ignored() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(&mut app, Msg::Term(TermEvent::Paste(String::new())));

        assert!(!result.changed);
        assert!(result.effects.is_empty());
        assert_eq!(app.input(), "");
    }

    #[test]
    fn update_terminal_resize_records_viewport_state() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let result = update(
            &mut app,
            Msg::Term(TermEvent::Resize {
                columns: 0,
                rows: 24,
            }),
        );

        assert!(result.changed);
        assert_eq!(app.viewport(), TerminalViewport::new(1, 24));
    }

    #[test]
    fn update_terminal_mouse_uses_recorded_viewport_for_hit_testing() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Workbench;
        app.router.workbench_mut().set_focus(WorkbenchPane::Source);
        update(
            &mut app,
            Msg::Term(TermEvent::Resize {
                columns: 80,
                rows: 20,
            }),
        );

        let result = update(
            &mut app,
            Msg::Term(TermEvent::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 10,
                row: 15,
                modifiers: KeyModifiers::empty(),
            })),
        );

        assert!(result.changed);
        assert_eq!(app.router.workbench().focus(), WorkbenchPane::Details);
    }

    #[test]
    fn handle_command_executes_command_effects() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.handle_command(ShellCommand::Quit);

        assert!(app.should_quit());
    }

    #[test]
    fn update_and_execute_effects_runs_returned_effects() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let changed = update_and_execute_effects(&mut app, Msg::Cmd(ShellCommand::Quit));

        assert!(changed);
        assert!(app.should_quit());
    }

    #[test]
    fn update_routes_tick_messages() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let now = Instant::now();
        app.set_ctrl_c_armed_at(Some(now - CTRL_C_ARM_WINDOW - Duration::from_millis(1)));

        let result = update(&mut app, Msg::Tick(now));

        assert!(result.changed);
        assert_eq!(app.ctrl_c_armed_at(), None);
    }
}
