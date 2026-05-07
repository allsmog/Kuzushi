use std::env;
use std::io::{self, IsTerminal, Read, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::cursor::MoveTo;
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event,
};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use kuzushi_core::{V2Config, WorkspaceTarget};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::renderer::{render_app, render_plain_app, render_plain_command_result};

use super::{ShellApp, SPINNER_FRAME};

pub fn run_shell(config: V2Config, target: Option<&WorkspaceTarget>) -> Result<()> {
    run_shell_with_plain(config, target, false)
}

pub fn run_shell_with_plain(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    force_plain: bool,
) -> Result<()> {
    let mut stdin = io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    let stdout_is_terminal = io::stdout().is_terminal();
    if should_run_plain_shell(force_plain, stdin_is_terminal, stdout_is_terminal) {
        return run_plain_shell(config, target, &mut stdin, stdin_is_terminal);
    }

    run_terminal_shell(config, target)
}

fn should_run_plain_shell(
    force_plain: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
) -> bool {
    should_run_plain_shell_for_io(
        force_plain,
        stdin_is_terminal,
        stdout_is_terminal,
        plain_shell_env_requested(),
    )
}

fn should_run_plain_shell_for_io(
    force_plain: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    env_requested: bool,
) -> bool {
    force_plain || !stdin_is_terminal || !stdout_is_terminal || env_requested
}

fn plain_shell_env_requested() -> bool {
    env::var_os("KUZUSHI_PLAIN").is_some()
        || env::var_os("KUZUSHI_SCREEN_READER").is_some()
        || env::var_os("KUZUSHI_LOW_BANDWIDTH").is_some()
}

fn run_terminal_shell(config: V2Config, target: Option<&WorkspaceTarget>) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = ShellApp::new(config, target);
    let result = terminal_shell_loop(&mut terminal, &mut app);
    let _ = restore_terminal(&mut terminal);
    result
}

fn terminal_shell_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
) -> Result<()> {
    let mut state = TerminalLoopState::default();
    while !app.should_quit {
        terminal_shell_step(terminal, app, &mut state)?;
    }
    Ok(())
}

#[derive(Debug)]
struct TerminalLoopState {
    needs_redraw: bool,
}

impl Default for TerminalLoopState {
    fn default() -> Self {
        Self { needs_redraw: true }
    }
}

fn terminal_shell_step(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
) -> Result<()> {
    state.needs_redraw |= app_background_changed(app);
    state.needs_redraw |= clear_terminal_after_external_output(terminal, app)?;
    state.needs_redraw = draw_terminal_if_needed(terminal, app, state.needs_redraw)?;
    state.needs_redraw |= poll_terminal_event(app)?;
    Ok(())
}

fn app_background_changed(app: &mut ShellApp) -> bool {
    let tick_changed = app.tick();
    let drain_changed = app.drain_background_events();
    let view_changed = app.sync_view_change();
    tick_changed || drain_changed || view_changed
}

fn clear_terminal_after_external_output(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
) -> Result<bool> {
    if !app.force_full_redraw {
        return Ok(false);
    }
    // A subprocess wrote to our terminal while we were paused (e.g. OAuth
    // bridge). Drop ratatui's diff buffer so the next draw repaints every cell.
    terminal.clear()?;
    app.force_full_redraw = false;
    Ok(true)
}

fn draw_terminal_if_needed(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &ShellApp,
    needs_redraw: bool,
) -> Result<bool> {
    if needs_redraw {
        terminal.draw(|frame| render_app(frame, app))?;
    }
    Ok(false)
}

fn poll_terminal_event(app: &mut ShellApp) -> Result<bool> {
    if !event::poll(terminal_event_timeout(app))? {
        return Ok(false);
    }
    Ok(apply_terminal_event(app, event::read()?))
}

fn terminal_event_timeout(app: &ShellApp) -> Duration {
    if app.has_running_work() {
        SPINNER_FRAME
    } else {
        Duration::from_millis(250)
    }
}

fn apply_terminal_event(app: &mut ShellApp, event: Event) -> bool {
    match event {
        Event::Key(key) => app.handle_key(key),
        Event::Paste(text) => app.handle_paste(&text),
        Event::Mouse(mouse) => app.handle_mouse(mouse),
        Event::Resize(_, _) => {}
        _ => return false,
    }
    true
}

fn run_plain_shell(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    stdin: &mut io::Stdin,
    stdin_is_terminal: bool,
) -> Result<()> {
    let mut app = ShellApp::new(config, target);
    let mut script = String::new();
    if !stdin_is_terminal {
        stdin
            .read_to_string(&mut script)
            .context("Could not read plain shell input")?;
    }

    let commands = script
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if commands.is_empty() {
        print!("{}", render_plain_app(&app, 80));
        return Ok(());
    }

    print!("{}", render_plain_scripted_session(&mut app, &commands, 80));
    Ok(())
}

pub(super) fn render_plain_scripted_session(
    app: &mut ShellApp,
    commands: &[&str],
    width: usize,
) -> String {
    let mut output = String::new();
    for (index, command) in commands.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let log_start = app.log.len();
        app.submit_line(command);
        app.drain_background_events();
        output.push_str(&render_plain_command_result(app, width, command, log_start));
        if app.should_quit {
            break;
        }
    }
    output
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("Could not enable raw mode")?;
    let mut stdout = reset_terminal_viewport()?;
    enable_mouse_capture_if_configured(&mut stdout)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).context("Could not initialize terminal")
}

fn reset_terminal_viewport() -> Result<Stdout> {
    let mut stdout = io::stdout();
    execute!(
        stdout,
        Clear(ClearType::All),
        MoveTo(0, 0),
        EnableBracketedPaste
    )
    .context("Could not reset terminal viewport")?;
    Ok(stdout)
}

fn enable_mouse_capture_if_configured(stdout: &mut Stdout) -> Result<()> {
    if mouse_capture_enabled() {
        execute!(stdout, EnableMouseCapture).context("Could not enable mouse capture")?;
    }
    Ok(())
}

fn mouse_capture_enabled() -> bool {
    let value = env::var("KUZUSHI_MOUSE_CAPTURE").ok();
    mouse_capture_setting_enabled(value.as_deref())
}

pub(super) fn mouse_capture_setting_enabled(value: Option<&str>) -> bool {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };

    value == "1"
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    let _ = execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        DisableBracketedPaste
    );
    disable_raw_mode().context("Could not disable raw mode")?;
    terminal
        .show_cursor()
        .context("Could not show terminal cursor")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };

    #[test]
    fn plain_shell_detection_covers_forced_non_tty_and_tty_modes() {
        assert!(should_run_plain_shell_for_io(true, true, true, false));
        assert!(should_run_plain_shell_for_io(false, false, true, false));
        assert!(should_run_plain_shell_for_io(false, true, false, false));
        assert!(should_run_plain_shell_for_io(false, true, true, true));
        assert!(!should_run_plain_shell_for_io(false, true, true, false));
    }

    #[test]
    fn terminal_event_dispatch_updates_app_for_interactive_events() {
        let mut app = ShellApp::new(V2Config::default(), None);

        assert!(apply_terminal_event(
            &mut app,
            Event::Paste("abc".to_string())
        ));
        assert_eq!(app.input, "abc");

        assert!(apply_terminal_event(
            &mut app,
            Event::Key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE))
        ));
        assert_eq!(app.input, "abcd");

        assert!(apply_terminal_event(&mut app, Event::Resize(120, 40)));
        assert!(apply_terminal_event(
            &mut app,
            Event::Mouse(MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 0,
                row: 0,
                modifiers: KeyModifiers::NONE,
            })
        ));
        assert!(!apply_terminal_event(&mut app, Event::FocusGained));
    }
}
