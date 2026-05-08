use super::prelude::*;
use super::*;

pub(crate) fn refresh_terminal_redraw_state(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
) -> Result<()> {
    state.needs_redraw |= app_background_changed(app);
    state.needs_redraw |= clear_terminal_after_external_output(terminal, app)?;
    state.needs_redraw = draw_terminal_if_needed(terminal, app, state.needs_redraw)?;
    Ok(())
}

pub(crate) fn app_background_changed(app: &mut ShellApp) -> bool {
    let tick_changed = app.tick();
    let drain_changed = app.drain_background_events();
    let view_changed = app.sync_view_change();
    tick_changed || drain_changed || view_changed
}

pub(crate) fn clear_terminal_after_external_output(
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

pub(crate) fn draw_terminal_if_needed(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &ShellApp,
    needs_redraw: bool,
) -> Result<bool> {
    if needs_redraw {
        terminal.draw(|frame| render_app(frame, app))?;
    }
    Ok(false)
}

pub(crate) fn poll_terminal_event(app: &mut ShellApp) -> Result<bool> {
    if !terminal_event_ready(app)? {
        return Ok(false);
    }
    read_and_apply_terminal_event(app)
}

pub(crate) fn terminal_event_ready(app: &ShellApp) -> Result<bool> {
    Ok(event::poll(terminal_event_timeout(app))?)
}

pub(crate) fn read_and_apply_terminal_event(app: &mut ShellApp) -> Result<bool> {
    Ok(apply_terminal_event(app, event::read()?))
}

pub(crate) fn terminal_event_timeout(app: &ShellApp) -> Duration {
    if app.has_running_work() {
        SPINNER_FRAME
    } else {
        Duration::from_millis(250)
    }
}

pub(crate) fn apply_terminal_event(app: &mut ShellApp, event: Event) -> bool {
    match event {
        Event::Key(key) => app.handle_key(key),
        Event::Paste(text) => app.handle_paste(&text),
        Event::Mouse(mouse) => app.handle_mouse(mouse),
        Event::Resize(_, _) => {}
        _ => return false,
    }
    true
}

pub(crate) fn run_plain_shell(
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
