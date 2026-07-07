use super::*;

pub(crate) fn refresh_terminal_redraw_state(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> Result<()> {
    state.needs_redraw |= app_background_changed(app, watcher);
    state.needs_redraw |= clear_terminal_after_external_output(terminal, app)?;
    state.needs_redraw = draw_terminal_if_needed(terminal, app, state.needs_redraw)?;
    Ok(())
}

pub(crate) fn app_background_changed(
    app: &mut ShellApp,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> bool {
    let drain_changed = apply_runtime_messages(app, Instant::now(), watcher);
    let view_changed = app.sync_view_change();
    drain_changed || view_changed
}

pub(crate) fn apply_runtime_messages(
    app: &mut ShellApp,
    now: Instant,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> bool {
    let maintenance_changed = app.run_background_maintenance();
    let watcher_changed = apply_watcher_messages(app, watcher);
    let mut messages = Vec::with_capacity(1);
    messages.push(Msg::Tick(now));
    messages.extend(app.drain_job_messages());
    update_many_and_execute_effects(app, messages) || maintenance_changed || watcher_changed
}

pub(crate) fn apply_pending_background_events(app: &mut ShellApp) -> bool {
    let maintenance_changed = app.run_background_maintenance();
    let messages = app.drain_job_messages();
    update_many_and_execute_effects(app, messages) || maintenance_changed
}

pub(crate) fn clear_terminal_after_external_output(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
) -> Result<bool> {
    if !app.ui_mut().take_force_full_redraw() {
        return Ok(false);
    }
    // A subprocess wrote to our terminal while we were paused (e.g. OAuth
    // bridge). Drop ratatui's diff buffer so the next draw repaints every cell.
    terminal.clear()?;
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

pub(crate) fn terminal_event_timeout(app: &ShellApp) -> Duration {
    if app.scene_animating() {
        SCENE_FRAME
    } else if app.has_running_work() {
        SPINNER_FRAME
    } else {
        Duration::from_millis(250)
    }
}

#[cfg(test)]
pub(crate) fn apply_terminal_event(app: &mut ShellApp, event: Event) -> bool {
    TermEvent::from_crossterm(event)
        .map(|event| update_and_execute_effects(app, Msg::Term(event)))
        .unwrap_or(false)
}

pub(crate) fn run_plain_shell(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    stdin: &mut io::Stdin,
    stdin_is_terminal: bool,
    registry: ModuleRegistry,
) -> Result<()> {
    let mut app = ShellApp::with_registry(config, target, registry);
    apply_launch_start_view(&mut app);
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
