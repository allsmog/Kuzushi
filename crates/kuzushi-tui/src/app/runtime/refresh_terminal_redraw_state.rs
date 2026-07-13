use super::*;

pub(crate) fn refresh_terminal_redraw_state(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> Result<bool> {
    let background = apply_runtime_messages_and_sync_view(app, Instant::now(), watcher);
    state.needs_redraw |= background.changed;
    state.needs_redraw |= clear_terminal_after_external_output(terminal, app)?;
    state.needs_redraw |= app.schedule_active_view_hydration();
    state.needs_redraw = draw_terminal_if_needed(terminal, app, state.needs_redraw)?;
    Ok(background.work_tail_may_remain)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RuntimeMessageOutcome {
    pub(crate) changed: bool,
    pub(crate) work_tail_may_remain: bool,
}

pub(crate) fn app_background_changed(
    app: &mut ShellApp,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> bool {
    apply_runtime_messages_and_sync_view(app, Instant::now(), watcher).changed
}

pub(crate) fn apply_runtime_messages_and_sync_view(
    app: &mut ShellApp,
    now: Instant,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> RuntimeMessageOutcome {
    let mut outcome = apply_runtime_messages_with_outcome(app, now, watcher);
    outcome.changed |= app.sync_view_change();
    outcome
}

pub(crate) fn apply_runtime_messages_with_outcome(
    app: &mut ShellApp,
    now: Instant,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> RuntimeMessageOutcome {
    let maintenance_changed = app.run_background_maintenance();
    let watcher = apply_watcher_messages_with_outcome(app, watcher);
    let tick_changed = update_and_execute_effects(app, Msg::Tick(now));
    let jobs = app.drain_job_events_with_outcome();
    RuntimeMessageOutcome {
        changed: maintenance_changed || watcher.changed || tick_changed || jobs.changed,
        work_tail_may_remain: watcher.tail_may_remain || jobs.time_slice_exhausted,
    }
}

pub(crate) fn apply_pending_background_events(app: &mut ShellApp) -> bool {
    let maintenance_changed = app.run_background_maintenance();
    app.drain_job_events() || maintenance_changed
}

pub(crate) fn clear_terminal_after_external_output<B>(
    terminal: &mut Terminal<B>,
    app: &mut ShellApp,
) -> Result<bool>
where
    B: Backend,
    B::Error: Send + Sync + 'static,
{
    if !app.ui_mut().take_force_full_redraw() {
        return Ok(false);
    }
    // A subprocess wrote to our terminal while we were paused (e.g. OAuth
    // bridge). Drop ratatui's diff buffer so the next draw repaints every cell.
    // Ratatui 0.30's `Terminal::clear` queries the cursor first. Fullscreen
    // Kuzushi does not need to preserve that cursor, and some terminals do not
    // answer the query. Resizing to the current area clears and resets the
    // buffers without issuing a terminal cursor-position request.
    let area = terminal.size()?.into();
    terminal.resize(area)?;
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
        print!("{}", plain_launch_summary(&app));
        return Ok(());
    }

    let report = execute_plain_scripted_session(&mut app, &commands, 80);
    print!("{}", report.output);
    if report.failed {
        anyhow::bail!("plain scripted session failed; see the result above");
    }
    Ok(())
}

fn plain_launch_summary(app: &ShellApp) -> String {
    let target = app
        .target()
        .map(|target| target.display().to_string())
        .unwrap_or_else(|| "none".to_string());
    let next = if app.target().is_some() {
        "printf 'findings\\n' | kuzushi --plain --target <path>"
    } else {
        "printf 'scan .\\n' | kuzushi --plain"
    };
    format!(
        "KUZUSHI PLAIN SESSION SUMMARY\nstatus: idle\ntarget: {target}\ncommands: 0\nNext: {next}\n"
    )
}

#[cfg(test)]
mod plain_summary_tests {
    use super::*;

    #[test]
    fn bare_plain_summary_is_self_contained_and_non_interactive() {
        let app = ShellApp::new(V2Config::default(), None);
        let output = plain_launch_summary(&app);

        assert!(output.contains("PLAIN SESSION SUMMARY"));
        assert!(output.contains("status: idle"));
        assert!(output.contains("target: none"));
        assert!(output.contains("commands: 0"));
        assert!(output.contains("Next: printf 'scan .\\n' | kuzushi --plain"));
        assert_eq!(output.lines().count(), 5);
        assert!(!output.contains("press "));
        assert!(!output.contains("kuzushi>"));
    }
}
