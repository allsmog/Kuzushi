use super::*;

pub(crate) fn refresh_terminal_redraw_state(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> Result<bool> {
    let background = apply_runtime_messages_and_sync_view(app, Instant::now(), watcher);
    let mut changed = background.changed;
    sync_terminal_title(terminal, app, state)?;
    sync_attention_signals(terminal, app, state)?;
    changed |= clear_terminal_after_external_output(terminal, app)?;
    changed |= app.schedule_active_view_hydration();
    state.request_redraw(changed, RedrawPriority::Background);
    Ok(background.work_tail_may_remain)
}

/// Out-of-frame attention: a newly appeared attention item rings the terminal
/// bell and posts an OSC 9 desktop notification, but only when the operator
/// is provably away (`should_notify_blurred` fails closed on unknown focus).
/// Active ids are recorded unconditionally so a suppressed item never replays
/// once focus is lost later. Resolved ids leave the active set, allowing a
/// later, distinct gate with the same stable id to notify.
fn sync_attention_signals(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
) -> Result<()> {
    if app.ui().terminal_focus() != crate::app::FocusState::Unknown {
        state.focus_unknown_notice_emitted = false;
    }
    let items = crate::app::notification_attention_items(app);
    let new_items = crate::app::newly_appeared_attention(&mut state.active_attention_ids, &items);
    let message = crate::app::notification_message(&new_items);
    let Some(message) = message else {
        return Ok(());
    };
    match crate::app::should_notify_blurred(app.ui().notify_enabled(), app.ui().terminal_focus()) {
        Ok(()) => {}
        Err(crate::app::NotifySkip::FocusUnknown) => {
            if !state.focus_unknown_notice_emitted {
                app.log(
                    "notify",
                    "desktop alert unavailable because this terminal does not report focus",
                );
                state.focus_unknown_notice_emitted = true;
            }
            return Ok(());
        }
        Err(_) => return Ok(()),
    }
    // BEL rings the terminal's bell; OSC 9 raises a desktop notification on
    // terminals that support it (iTerm2, kitty, WezTerm) and is ignored
    // elsewhere. The message is static kind text — no operator data leaves
    // the frame.
    execute!(
        terminal.backend_mut(),
        crossterm::style::Print(format!("\x07\x1b]9;Kuzushi · {message}\x07"))
    )
    .context("Could not emit attention notification")?;
    Ok(())
}

fn sync_terminal_title(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &ShellApp,
    state: &mut TerminalLoopState,
) -> Result<()> {
    let title = crate::ui_view_models::terminal_title(app);
    if state.last_title.as_deref() == Some(&title) {
        return Ok(());
    }
    execute!(
        terminal.backend_mut(),
        crossterm::terminal::SetTitle(&title)
    )
    .context("Could not update terminal title")?;
    state.last_title = Some(title);
    Ok(())
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
    let store_changed = app.refresh_findings_after_external_store_write(now);
    let jobs = app.drain_job_events_with_outcome();
    RuntimeMessageOutcome {
        changed: maintenance_changed
            || watcher.changed
            || tick_changed
            || store_changed
            || jobs.changed,
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

/// Background refreshes remain capped near 30 fps, while input-driven frames
/// can paint at 125 fps. Batching prevents that tighter interactive interval
/// from turning a queued character burst into one full render per character.
pub(crate) const BACKGROUND_FRAME_INTERVAL: Duration = Duration::from_millis(33);
pub(crate) const INTERACTIVE_FRAME_INTERVAL: Duration = Duration::from_millis(8);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RedrawPriority {
    #[default]
    Background,
    Interactive,
}

impl RedrawPriority {
    fn frame_interval(self) -> Duration {
        match self {
            Self::Background => BACKGROUND_FRAME_INTERVAL,
            Self::Interactive => INTERACTIVE_FRAME_INTERVAL,
        }
    }
}

pub(crate) fn draw_terminal_if_needed(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
) -> Result<()> {
    if !should_draw_frame(
        state.needs_redraw,
        state.redraw_priority,
        state.last_draw,
        Instant::now(),
    ) {
        // A deferred dirty frame stays pending; the capped recv timeout in
        // `terminal_shell_step` guarantees it paints within the interval.
        return Ok(());
    }
    terminal.draw(|frame| render_measured_terminal_frame(frame, app))?;
    state.last_draw = Some(Instant::now());
    state.needs_redraw = false;
    state.redraw_priority = RedrawPriority::Background;
    Ok(())
}

fn render_measured_terminal_frame(frame: &mut ratatui::Frame<'_>, app: &mut ShellApp) {
    let area = frame.area();
    app.set_viewport(TerminalViewport::new(area.width, area.height));
    render_app(frame, app);
}

#[cfg(test)]
mod measured_frame_tests {
    use super::*;
    use crate::ui_view_models::PhaseSurfaceId;
    use ratatui::backend::TestBackend;

    fn fixture() -> (tempfile::TempDir, ShellApp) {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Review));
        app.router
            .workbench_mut()
            .set_focus(PhaseSurfaceId::ReviewDetail);
        app.set_findings(vec![kuzushi_core::Finding::new_tool(
            "native",
            "owned",
            "note.txt",
            1,
            Some(1),
            kuzushi_core::Severity::Low,
            "Owned inert fixture",
        )]);
        app.set_viewport(TerminalViewport::new(120, 36));
        (root, app)
    }

    #[test]
    fn frame_size_preserves_the_draft_cursor_focus_and_scroll() {
        let (_root, mut app) = fixture();
        app.set_input("unsent\noperator draft");
        app.set_cursor(3);
        app.router
            .workbench_mut()
            .scroll_mut()
            .set(PhaseSurfaceId::ReviewDetail, 5);
        let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
        terminal
            .draw(|frame| render_measured_terminal_frame(frame, &mut app))
            .unwrap();
        assert_eq!(app.viewport(), TerminalViewport::new(40, 12));
        assert_eq!(app.input(), "unsent\noperator draft");
        assert_eq!(app.cursor(), 3);
        assert_eq!(
            app.router
                .workbench()
                .scroll()
                .get(PhaseSurfaceId::ReviewDetail),
            5
        );
        assert_eq!(
            app.router.workbench().focus_for(WorkbenchPage::Review),
            PhaseSurfaceId::ReviewDetail
        );
    }

    #[test]
    fn a_measured_resize_updates_review_paging_without_a_resize_event() {
        let (_root, mut app) = fixture();
        app.set_input_mode(InputMode::Navigate);
        let mut terminal = Terminal::new(TestBackend::new(40, 12)).unwrap();
        terminal
            .draw(|frame| render_measured_terminal_frame(frame, &mut app))
            .unwrap();
        let page = crate::renderer::workbench_scroll_page_rows(&app).unwrap();
        assert_eq!(page, 6);
        app.reduce_key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::PageDown,
            crossterm::event::KeyModifiers::NONE,
        ));
        assert_eq!(
            app.router
                .workbench()
                .scroll()
                .get(PhaseSurfaceId::ReviewDetail),
            page as u16
        );
    }
}

pub(crate) fn should_draw_frame(
    needs_redraw: bool,
    priority: RedrawPriority,
    last_draw: Option<Instant>,
    now: Instant,
) -> bool {
    needs_redraw
        && last_draw.is_none_or(|at| now.saturating_duration_since(at) >= priority.frame_interval())
}

/// The recv timeout for the next loop wait: the view-driven cadence, capped
/// by the remaining frame interval when a dirty frame was deferred so the
/// deferred repaint lands on time instead of waiting out the idle timeout.
pub(crate) fn deferred_frame_timeout(
    view_timeout: Duration,
    needs_redraw: bool,
    priority: RedrawPriority,
    last_draw: Option<Instant>,
    now: Instant,
) -> Duration {
    if !needs_redraw {
        return view_timeout;
    }
    let Some(last_draw) = last_draw else {
        return Duration::ZERO;
    };
    let remaining = priority
        .frame_interval()
        .saturating_sub(now.saturating_duration_since(last_draw));
    view_timeout.min(remaining)
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
    startup: ShellStartup,
) -> Result<()> {
    let mut app =
        ShellApp::with_registry_and_transcript(config, target, registry, startup.transcript);
    for diagnostic in &startup.config_diagnostics {
        eprintln!("{diagnostic}"); // terminal-output: plain-mode
    }
    app.log_config_diagnostics(&startup.config_diagnostics);
    if let Some(warning) = startup.transcript_warning {
        app.surface_session_start_warning(warning);
    }
    let armed = app.arm_review_yield_from_config();
    EffectRuntime::execute(&mut app, armed);
    apply_launch_start_view(&mut app);
    let result = run_plain_shell_session(&mut app, stdin, stdin_is_terminal);
    let reason = if result.is_ok() {
        "completed"
    } else {
        "failed"
    };
    app.finish_session_transcript(reason);
    result
}

fn run_plain_shell_session(
    app: &mut ShellApp,
    stdin: &mut io::Stdin,
    stdin_is_terminal: bool,
) -> Result<()> {
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
        print!("{}", plain_launch_summary(app)); // terminal-output: plain-mode
        return Ok(());
    }

    let report = execute_plain_scripted_session(app, &commands, 80);
    print!("{}", report.output); // terminal-output: plain-mode
    if report.outcome.exit_code() != 0 {
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
        "kuzushi scan ."
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
        assert!(output.contains("Next: kuzushi scan ."));
        assert_eq!(output.lines().count(), 5);
        assert!(!output.contains("press "));
        assert!(!output.contains("kuzushi>"));
    }
}
