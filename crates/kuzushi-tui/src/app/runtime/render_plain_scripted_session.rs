use super::*;

#[cfg(test)]
pub(crate) fn render_plain_scripted_session(
    app: &mut ShellApp,
    commands: &[&str],
    width: usize,
) -> String {
    execute_plain_scripted_session(app, commands, width).output
}

pub(crate) struct PlainSessionReport {
    pub(crate) output: String,
    pub(crate) failed: bool,
}

pub(crate) fn execute_plain_scripted_session(
    app: &mut ShellApp,
    commands: &[&str],
    width: usize,
) -> PlainSessionReport {
    let mut output = String::new();
    let mut failed = false;
    for (index, command) in commands.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let log_start = app.log_len();
        submit_plain_scripted_command(app, command);
        let work = wait_for_plain_work(app);
        app.hydrate_active_view_blocking();
        failed |= plain_command_failed(app, log_start);
        output.push_str(&render_plain_command_result(app, width, command, log_start));
        if app.should_quit() || work == PlainWorkOutcome::Quarantined {
            break;
        }
    }
    PlainSessionReport { output, failed }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlainWorkOutcome {
    Completed,
    Quarantined,
}

fn wait_for_plain_work(app: &mut ShellApp) -> PlainWorkOutcome {
    app_background_changed(app, None);
    while app.has_running_work() {
        if app.jobs().has_quarantined_slot() {
            app.log(
                "error",
                "plain session stopped: worker remained unresponsive after watchdog grace and was quarantined",
            );
            return PlainWorkOutcome::Quarantined;
        }
        std::thread::sleep(Duration::from_millis(10));
        app_background_changed(app, None);
    }
    app_background_changed(app, None);
    PlainWorkOutcome::Completed
}

fn plain_command_failed(app: &ShellApp, log_start: usize) -> bool {
    app.log_lines().iter().skip(log_start).any(|line| {
        line.prefix == "error"
            || (line.prefix == "result"
                && matches!(
                    line.body.split_whitespace().next(),
                    Some("fail" | "failed" | "partial" | "canceled" | "interrupted")
                ))
    })
}

fn submit_plain_scripted_command(app: &mut ShellApp, command: &str) {
    match crate::commands::parse_command(command) {
        ShellCommand::Scan(None) if app.target().is_none() => app.log(
            "error",
            "scripted scan needs an explicit target; use `scan .` to consent to cwd",
        ),
        ShellCommand::Scan(target) => {
            update_and_execute_effects(app, Msg::Cmd(ShellCommand::ScriptedScan(target)));
        }
        _ => {
            submit_plain_line(app, command);
        }
    }
}

fn submit_plain_line(app: &mut ShellApp, command: &str) {
    let update = app.reduce_submitted_line(command);
    EffectRuntime::execute(app, update.effects);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_scan_starts_worker_instead_of_opening_picker() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);

        submit_plain_scripted_command(&mut app, &format!("scan {}", temp.path().display()));

        assert!(app.scan().is_some_and(|scan| scan.running));
        assert_eq!(app.shell_view(), ShellView::Activity);
        assert_ne!(app.shell_view(), ShellView::PlanningPicker);
    }

    #[test]
    fn targetless_scripted_scan_is_a_failed_plain_outcome() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let report = execute_plain_scripted_session(&mut app, &["scan"], 80);

        assert!(report.failed);
        assert!(
            report.output.contains("explicit target"),
            "{}",
            report.output
        );
        assert!(!app.has_running_work());
    }

    #[test]
    fn plain_commands_bypass_modal_onboarding_without_selecting_a_model() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        assert_eq!(app.shell_view(), ShellView::ModelPicker);

        let report = execute_plain_scripted_session(&mut app, &["findings"], 80);

        assert_eq!(app.config().model, None);
        assert_eq!(app.shell_view(), ShellView::Workbench);
        assert!(report.output.contains("findings"), "{}", report.output);
    }

    #[test]
    fn partial_result_marks_plain_session_failed_but_skipped_does_not() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let partial_start = app.log_len();
        app.log("result", "partial (scan incomplete) exit_hint=1");
        assert!(plain_command_failed(&app, partial_start));

        let skipped_start = app.log_len();
        app.log("result", "skipped (scan did not run) exit_hint=0");
        assert!(!plain_command_failed(&app, skipped_start));
    }

    #[test]
    fn quarantined_worker_fails_plain_session_without_waiting_for_thread_exit() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let ticket = app.jobs_mut().start(JobKind::Run, "hung:tool");
        let generation = ticket.generation();
        let now = std::time::Instant::now();
        app.jobs_mut()
            .schedule_unresponsive_escalation(JobKind::Run, generation, now);
        assert!(app
            .jobs_mut()
            .quarantine_unresponsive_slots(now + WORKER_UNRESPONSIVE_GRACE));

        let report = execute_plain_scripted_session(&mut app, &["help"], 80);

        assert!(report.failed);
        assert!(report.output.contains("worker remained unresponsive"));
        assert!(app.jobs().is_quarantined(JobKind::Run));
        app.jobs_mut().finish(JobKind::Run);
        ticket.complete();
    }

    #[test]
    fn scripted_replay_hydrates_artifacts_before_plain_rendering() {
        let temp = tempfile::tempdir().unwrap();
        let run_id = "run-plain-replay";
        let summary = kuzushi_core::RunSummary::running(
            run_id,
            "tool",
            None,
            temp.path().display().to_string(),
        )
        .complete();
        kuzushi_core::write_run_summary(temp.path(), &summary).unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));

        let report = execute_plain_scripted_session(&mut app, &[&format!("replay {run_id}")], 180);

        assert!(report.output.contains("run.json"), "{}", report.output);
        assert!(
            !report.output.contains("loading artifact"),
            "{}",
            report.output
        );
    }
}

pub(crate) fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    let stdout = setup_terminal_stdout()?;
    Terminal::new(CrosstermBackend::new(stdout)).map_err(|error| {
        rollback_terminal_mode();
        anyhow::Error::new(error).context("Could not initialize terminal")
    })
}

pub(crate) struct TerminalSession {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    pub(crate) fn setup() -> Result<Self> {
        setup_terminal().map(|terminal| Self { terminal })
    }

    pub(crate) fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        &mut self.terminal
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        let _ = restore_terminal(&mut self.terminal);
    }
}

pub(crate) fn setup_terminal_stdout() -> Result<Stdout> {
    let mut stdout = raw_terminal_stdout()?;
    if let Err(error) = enable_mouse_capture_if_configured(&mut stdout) {
        rollback_terminal_mode();
        return Err(error);
    }
    Ok(stdout)
}

fn raw_terminal_stdout() -> Result<Stdout> {
    enable_raw_mode().context("Could not enable raw mode")?;
    // Enter the alternate screen so the shell owns a dedicated full-screen
    // buffer: the terminal has no scrollback to drift through, the view stays
    // locked in place, and rendered frames don't pile into the user's history.
    if let Err(error) = execute!(io::stdout(), EnterAlternateScreen) {
        rollback_terminal_mode();
        return Err(error).context("Could not enter alternate screen");
    }
    reset_terminal_viewport().inspect_err(|_| rollback_terminal_mode())
}

fn rollback_terminal_mode() {
    let _ = execute!(
        io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen
    );
    let _ = disable_raw_mode();
}

pub(crate) fn reset_terminal_viewport() -> Result<Stdout> {
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

pub(crate) fn enable_mouse_capture_if_configured(stdout: &mut Stdout) -> Result<()> {
    if mouse_capture_enabled() {
        execute!(stdout, EnableMouseCapture).context("Could not enable mouse capture")?;
    }
    Ok(())
}

pub(crate) fn mouse_capture_enabled() -> bool {
    let value = env::var("KUZUSHI_MOUSE_CAPTURE").ok();
    mouse_capture_setting_enabled(value.as_deref())
}

pub(crate) fn mouse_capture_setting_enabled(value: Option<&str>) -> bool {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };

    value == "1"
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
}

pub(crate) fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    let escape_result = execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen
    );
    let raw_result = disable_raw_mode();
    let cursor_result = terminal.show_cursor();
    let mut failures = Vec::new();
    record_terminal_failure(
        &mut failures,
        escape_result,
        "could not leave terminal screen",
    );
    record_terminal_failure(&mut failures, raw_result, "could not disable raw mode");
    record_terminal_failure(
        &mut failures,
        cursor_result,
        "could not show terminal cursor",
    );
    terminal_restore_result(failures)
}

fn record_terminal_failure(failures: &mut Vec<String>, result: std::io::Result<()>, context: &str) {
    if let Err(error) = result {
        failures.push(format!("{context}: {error}"));
    }
}

fn terminal_restore_result(failures: Vec<String>) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(failures.join("; "))
    }
}
