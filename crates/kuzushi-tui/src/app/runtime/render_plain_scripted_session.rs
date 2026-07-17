use super::*;

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
        crossterm::terminal::SetTitle("Kuzushi"),
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
        crossterm::terminal::SetTitle("Kuzushi"),
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
