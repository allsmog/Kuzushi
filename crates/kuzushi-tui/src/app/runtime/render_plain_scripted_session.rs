use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

/// True while raw mode + alternate screen are engaged. The panic hook swaps
/// it off so exactly one restore runs, and normal teardown clears it so a
/// later panic doesn't emit stray escape sequences into a sane terminal.
static TERMINAL_GUARD_ACTIVE: AtomicBool = AtomicBool::new(false);
static TERMINAL_PANIC_HOOK: Once = Once::new();

pub(crate) fn mark_terminal_guard_active() {
    TERMINAL_GUARD_ACTIVE.store(true, Ordering::SeqCst);
}

pub(crate) fn take_terminal_guard() -> bool {
    TERMINAL_GUARD_ACTIVE.swap(false, Ordering::SeqCst)
}

pub(crate) fn terminal_guard_active() -> bool {
    TERMINAL_GUARD_ACTIVE.load(Ordering::SeqCst)
}

/// Temporarily returns the real terminal to an interactive child. Resuming
/// re-enters Kuzushi's alternate screen; the caller then requests a complete
/// Ratatui redraw so no child-controlled cells survive.
pub(crate) struct ExternalTerminalSuspension {
    active: bool,
}

impl ExternalTerminalSuspension {
    pub(crate) fn begin() -> Result<Self> {
        if !terminal_guard_active() {
            return Ok(Self { active: false });
        }
        leave_terminal_for_external_process()?;
        take_terminal_guard();
        Ok(Self { active: true })
    }

    pub(crate) fn resume(mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        setup_terminal_stdout()?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ExternalTerminalSuspension {
    fn drop(&mut self) {
        if self.active && setup_terminal_stdout().is_ok() {
            self.active = false;
        }
    }
}

/// Without this hook a panic prints its message into the alternate screen
/// while raw mode is still active: the terminal is wiped on unwind and the
/// operator never sees why Kuzushi died. Restore the terminal FIRST, then
/// chain to the previous hook so the message lands on the normal screen.
pub(crate) fn install_terminal_panic_hook() {
    TERMINAL_PANIC_HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if take_terminal_guard() {
                rollback_terminal_mode();
            }
            previous(info);
        }));
    });
}

pub(crate) fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    install_terminal_panic_hook();
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
    // Arm the panic guard the moment raw mode engages: every later setup
    // failure or panic must put the operator's terminal back.
    mark_terminal_guard_active();
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
    take_terminal_guard();
    // `cursor::Show` covers the panic-hook path, which has no Terminal
    // handle to call `show_cursor()` on.
    let _ = execute!(
        io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste,
        crossterm::terminal::SetTitle("Kuzushi"),
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
    let _ = disable_raw_mode();
}

fn leave_terminal_for_external_process() -> Result<()> {
    execute!(
        io::stdout(),
        DisableMouseCapture,
        DisableBracketedPaste,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    )
    .context("Could not suspend Kuzushi's terminal screen")?;
    if let Err(error) = disable_raw_mode() {
        take_terminal_guard();
        let _ = setup_terminal_stdout();
        return Err(error).context("Could not disable raw mode for external process");
    }
    Ok(())
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
    take_terminal_guard();
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
