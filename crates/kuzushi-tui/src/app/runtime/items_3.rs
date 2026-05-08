use super::prelude::*;
use super::*;

pub(crate) fn render_plain_scripted_session(
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

pub(crate) fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    let stdout = setup_terminal_stdout()?;
    Terminal::new(CrosstermBackend::new(stdout)).context("Could not initialize terminal")
}

pub(crate) fn setup_terminal_stdout() -> Result<Stdout> {
    enable_raw_mode().context("Could not enable raw mode")?;
    let mut stdout = reset_terminal_viewport()?;
    enable_mouse_capture_if_configured(&mut stdout)?;
    Ok(stdout)
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
