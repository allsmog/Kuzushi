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
        let log_start = app.log_len();
        submit_plain_scripted_command(app, command);
        app_background_changed(app, None);
        output.push_str(&render_plain_command_result(app, width, command, log_start));
        if app.should_quit() {
            break;
        }
    }
    output
}

fn submit_plain_scripted_command(app: &mut ShellApp, command: &str) {
    match crate::commands::parse_command(command) {
        ShellCommand::Scan(target) => {
            update_and_execute_effects(app, Msg::Cmd(ShellCommand::ScriptedScan(target)));
        }
        _ => {
            submit_plain_line(app, command);
        }
    }
}

fn submit_plain_line(app: &mut ShellApp, command: &str) {
    app.set_input(command);
    update_and_execute_effects(
        app,
        Msg::Term(TermEvent::Key(crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Enter,
            crossterm::event::KeyModifiers::empty(),
        ))),
    );
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
}

pub(crate) fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    let stdout = setup_terminal_stdout()?;
    Terminal::new(CrosstermBackend::new(stdout)).context("Could not initialize terminal")
}

pub(crate) fn setup_terminal_stdout() -> Result<Stdout> {
    let mut stdout = raw_terminal_stdout()?;
    enable_mouse_capture_if_configured(&mut stdout)?;
    Ok(stdout)
}

fn raw_terminal_stdout() -> Result<Stdout> {
    enable_raw_mode().context("Could not enable raw mode")?;
    // Enter the alternate screen so the shell owns a dedicated full-screen
    // buffer: the terminal has no scrollback to drift through, the view stays
    // locked in place, and rendered frames don't pile into the user's history.
    execute!(io::stdout(), EnterAlternateScreen).context("Could not enter alternate screen")?;
    reset_terminal_viewport()
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
        DisableBracketedPaste,
        LeaveAlternateScreen
    );
    disable_raw_mode().context("Could not disable raw mode")?;
    terminal
        .show_cursor()
        .context("Could not show terminal cursor")
}
