use super::*;

pub fn run_shell(config: V2Config, target: Option<&WorkspaceTarget>) -> Result<()> {
    run_shell_with_plain(config, target, false, ModuleRegistry::with_v2_builtins())
}

pub fn run_shell_with_plain(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    force_plain: bool,
    registry: ModuleRegistry,
) -> Result<()> {
    let mut stdin = io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    let stdout_is_terminal = io::stdout().is_terminal();
    if should_run_plain_shell(force_plain, stdin_is_terminal, stdout_is_terminal) {
        return run_plain_shell(config, target, &mut stdin, stdin_is_terminal, registry);
    }

    run_terminal_shell(config, target, registry)
}

pub(crate) fn should_run_plain_shell(
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

pub(crate) fn should_run_plain_shell_for_io(
    force_plain: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    env_requested: bool,
) -> bool {
    force_plain || !stdin_is_terminal || !stdout_is_terminal || env_requested
}

pub(crate) fn plain_shell_env_requested() -> bool {
    env::var_os("KUZUSHI_PLAIN").is_some()
        || env::var_os("KUZUSHI_SCREEN_READER").is_some()
        || env::var_os("KUZUSHI_LOW_BANDWIDTH").is_some()
}

pub(crate) fn run_terminal_shell(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    registry: ModuleRegistry,
) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = ShellApp::with_registry(config, target, registry);
    open_start_view(&mut app);
    // Bare interactive launch (no --target): open the target picker so the
    // front door lands in the same guided journey as `shell --target .`.
    // Done here (not in construction) so headless/test apps keep their
    // targetless default, and the explicit-target rule stays intact — the
    // operator picks, nothing silently falls back to cwd.
    if app.target.is_none() && !crate::app::skip_onboarding_env() {
        app.open_target_picker();
    }
    let result = terminal_shell_loop(&mut terminal, &mut app);
    let _ = restore_terminal(&mut terminal);
    result
}

pub(crate) fn open_start_view(app: &mut ShellApp) {
    // Preserve the onboarding picker chosen by
    // `apply_initial_onboarding_phase` — otherwise the first-run flow
    // would be clobbered the moment the terminal shell loop boots.
    if matches!(
        app.shell_view,
        ShellView::ModelPicker
            | ShellView::AuthMethodPicker(_)
            | ShellView::PlanningPicker
            | ShellView::TargetPicker
    ) {
        return;
    }
    // The Workbench command center is the default landing surface (both the
    // interactive shell and the plain front door route through here). The
    // onboarding/target/model pickers above still take precedence — nothing
    // here clobbers a first-run gate.
    app.shell_view = ShellView::Workbench;
    app.workbench_focus = WorkbenchPane::Findings;
    app.workbench_center_mode = app.default_workbench_center_mode(WorkbenchPane::Findings);
}

pub(crate) fn terminal_shell_loop(
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
pub(crate) struct TerminalLoopState {
    pub(crate) needs_redraw: bool,
}

impl Default for TerminalLoopState {
    fn default() -> Self {
        Self { needs_redraw: true }
    }
}

pub(crate) fn terminal_shell_step(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
    state: &mut TerminalLoopState,
) -> Result<()> {
    refresh_terminal_redraw_state(terminal, app, state)?;
    state.needs_redraw |= poll_terminal_event(app)?;
    Ok(())
}
