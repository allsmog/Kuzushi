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
    if let Ok((columns, rows)) = crossterm::terminal::size() {
        apply_initial_terminal_size(&mut app, columns, rows);
    }
    apply_launch_start_view(&mut app);
    // Bare interactive launch (no --target): open the target picker so the
    // front door lands in the same guided journey as `shell --target .`.
    // Done here (not in construction) so headless/test apps keep their
    // targetless default, and the explicit-target rule stays intact — the
    // operator picks, nothing silently falls back to cwd.
    if app.target().is_none() && !crate::app::skip_onboarding_env() {
        apply_launch_target_picker(&mut app);
    }
    let result = terminal_shell_loop(&mut terminal, &mut app);
    let _ = restore_terminal(&mut terminal);
    result
}

pub(crate) fn apply_initial_terminal_size(app: &mut ShellApp, columns: u16, rows: u16) -> bool {
    update_and_execute_effects(app, Msg::Term(TermEvent::Resize { columns, rows }))
}

pub(crate) fn apply_launch_start_view(app: &mut ShellApp) -> bool {
    update_and_execute_effects(app, Msg::Cmd(ShellCommand::LaunchStartView))
}

pub(crate) fn apply_launch_target_picker(app: &mut ShellApp) -> bool {
    update_and_execute_effects(app, Msg::Cmd(ShellCommand::LaunchTargetPicker))
}

pub(crate) fn open_start_view(app: &mut ShellApp) {
    // Preserve the onboarding picker chosen by
    // `apply_initial_onboarding_phase` — otherwise the first-run flow
    // would be clobbered the moment the terminal shell loop boots.
    if matches!(
        app.shell_view(),
        ShellView::ModelPicker
            | ShellView::AuthMethodPicker
            | ShellView::PlanningPicker
            | ShellView::TargetPicker
    ) {
        return;
    }
    // The Workbench command center is the default landing surface (both the
    // interactive shell and the plain front door route through here). The
    // onboarding/target/model pickers above still take precedence — nothing
    // here clobbers a first-run gate.
    app.set_shell_view(ShellView::Workbench);
    let center_mode = app.default_workbench_center_mode(WorkbenchPane::Findings);
    app.router
        .workbench_mut()
        .set_focus(WorkbenchPane::Findings);
    app.router.workbench_mut().set_center_mode(center_mode);
}

pub(crate) fn terminal_shell_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut ShellApp,
) -> Result<()> {
    let mut state = TerminalLoopState::default();
    let (input, wake) = TerminalLoopInbox::spawn_crossterm_reader();
    app.set_loop_wake(Some(wake.clone()));
    app.jobs_mut().set_wake(Some(wake.clone()));
    let mut watcher = WorkspaceWatcherRuntime::start(app.target(), wake)?;
    while !app.should_quit() {
        terminal_shell_step(terminal, app, &mut state, &input, watcher.as_mut())?;
    }
    app.jobs_mut().set_wake(None);
    app.set_loop_wake(None);
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
    input: &TerminalLoopInbox,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> Result<()> {
    refresh_terminal_redraw_state(terminal, app, state, watcher)?;
    state.needs_redraw |= wait_for_terminal_loop_event(app, input)?;
    Ok(())
}
