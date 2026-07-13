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
    let mut app = ShellApp::with_registry(config, target, registry);
    if let Ok((columns, rows)) = crossterm::terminal::size() {
        apply_initial_terminal_size(&mut app, columns, rows);
    }
    apply_launch_onboarding(&mut app);
    let mut terminal = TerminalSession::setup()?;
    terminal_shell_loop(terminal.terminal_mut(), &mut app)
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

/// Single interactive-launch onboarding entry point. Construction already ran
/// `apply_initial_onboarding_phase` (opening the model/auth/planning picker
/// when a `--target` was given), so the only additional front-door decision
/// is whether to open the launch-time target picker. The ordered gate lives
/// in the pure `initial_onboarding_phase` fn: only a bare interactive launch
/// (no `--target`, no skip-env) yields `TargetPicker`; every other phase was
/// already applied at construction and is preserved by `open_start_view`.
/// Nothing silently falls back to cwd — the operator picks a target or
/// explicitly defers with Esc.
pub(crate) fn apply_launch_onboarding(app: &mut ShellApp) {
    match app.launch_onboarding_phase() {
        InitialOnboardingPhase::TargetPicker => {
            apply_launch_target_picker(app);
        }
        _ => {
            apply_launch_start_view(app);
        }
    }
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
    let mut watcher = WorkspaceWatcherRuntime::start(app.target(), wake.clone())?;
    while !app.should_quit() {
        reconcile_workspace_watcher(&mut watcher, app.target(), wake.clone())?;
        terminal_shell_step(terminal, app, &mut state, &input, &wake, watcher.as_mut())?;
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
    wake: &TerminalLoopWake,
    watcher: Option<&mut WorkspaceWatcherRuntime>,
) -> Result<()> {
    let work_tail_may_remain = refresh_terminal_redraw_state(terminal, app, state, watcher)?;
    rearm_work_tail(wake, work_tail_may_remain);
    state.needs_redraw |= wait_for_terminal_loop_event(app, input)?;
    Ok(())
}

pub(crate) fn rearm_work_tail(wake: &TerminalLoopWake, tail_may_remain: bool) {
    if tail_may_remain {
        wake.notify();
    }
}
