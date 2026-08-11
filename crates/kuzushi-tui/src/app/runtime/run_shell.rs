use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellTargetSource {
    ShellFlag,
    GlobalFlag,
    Caller,
    None,
}

impl ShellTargetSource {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ShellFlag => "shell_flag",
            Self::GlobalFlag => "global_flag",
            Self::Caller => "caller",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellLaunchContext {
    pub argv: Vec<String>,
    pub target_source: ShellTargetSource,
    pub session_persistence: bool,
}

impl ShellLaunchContext {
    pub fn caller(has_target: bool) -> Self {
        Self {
            argv: std::env::args().skip(1).collect(),
            target_source: if has_target {
                ShellTargetSource::Caller
            } else {
                ShellTargetSource::None
            },
            session_persistence: true,
        }
    }
}

pub fn run_shell(config: V2Config, target: Option<&WorkspaceTarget>) -> Result<()> {
    run_shell_with_context(
        config,
        target,
        false,
        ModuleRegistry::with_v2_builtins(),
        ShellLaunchContext::caller(target.is_some()),
    )
}

pub fn run_shell_with_plain(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    force_plain: bool,
    registry: ModuleRegistry,
) -> Result<()> {
    run_shell_with_context(
        config,
        target,
        force_plain,
        registry,
        ShellLaunchContext::caller(target.is_some()),
    )
}

pub fn run_shell_with_context(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    force_plain: bool,
    registry: ModuleRegistry,
    launch: ShellLaunchContext,
) -> Result<()> {
    run_shell_with_context_and_config_diagnostics(
        config,
        target,
        force_plain,
        registry,
        launch,
        Vec::new(),
    )
}

/// CLI-aware shell entry point that preserves the stable `ShellLaunchContext`
/// construction contract while handing typed config notices to the selected
/// presentation mode.
pub fn run_shell_with_context_and_config_diagnostics(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    force_plain: bool,
    registry: ModuleRegistry,
    launch: ShellLaunchContext,
    config_diagnostics: Vec<kuzushi_core::ConfigDiagnostic>,
) -> Result<()> {
    let mut stdin = io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    let stdout_is_terminal = io::stdout().is_terminal();
    let plain = should_run_plain_shell(force_plain, stdin_is_terminal, stdout_is_terminal);
    let shell_mode = shell_mode_label(plain, stdin_is_terminal);
    let (transcript, transcript_warning) =
        prepare_session_transcript(&config, target, &launch, shell_mode);
    let startup = ShellStartup {
        transcript,
        transcript_warning,
        config_diagnostics,
    };
    if plain {
        return run_plain_shell(
            config,
            target,
            &mut stdin,
            stdin_is_terminal,
            registry,
            startup,
        );
    }

    run_terminal_shell(config, target, registry, startup)
}

/// The launch-time inputs a constructed `ShellApp` still needs applied.
pub(crate) struct ShellStartup {
    pub(crate) transcript: Option<kuzushi_core::session_transcript::SessionRecorder>,
    pub(crate) transcript_warning: Option<String>,
    pub(crate) config_diagnostics: Vec<kuzushi_core::ConfigDiagnostic>,
}

pub(crate) fn shell_mode_label(plain: bool, stdin_is_terminal: bool) -> &'static str {
    match (plain, stdin_is_terminal) {
        (false, _) => "interactive",
        (true, false) => "scripted",
        (true, true) => "plain",
    }
}

fn prepare_session_transcript(
    config: &V2Config,
    target: Option<&WorkspaceTarget>,
    launch: &ShellLaunchContext,
    shell_mode: &str,
) -> (
    Option<kuzushi_core::session_transcript::SessionRecorder>,
    Option<String>,
) {
    if !launch.session_persistence {
        return (None, None);
    }
    match start_session_transcript(config, target, launch, shell_mode) {
        Ok(recorder) => (Some(recorder), None),
        Err(error) => (
            None,
            Some(format!(
                "durable transcript could not start: {error}; Kuzushi will continue"
            )),
        ),
    }
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
    startup: ShellStartup,
) -> Result<()> {
    let mut app =
        ShellApp::with_registry_and_transcript(config, target, registry, startup.transcript);
    app.log_config_diagnostics(&startup.config_diagnostics);
    if let Some(warning) = startup.transcript_warning {
        app.surface_session_start_warning(warning);
    }
    let armed = app.arm_review_yield_from_config();
    EffectRuntime::execute(&mut app, armed);
    if let Ok((columns, rows)) = crossterm::terminal::size() {
        apply_initial_terminal_size(&mut app, columns, rows);
    }
    apply_launch_onboarding(&mut app);
    let result = TerminalSession::setup()
        .and_then(|mut terminal| terminal_shell_loop(terminal.terminal_mut(), &mut app));
    let reason = if result.is_ok() {
        "completed"
    } else {
        "failed"
    };
    app.finish_session_transcript(reason);
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
        ShellView::PlanningPicker | ShellView::TargetPicker | ShellView::Setup
    ) {
        return;
    }
    // Establish the phase Workbench as the workflow origin (both the
    // interactive shell and the plain front door route through here).
    // Contextual decks open only from explicit navigation or a foreground tool
    // completion, never merely because a persisted artifact exists.
    app.set_shell_view(ShellView::Workbench);
    app.router
        .workbench_mut()
        .set_focus(crate::ui_view_models::PhaseSurfaceId::ReviewQueue);
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
    /// When the last full frame was painted; gates draws to
    /// `MIN_FRAME_INTERVAL` so event floods cannot monopolize the loop.
    pub(crate) last_draw: Option<Instant>,
    pub(crate) last_title: Option<String>,
    /// Attention ids active on the previous broker snapshot. This suppresses
    /// redraw/refocus replays without conflating later approvals that reuse a
    /// stable id after the earlier item was resolved.
    pub(crate) active_attention_ids: std::collections::BTreeSet<String>,
    run_focus_hold: RunFocusVisibilityHold,
}

impl Default for TerminalLoopState {
    fn default() -> Self {
        Self {
            needs_redraw: true,
            last_draw: None,
            last_title: None,
            active_attention_ids: std::collections::BTreeSet::new(),
            run_focus_hold: RunFocusVisibilityHold::default(),
        }
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
    if let Some(input_changed) = state.run_focus_hold.intercept_input(app, input)? {
        state.needs_redraw |= input_changed;
        draw_terminal_if_needed(terminal, app, state)?;
        return Ok(());
    }
    let work_tail_may_remain = refresh_terminal_redraw_state(terminal, app, state, watcher)?;
    rearm_work_tail(wake, work_tail_may_remain);
    let view_before_input = app.shell_view();
    let timeout = deferred_frame_timeout(
        terminal_event_timeout(app),
        state.needs_redraw,
        state.last_draw,
        Instant::now(),
    );
    let input_changed = wait_for_terminal_loop_event_within(app, input, timeout)?;
    state.needs_redraw |= input_changed;
    if input_changed {
        draw_terminal_if_needed(terminal, app, state)?;
        state
            .run_focus_hold
            .begin_after_transition(view_before_input, app);
    }
    Ok(())
}

pub(crate) fn rearm_work_tail(wake: &TerminalLoopWake, tail_may_remain: bool) {
    if tail_may_remain {
        wake.notify();
    }
}
