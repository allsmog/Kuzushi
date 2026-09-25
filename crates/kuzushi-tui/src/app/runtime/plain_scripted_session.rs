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
    pub(crate) outcome: PlainCommandOutcome,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum PlainCommandOutcome {
    #[default]
    NoRunCompleted,
    Rejected,
    RunTerminal {
        run_id: kuzushi_core::run_lifecycle::RunId,
        status: kuzushi_core::run_lifecycle::RunItemStatus,
    },
    Quarantined,
    InvariantFailure,
}

impl PlainCommandOutcome {
    pub(crate) const fn exit_code(&self) -> i32 {
        use kuzushi_core::run_lifecycle::RunItemStatus;
        match self {
            Self::NoRunCompleted
            | Self::RunTerminal {
                status: RunItemStatus::Completed | RunItemStatus::Skipped,
                ..
            } => 0,
            Self::Rejected
            | Self::RunTerminal { .. }
            | Self::Quarantined
            | Self::InvariantFailure => 1,
        }
    }

    fn merge(self, next: Self) -> Self {
        if self.exit_code() != 0 {
            return self;
        }
        if next.exit_code() != 0 {
            return next;
        }
        match next {
            Self::NoRunCompleted => self,
            successful_run => successful_run,
        }
    }
}

pub(crate) fn execute_plain_scripted_session(
    app: &mut ShellApp,
    commands: &[&str],
    width: usize,
) -> PlainSessionReport {
    let mut output = String::new();
    let mut outcome = PlainCommandOutcome::NoRunCompleted;
    for (index, command) in commands.iter().enumerate() {
        if index > 0 {
            output.push('\n');
        }
        let log_start = app.log_len();
        let terminal_before = plain_terminal_snapshot(app);
        let submission = submit_plain_scripted_command(app, command, terminal_before.as_ref());
        let work = wait_for_plain_work(app);
        app.hydrate_active_view_blocking();
        let command_outcome =
            plain_command_outcome(app, terminal_before.as_ref(), submission, work);
        outcome = outcome.merge(command_outcome);
        output.push_str(&render_plain_command_result(app, width, command, log_start));
        if app.should_quit() || work == PlainWorkOutcome::Quarantined {
            break;
        }
    }
    PlainSessionReport { output, outcome }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PlainTerminalSnapshot {
    run_id: kuzushi_core::run_lifecycle::RunId,
    item_id: kuzushi_core::run_lifecycle::RunItemId,
    status: kuzushi_core::run_lifecycle::RunItemStatus,
    health: kuzushi_core::run_lifecycle::RunLifecycleHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlainWorkOutcome {
    Completed,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlainSubmission {
    NoRunExpected,
    Rejected,
    RunExpected,
}

fn plain_command_outcome(
    app: &ShellApp,
    terminal_before: Option<&PlainTerminalSnapshot>,
    submission: PlainSubmission,
    work: PlainWorkOutcome,
) -> PlainCommandOutcome {
    if work == PlainWorkOutcome::Quarantined {
        return PlainCommandOutcome::Quarantined;
    }
    match submission {
        PlainSubmission::Rejected => PlainCommandOutcome::Rejected,
        PlainSubmission::NoRunExpected => PlainCommandOutcome::NoRunCompleted,
        PlainSubmission::RunExpected => fresh_plain_terminal_outcome(app, terminal_before)
            .unwrap_or(PlainCommandOutcome::InvariantFailure),
    }
}

fn fresh_plain_terminal_outcome(
    app: &ShellApp,
    before: Option<&PlainTerminalSnapshot>,
) -> Option<PlainCommandOutcome> {
    let current = plain_terminal_snapshot(app)?;
    terminal_is_fresh(&current, before).then(|| plain_terminal_outcome(current))
}

fn terminal_is_fresh(
    current: &PlainTerminalSnapshot,
    before: Option<&PlainTerminalSnapshot>,
) -> bool {
    before.is_none_or(|before| current.run_id != before.run_id || current.item_id != before.item_id)
}

fn plain_terminal_outcome(snapshot: PlainTerminalSnapshot) -> PlainCommandOutcome {
    if !snapshot.status.is_terminal() || !terminal_health_is_reliable(&snapshot.health) {
        return PlainCommandOutcome::InvariantFailure;
    }
    PlainCommandOutcome::RunTerminal {
        run_id: snapshot.run_id,
        status: snapshot.status,
    }
}

fn terminal_health_is_reliable(health: &kuzushi_core::run_lifecycle::RunLifecycleHealth) -> bool {
    use kuzushi_core::run_lifecycle::{ProjectionHealth, RunDeliveryHealth, RunDurabilityHealth};
    matches!(health.integrity, ProjectionHealth::Healthy)
        && matches!(health.durability, RunDurabilityHealth::Durable { .. })
        && matches!(health.delivery, RunDeliveryHealth::Current { .. })
}

fn plain_terminal_snapshot(app: &ShellApp) -> Option<PlainTerminalSnapshot> {
    let activity = app.activity()?;
    if let Some(terminal) = activity.run_projection.terminal.as_ref() {
        return Some(PlainTerminalSnapshot {
            run_id: kuzushi_core::run_lifecycle::RunId::parse(&activity.run_id).ok()?,
            item_id: terminal.item_id,
            status: terminal.status,
            health: activity.effective_run_lifecycle_health(),
        });
    }
    typed_terminal_snapshot_from_disk(app.target()?, &activity.run_id)
}

fn typed_terminal_snapshot_from_disk(
    target: &std::path::Path,
    run_id: &str,
) -> Option<PlainTerminalSnapshot> {
    let read = kuzushi_core::run_lifecycle::load_run_projection(target, run_id).ok()?;
    if read.source != kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1 {
        return None;
    }
    let health = read.projection.lifecycle_health();
    let terminal = read.projection.terminal?;
    Some(PlainTerminalSnapshot {
        run_id: kuzushi_core::run_lifecycle::RunId::parse(run_id).ok()?,
        item_id: terminal.item_id,
        status: terminal.status,
        health,
    })
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

fn submit_plain_scripted_command(
    app: &mut ShellApp,
    command: &str,
    terminal_before: Option<&PlainTerminalSnapshot>,
) -> PlainSubmission {
    if let Some(workflow) = plain_interactive_workflow(app, command) {
        return reject_plain_workflow_command(app, &workflow);
    }
    let submission = submit_plain_line(app, command);
    classify_plain_submission(app, terminal_before, submission)
}

/// Queue commands are reparsed by the reducer, so inspect their payloads here
/// too. Otherwise `queue scan` would bypass the plain-mode boundary and open an
/// interactive picker while reporting a successful scripted command. A phase
/// verb for a completed or passed phase opens its durable page, which plain
/// output renders, so only planner-bound phase verbs are rejected.
fn plain_interactive_workflow(app: &ShellApp, command: &str) -> Option<String> {
    let mut pending = command.trim().to_string();
    loop {
        match crate::commands::parse_command(&pending) {
            ShellCommand::Phase(phase) if app.phase_verb_opens_page(phase) => return None,
            ShellCommand::Phase(phase) | ShellCommand::PhasePlanner(phase) => {
                return Some(phase.word().to_string())
            }
            ShellCommand::Full(_) | ShellCommand::Scan(_) => {
                return Some(command_head(&pending).to_string())
            }
            ShellCommand::QueueCommand(queued) => pending = queued,
            ShellCommand::Unknown(_) if is_legacy_scan_with_target(&pending) => {
                return Some("scan".to_string())
            }
            _ => return None,
        }
    }
}

fn command_head(command: &str) -> &str {
    command
        .trim()
        .strip_prefix('/')
        .unwrap_or(command.trim())
        .split_whitespace()
        .next()
        .unwrap_or("workflow")
}

fn is_legacy_scan_with_target(command: &str) -> bool {
    let normalized = command.trim().strip_prefix('/').unwrap_or(command.trim());
    let mut parts = normalized.split_whitespace();
    parts.next() == Some("scan") && parts.next().is_some()
}

fn reject_plain_workflow_command(app: &mut ShellApp, command: &str) -> PlainSubmission {
    app.log(
        "error",
        format!(
            "`{command}` is an interactive TUI workflow; for scripts use `kuzushi scan <target>` or `kuzushi --target <target> run sast:scan`"
        ),
    );
    PlainSubmission::Rejected
}

fn classify_plain_submission(
    app: &ShellApp,
    terminal_before: Option<&PlainTerminalSnapshot>,
    submission: PlainSubmission,
) -> PlainSubmission {
    let fresh_terminal = plain_terminal_snapshot(app)
        .as_ref()
        .is_some_and(|current| terminal_is_fresh(current, terminal_before));
    if app.has_running_work() || fresh_terminal {
        PlainSubmission::RunExpected
    } else {
        submission
    }
}

fn submit_plain_line(app: &mut ShellApp, command: &str) -> PlainSubmission {
    let update = app.reduce_submitted_line(command);
    let expects_run = update.effects.iter().any(plain_effect_expects_run);
    let submission = if update.rejected {
        PlainSubmission::Rejected
    } else if expects_run {
        PlainSubmission::RunExpected
    } else {
        PlainSubmission::NoRunExpected
    };
    EffectRuntime::execute(app, update.effects);
    submission
}

fn plain_effect_expects_run(effect: &ShellEffect) -> bool {
    matches!(
        effect,
        ShellEffect::AdvancePrereqChain(_)
            | ShellEffect::DispatchAgent(_)
            | ShellEffect::DispatchNextPlanningTask(_)
            | ShellEffect::PrepareRunTool(_)
            | ShellEffect::DispatchRunTool(_)
            | ShellEffect::FireNextApprovedStrategy(_)
            | ShellEffect::StartOfflineDemoFixtureScan
            | ShellEffect::StartPlanner(_)
            | ShellEffect::PrepareScan(_)
            | ShellEffect::StartScan(_)
            | ShellEffect::StartThreat(_)
    )
}

#[cfg(test)]
#[path = "plain_scripted_session/tests.rs"]
mod tests;
