use super::*;

pub(crate) fn handle_trace_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Trace(run_id) = command else {
        return false;
    };
    app.shell_view = ShellView::Trace(run_id.clone());
    app.log("trace", run_id);
    true
}

pub(crate) fn handle_activity_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Activity = command else {
        return false;
    };
    if app.activity.is_none() {
        let run_id = app
            .tool_run_id
            .clone()
            .or_else(|| app.scan.as_ref().and_then(|scan| scan.run_id.clone()))
            .unwrap_or_else(|| {
                format!(
                    "manual-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                )
            });
        let mut session = ActivitySession::new(run_id);
        // Seed with all DAG-participating tasks so manual `/activity`
        // openers see the same Queued layout the scan-mode auto-open
        // produces.
        session.seed_from_registry(&app.registry);
        app.activity = Some(session);
    }
    app.shell_view = ShellView::Activity;
    app.log("activity", "live module-progress dashboard");
    true
}

pub(crate) fn handle_plan_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Plan(goal) = command else {
        return false;
    };
    app.start_planner(goal);
    true
}

pub(crate) fn handle_plan_apply_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::PlanApply = command else {
        return false;
    };
    app.apply_pending_plan();
    true
}

pub(crate) fn handle_plan_discard_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::PlanDiscard = command else {
        return false;
    };
    app.discard_pending_plan();
    true
}

pub(crate) fn handle_quickstart_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Quickstart = command else {
        return false;
    };
    app.show_quickstart();
    true
}

pub(crate) fn handle_target_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Target(path) = command else {
        return false;
    };
    app.handle_target_command(path.as_deref());
    true
}

pub(crate) fn handle_ask_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Ask(question) = command else {
        return false;
    };
    app.ask_agent(question);
    true
}

pub(crate) fn handle_options_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Options { tool, filter } = command else {
        return false;
    };
    app.show_options(tool.clone(), *filter);
    true
}

pub(crate) fn handle_set_option_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::SetOption {
        global,
        name,
        value,
    } = command
    else {
        return false;
    };
    app.set_option(*global, name, value);
    true
}

pub(crate) fn handle_unset_option_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::UnsetOption { global, name } = command else {
        return false;
    };
    app.unset_option(*global, name);
    true
}

pub(crate) fn handle_tasks_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tasks = command else {
        return false;
    };
    app.show_sast_tasks();
    true
}

pub(crate) fn handle_task_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Task(task_command) = command else {
        return false;
    };
    app.handle_sast_task_command(task_command.clone());
    true
}

pub(crate) fn handle_context_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Context(context_command) = command else {
        return false;
    };
    app.handle_context_command(context_command.clone());
    true
}
