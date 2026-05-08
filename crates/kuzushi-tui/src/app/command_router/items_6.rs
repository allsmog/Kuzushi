use super::prelude::*;
use super::*;

pub(crate) fn handle_workspace_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Workspace(workspace_command) = command else {
        return false;
    };
    app.handle_workspace_command(workspace_command.clone());
    true
}

pub(crate) fn handle_knowledge_base_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::KnowledgeBase(module) = command else {
        return false;
    };
    app.show_kb(module.clone());
    true
}

pub(crate) fn handle_attach_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Attach(source) = command else {
        return false;
    };
    app.attach_kb_source(source);
    true
}

pub(crate) fn handle_detach_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Detach(id) = command else {
        return false;
    };
    app.detach_kb_source(id);
    true
}

pub(crate) fn handle_reparse_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Reparse(id) = command else {
        return false;
    };
    app.reparse_kb_source(id);
    true
}

pub(crate) fn handle_history_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::History = command else {
        return false;
    };
    app.show_history();
    true
}

pub(crate) fn handle_clear_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Clear = command else {
        return false;
    };
    app.clear_conversation();
    true
}

pub(crate) fn handle_load_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Load(specifier) = command else {
        return false;
    };
    app.handle_load_command(specifier.clone());
    true
}

pub(crate) fn handle_resume_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Resume(run_id) = command else {
        return false;
    };
    app.handle_resume_command(run_id.clone());
    true
}

pub(crate) fn handle_pause_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Pause = command else {
        return false;
    };
    app.handle_pause_command();
    true
}

pub(crate) fn handle_story_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Story = command else {
        return false;
    };
    app.show_story();
    true
}

pub(crate) fn handle_run_tool_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::RunTool { tool, input } = command else {
        return false;
    };
    app.run_tool(tool.clone(), input.clone());
    true
}

pub(crate) fn handle_quit_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Quit = command else {
        return false;
    };
    app.request_exit();
    true
}

pub(crate) fn handle_empty_command(_app: &mut ShellApp, command: &ShellCommand) -> bool {
    matches!(command, ShellCommand::Empty)
}

pub(crate) fn handle_unknown_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Unknown(raw) = command else {
        return false;
    };
    app.log("error", unknown_command_message(raw));
    true
}
