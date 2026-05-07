use crate::commands::{parse_command, shell_command_specs, shell_help_examples, ShellCommand};

use super::threats::threat_view_label;
use super::{runtime_backend_label, ShellApp, ShellView};

type CommandHandler = fn(&mut ShellApp, &ShellCommand) -> bool;

const COMMAND_HANDLERS: &[CommandHandler] = &[
    handle_help_command,
    handle_back_command,
    handle_modules_command,
    handle_tools_command,
    handle_findings_command,
    handle_open_command,
    handle_scan_command,
    handle_model_command,
    handle_auth_command,
    handle_auth_login_command,
    handle_provider_command,
    handle_backend_command,
    handle_cost_command,
    handle_config_command,
    handle_use_command,
    handle_tune_command,
    handle_threat_command,
    handle_threat_regen_command,
    handle_threat_ask_command,
    handle_threat_apply_command,
    handle_threat_reject_command,
    handle_threat_editor_command,
    handle_prompts_command,
    handle_prompt_command,
    handle_actor_command,
    handle_show_runs_command,
    handle_show_aliases_command,
    handle_since_command,
    handle_replay_command,
    handle_trace_command,
    handle_plan_command,
    handle_plan_apply_command,
    handle_plan_discard_command,
    handle_quickstart_command,
    handle_target_command,
    handle_ask_command,
    handle_options_command,
    handle_set_option_command,
    handle_unset_option_command,
    handle_tasks_command,
    handle_task_command,
    handle_context_command,
    handle_workspace_command,
    handle_knowledge_base_command,
    handle_attach_command,
    handle_detach_command,
    handle_reparse_command,
    handle_history_command,
    handle_clear_command,
    handle_load_command,
    handle_resume_command,
    handle_pause_command,
    handle_story_command,
    handle_run_tool_command,
    handle_quit_command,
    handle_empty_command,
    handle_unknown_command,
];

impl ShellApp {
    pub fn handle_command(&mut self, command: ShellCommand) {
        for handler in COMMAND_HANDLERS {
            if handler(self, &command) {
                return;
            }
        }
    }

    pub fn submit_line(&mut self, raw: &str) {
        let trimmed = raw.trim();
        // Empty / whitespace-only Enter is a no-op. Logging an empty `>`
        // bullet just clutters the 2-row transcript with `· ` rows the
        // operator never asked for.
        if trimmed.is_empty() {
            return;
        }
        self.log(">", raw.to_string());
        self.command_history.push(trimmed.to_string());
        if self.command_history.len() > 200 {
            let overflow = self.command_history.len() - 200;
            self.command_history.drain(0..overflow);
        }
        if matches!(self.shell_view, ShellView::PromptsEditor)
            && !trimmed.is_empty()
            && !trimmed.starts_with('/')
            && self.is_bare_prompt_verb(trimmed)
        {
            self.handle_prompt_verb(trimmed);
            return;
        }
        if matches!(self.shell_view, ShellView::Tune)
            && !trimmed.is_empty()
            && !trimmed.starts_with('/')
            && self.is_bare_tune_verb(trimmed)
        {
            self.handle_tune_verb(trimmed);
            return;
        }
        self.handle_command(parse_command(raw));
    }

    pub(super) fn is_bare_prompt_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "edit" | "show" | "diff" | "reset" | "set" | "list")
    }

    pub(super) fn is_bare_tune_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "show" | "set" | "reset")
    }
}

fn handle_help_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Help = command else {
        return false;
    };
    app.shell_view = ShellView::Help;
    app.help_scroll = 0;
    app.log("help", compact_help_summary());
    true
}

fn handle_back_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Back = command else {
        return false;
    };
    app.go_back();
    true
}

fn handle_modules_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Modules = command else {
        return false;
    };
    app.shell_view = ShellView::Catalog;
    app.catalog_expanded = true;
    app.modules_scroll = 0;
    app.log(
        "module",
        format!("showing {} module(s)", app.registry.modules().count()),
    );
    true
}

fn handle_tools_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tools = command else {
        return false;
    };
    app.shell_view = ShellView::Tools;
    app.tools_scroll = 0;
    app.log(
        "tool",
        format!("showing {} tool(s)", app.registry.tools().count()),
    );
    true
}

fn handle_findings_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Findings = command else {
        return false;
    };
    app.show_findings();
    true
}

fn handle_open_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Open(id) = command else {
        return false;
    };
    app.open_finding(id);
    true
}

fn handle_scan_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Scan(target) = command else {
        return false;
    };
    app.start_scan(target.clone());
    true
}

fn handle_model_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Model(model) = command else {
        return false;
    };
    app.handle_model_command(model.clone());
    true
}

fn handle_auth_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Auth = command else {
        return false;
    };
    app.show_auth_status();
    true
}

fn handle_auth_login_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::AuthLogin(provider) = command else {
        return false;
    };
    app.handle_auth_login_command(provider.clone());
    true
}

fn handle_provider_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Provider(provider) = command else {
        return false;
    };
    app.handle_provider_command(provider.clone());
    true
}

fn handle_backend_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Backend(backend) = command else {
        return false;
    };
    app.handle_backend_command(backend.clone());
    true
}

fn handle_cost_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Cost = command else {
        return false;
    };
    app.show_cost_status();
    true
}

fn handle_config_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Config = command else {
        return false;
    };
    app.shell_view = ShellView::Config;
    app.sync_selected_model_index();
    app.log(
        "config",
        format!(
            "runtime={} provider={} model={}",
            runtime_backend_label(&app.config),
            app.provider_label(),
            app.config.model.as_deref().unwrap_or("unconfigured")
        ),
    );
    true
}

fn handle_use_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Use(module) = command else {
        return false;
    };
    if app
        .registry
        .modules()
        .any(|entry| entry.metadata().id == module.as_str())
    {
        app.focused_module = Some(module.clone());
        app.shell_view = ShellView::Module;
        app.log("use", module);
    } else {
        app.log("error", app.unknown_module_message(module));
    }
    true
}

fn handle_tune_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tune = command else {
        return false;
    };
    app.shell_view = ShellView::Tune;
    app.log("view", "tune");
    true
}

fn handle_threat_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Threat(view) = command else {
        return false;
    };
    app.shell_view = ShellView::Threat(*view);
    app.log("view", format!("threats {}", threat_view_label(*view)));
    true
}

fn handle_threat_regen_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatRegen = command else {
        return false;
    };
    app.start_threat_regen();
    true
}

fn handle_threat_ask_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatAsk(question) = command else {
        return false;
    };
    app.start_threat_ask(question);
    true
}

fn handle_threat_apply_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatApply = command else {
        return false;
    };
    app.apply_pending_threat_patch();
    true
}

fn handle_threat_reject_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatReject = command else {
        return false;
    };
    app.discard_pending_threat_patch();
    true
}

fn handle_threat_editor_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ThreatEditor = command else {
        return false;
    };
    app.shell_view = ShellView::ThreatEditor;
    app.log("view", "threats edit");
    true
}

fn handle_prompts_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Prompts = command else {
        return false;
    };
    app.shell_view = ShellView::PromptsEditor;
    app.log("view", "prompts");
    true
}

fn handle_prompt_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Prompt(raw) = command else {
        return false;
    };
    app.shell_view = ShellView::PromptsEditor;
    app.handle_prompt_verb(raw);
    true
}

fn handle_actor_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Actor(index) = command else {
        return false;
    };
    app.shell_view = ShellView::ActorDetail(*index);
    app.log("actor", index.to_string());
    true
}

fn handle_show_runs_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ShowRuns = command else {
        return false;
    };
    app.shell_view = ShellView::Runs;
    app.log("runs", "recent runs");
    true
}

fn handle_show_aliases_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::ShowAliases(prefix) = command else {
        return false;
    };
    app.show_aliases(prefix.as_deref());
    true
}

fn handle_since_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Since(reference) = command else {
        return false;
    };
    app.shell_view = ShellView::Findings;
    app.log("since", reference);
    true
}

fn handle_replay_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Replay(run_id) = command else {
        return false;
    };
    app.shell_view = ShellView::Replay(run_id.clone());
    app.log("replay", run_id);
    true
}

fn handle_trace_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Trace(run_id) = command else {
        return false;
    };
    app.shell_view = ShellView::Trace(run_id.clone());
    app.log("trace", run_id);
    true
}

fn handle_plan_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Plan(goal) = command else {
        return false;
    };
    app.start_planner(goal);
    true
}

fn handle_plan_apply_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::PlanApply = command else {
        return false;
    };
    app.apply_pending_plan();
    true
}

fn handle_plan_discard_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::PlanDiscard = command else {
        return false;
    };
    app.discard_pending_plan();
    true
}

fn handle_quickstart_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Quickstart = command else {
        return false;
    };
    app.show_quickstart();
    true
}

fn handle_target_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Target(path) = command else {
        return false;
    };
    app.handle_target_command(path.as_deref());
    true
}

fn handle_ask_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Ask(question) = command else {
        return false;
    };
    app.ask_agent(question);
    true
}

fn handle_options_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Options { tool, filter } = command else {
        return false;
    };
    app.show_options(tool.clone(), *filter);
    true
}

fn handle_set_option_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
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

fn handle_unset_option_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::UnsetOption { global, name } = command else {
        return false;
    };
    app.unset_option(*global, name);
    true
}

fn handle_tasks_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Tasks = command else {
        return false;
    };
    app.show_sast_tasks();
    true
}

fn handle_task_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Task(task_command) = command else {
        return false;
    };
    app.handle_sast_task_command(task_command.clone());
    true
}

fn handle_context_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Context(context_command) = command else {
        return false;
    };
    app.handle_context_command(context_command.clone());
    true
}

fn handle_workspace_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Workspace(workspace_command) = command else {
        return false;
    };
    app.handle_workspace_command(workspace_command.clone());
    true
}

fn handle_knowledge_base_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::KnowledgeBase(module) = command else {
        return false;
    };
    app.show_kb(module.clone());
    true
}

fn handle_attach_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Attach(source) = command else {
        return false;
    };
    app.attach_kb_source(source);
    true
}

fn handle_detach_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Detach(id) = command else {
        return false;
    };
    app.detach_kb_source(id);
    true
}

fn handle_reparse_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Reparse(id) = command else {
        return false;
    };
    app.reparse_kb_source(id);
    true
}

fn handle_history_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::History = command else {
        return false;
    };
    app.show_history();
    true
}

fn handle_clear_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Clear = command else {
        return false;
    };
    app.clear_conversation();
    true
}

fn handle_load_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Load(specifier) = command else {
        return false;
    };
    app.handle_load_command(specifier.clone());
    true
}

fn handle_resume_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Resume(run_id) = command else {
        return false;
    };
    app.handle_resume_command(run_id.clone());
    true
}

fn handle_pause_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Pause = command else {
        return false;
    };
    app.handle_pause_command();
    true
}

fn handle_story_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Story = command else {
        return false;
    };
    app.show_story();
    true
}

fn handle_run_tool_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::RunTool { tool, input } = command else {
        return false;
    };
    app.run_tool(tool.clone(), input.clone());
    true
}

fn handle_quit_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Quit = command else {
        return false;
    };
    app.request_exit();
    true
}

fn handle_empty_command(_app: &mut ShellApp, command: &ShellCommand) -> bool {
    matches!(command, ShellCommand::Empty)
}

fn handle_unknown_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Unknown(raw) = command else {
        return false;
    };
    app.log("error", unknown_command_message(raw));
    true
}

fn compact_help_summary() -> String {
    let commands = shell_command_specs()
        .iter()
        .map(|spec| {
            if spec.command.starts_with('?') {
                spec.command.to_string()
            } else {
                format!("/{}", spec.command)
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let examples = shell_help_examples();
    if examples.is_empty() {
        commands
    } else {
        format!("Examples: {}. Commands: {commands}", examples.join(", "))
    }
}

pub(super) fn unknown_command_message(raw: &str) -> String {
    let trimmed = raw.trim();
    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let verb = normalized.split_whitespace().next().unwrap_or_default();

    if verb == "ask" {
        return "ask needs a question. Next: /ask <question>".to_string();
    }

    if verb == "open" {
        return "open needs a finding alias. Next: `findings` to list, then `open F-0001`"
            .to_string();
    }

    if verb == "since" {
        return "since needs a git ref. Next: `since main` or `since HEAD~5`".to_string();
    }

    if verb == "replay" || verb == "trace" {
        return format!(
            "{verb} needs a runId. Next: `show runs` to list runs, then `{verb} <runId>`"
        );
    }

    if verb == "use" {
        return "use needs a module id. Next: `modules` to list, then `use <module>`".to_string();
    }

    if verb == "run" {
        return "run needs a tool id. Next: `tools` to list, then `run <tool> [json-input]`"
            .to_string();
    }

    if verb == "plan" {
        return "plan needs a natural-language goal. Next: `plan use Claude Sonnet 4.6 with high effort` (Haiku translates intent → option diff, review with /yes or /no)".to_string();
    }

    if verb == "load" {
        return "load needs a module specifier. Next: `modules` for static registry; dynamic loading is unsupported in the Rust shell.".to_string();
    }

    if matches!(verb, "set" | "setg") {
        let scope = if verb == "setg" { "global" } else { "session" };
        return format!(
            "{verb} needs a key + value. Next: `options [tool]` to discover keys, then `{verb} <key> <value>` ({scope})"
        );
    }

    if matches!(verb, "unset" | "unsetg") {
        let scope = if verb == "unsetg" {
            "global"
        } else {
            "session"
        };
        return format!(
            "{verb} needs a key. Next: `options [tool]` to discover keys, then `{verb} <key>` ({scope})"
        );
    }

    if matches!(verb, "attach" | "detach" | "reparse") {
        return format!(
            "{verb} needs an arg. Next: `kb` to see attachments and supported modules, then `{verb} <path-or-id>`"
        );
    }

    if verb == "task" {
        return "task needs a sub-verb. Next: `tasks` to list, then `task block <id>` / `task allow <id>` / `task toggle [id]` / `task mode auto|manual|toggle` / `task reset`".to_string();
    }

    if verb == "threats" {
        return "threats needs a sub-verb or number. Next: `threats summary|dfd|stride|stories|scope` (or 1..5), `threats edit`, `threats regen`, `threats apply`, `threats reject`, `threats ask <question>`".to_string();
    }

    if verb == "prompt" {
        return "prompt needs a sub-verb. Next: `prompts` to open the editor, or `prompt edit <verb>` / `prompt show <verb>` / `prompt diff <verb>` / `prompt reset <verb>`".to_string();
    }

    // Verbs that only exist as top-level CLI subcommands. The shell rejects
    // them, but the user is probably asking for the diagnostic, so point at
    // the right place rather than punting them into the agent flow.
    if let Some(cli_hint) = cli_only_verb_hint(verb) {
        return format!("{trimmed:?} is a CLI subcommand, not an in-shell verb. Next: {cli_hint}");
    }

    // `findings F-0001` / `finding F-0001` are common typos for `open F-0001`.
    // The user clearly knows what alias they want; they just picked the
    // wrong verb. Point them at the right one instead of punting to /ask.
    if matches!(verb, "findings" | "finding") {
        let rest = normalized
            .split_whitespace()
            .nth(1)
            .filter(|arg| arg.to_ascii_uppercase().starts_with("F-"));
        if let Some(alias) = rest {
            return format!(
                "{verb:?} doesn't take arguments. Next: `open {}` to view the finding.",
                alias.to_ascii_uppercase()
            );
        }
    }

    if trimmed.starts_with('/') {
        format!("unknown command {trimmed:?}. Next: /help")
    } else {
        format!(
            "unknown command {trimmed:?}. Free-form chat is explicit only. Next: /ask <question> or help"
        )
    }
}

fn cli_only_verb_hint(verb: &str) -> Option<&'static str> {
    match verb {
        "doctor" => Some("run `kuzushi doctor` from a shell, or `auth` here for credential status"),
        "scan-ci" | "ci" => Some("run `kuzushi scan <target> --ci` from a shell"),
        "pr-comment" => Some("run `kuzushi pr-comment` from a shell"),
        "mcp" => Some("run `kuzushi mcp serve <backend>` from a shell"),
        "version" | "--version" | "-V" => Some("run `kuzushi --version` from a shell"),
        _ => None,
    }
}
