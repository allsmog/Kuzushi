use super::prelude::*;
use super::*;

pub(crate) fn unknown_command_message(raw: &str) -> String {
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
