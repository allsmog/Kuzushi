use super::*;

pub(crate) fn unknown_command_message(raw: &str) -> String {
    let trimmed = raw.trim();
    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let verb = normalized.split_whitespace().next().unwrap_or_default();

    if let Some(message) = missing_argument_message(verb) {
        return message;
    }
    if let Some(message) = missing_option_message(verb) {
        return message;
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

    fallback_unknown_command_message(trimmed)
}

fn missing_argument_message(verb: &str) -> Option<String> {
    let message = match verb {
        "ask" => "ask needs a question. Next: /ask <question>".to_string(),
        "open" => {
            "open needs a finding alias. Next: `findings` to list, then `open F-0001`".to_string()
        }
        "since" => "since needs a git ref. Next: `since main` or `since HEAD~5`".to_string(),
        "replay" | "trace" => format!(
            "{verb} needs a runId. Next: `show runs` to list runs, then `{verb} <runId>`"
        ),
        "use" => {
            "use needs a module id. Next: `modules` to list, then `use <module>`".to_string()
        }
        "run" => {
            "run needs a tool id. Next: `tools` to list, then `run <tool> [json-input]`"
                .to_string()
        }
        "plan" => "plan needs a natural-language goal. Next: `plan use Claude Sonnet 4.6 with high effort` (Haiku translates intent → option diff, review with /yes or /no)".to_string(),
        "load" => "load needs a module specifier. Next: `load file:///abs/module.mjs` after trusting it in operator config.".to_string(),
        _ => return None,
    };
    Some(message)
}

fn missing_option_message(verb: &str) -> Option<String> {
    if let Some(message) = missing_set_option_message(verb) {
        return Some(message);
    }
    if let Some(message) = missing_attachment_option_message(verb) {
        return Some(message);
    }
    let message = match verb {
        "task" => "task needs a sub-verb. Next: `tasks` to list, then `task block <id>` / `task allow <id>` / `task toggle [id]` / `task mode auto|manual|toggle` / `task reset`".to_string(),
        "threats" => "threats needs a sub-verb or number. Next: `threats summary|dfd|stride|stories|scope` (or 1..5), `threats edit`, `threats regen`, `threats apply`, `threats reject`, `threats ask <question>`".to_string(),
        "prompt" => "prompt needs a sub-verb. Next: `prompts` to open the editor, or `prompt edit <verb>` / `prompt show <verb>` / `prompt diff <verb>` / `prompt reset <verb>`".to_string(),
        _ => return None,
    };
    Some(message)
}

fn missing_set_option_message(verb: &str) -> Option<String> {
    match verb {
        "set" | "setg" => Some(format!(
            "{verb} needs a key + value. Next: `options [tool]` to discover keys, then `{verb} <key> <value>` ({})",
            option_scope_label(verb)
        )),
        "unset" | "unsetg" => Some(format!(
            "{verb} needs a key. Next: `options [tool]` to discover keys, then `{verb} <key>` ({})",
            option_scope_label(verb)
        )),
        _ => None,
    }
}

fn option_scope_label(verb: &str) -> &'static str {
    if verb.ends_with('g') {
        "global"
    } else {
        "session"
    }
}

fn missing_attachment_option_message(verb: &str) -> Option<String> {
    matches!(verb, "attach" | "detach" | "reparse").then(|| {
        format!(
            "{verb} needs an arg. Next: `kb` to see attachments and supported modules, then `{verb} <path-or-id>`"
        )
    })
}

fn fallback_unknown_command_message(trimmed: &str) -> String {
    if trimmed.starts_with('/') {
        format!("unknown command {trimmed:?}. Next: /help")
    } else {
        format!(
            "unknown command {trimmed:?}. Free-form chat is explicit only. Next: /ask <question> or help"
        )
    }
}
