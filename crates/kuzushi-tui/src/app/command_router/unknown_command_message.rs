use super::*;
use crate::app::line_editor::rank_fuzzy;
use crate::commands::shell_command_specs;

pub(crate) fn unknown_command_message(raw: &str) -> String {
    let trimmed = raw.trim();
    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let verb = normalized.split_whitespace().next().unwrap_or_default();

    known_unknown_command_message(normalized, verb)
        .or_else(|| did_you_mean_command_message(trimmed, verb))
        .unwrap_or_else(|| fallback_unknown_command_message(trimmed))
}

fn known_unknown_command_message(normalized: &str, verb: &str) -> Option<String> {
    missing_argument_message(verb)
        .or_else(|| missing_option_message(verb))
        .or_else(|| legacy_auth_selector_message(normalized))
        .or_else(|| cli_only_command_message(verb))
        .or_else(|| findings_alias_typo_message(normalized, verb))
}

fn cli_only_command_message(verb: &str) -> Option<String> {
    // Verbs that only exist as top-level CLI subcommands. The shell rejects
    // them, but the user is probably asking for the diagnostic, so point at
    // the right place rather than punting them into the agent flow.
    cli_only_verb_hint(verb).map(|cli_hint| {
        format!("{verb:?} is a CLI subcommand, not an in-shell verb. Next: {cli_hint}")
    })
}

fn findings_alias_typo_message(normalized: &str, verb: &str) -> Option<String> {
    // `findings F-0001` / `finding F-0001` are common typos for `open F-0001`.
    // The user clearly knows what alias they want; they just picked the
    // wrong verb. Point them at the right one instead of punting to /ask.
    matches!(verb, "findings" | "finding")
        .then(|| normalized.split_whitespace().nth(1))
        .flatten()
        .filter(|arg| arg.to_ascii_uppercase().starts_with("F-"))
        .map(|alias| {
            format!(
                "{verb:?} doesn't take arguments. Next: `open {}` to view the finding.",
                alias.to_ascii_uppercase()
            )
        })
}

fn legacy_auth_selector_message(normalized: &str) -> Option<String> {
    if normalized == "auth legacy-openai-oauth" {
        return Some(public_openai_oauth_login_message());
    }
    let mut parts = normalized.split_whitespace();
    let first = parts.next()?;
    let second = parts.next()?;
    let legacy_selector = matches!(second, "codex" | "openai-codex")
        || matches!(parts.next(), Some("codex" | "openai-codex"));
    (first == "auth" && legacy_selector).then(public_openai_oauth_login_message)
}

fn public_openai_oauth_login_message() -> String {
    "OpenAI OAuth login uses `auth login openai`. Next: auth login openai browser or auth login openai headless".to_string()
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
        "threats" => "threats needs a sub-verb or number. Next: `threats summary|dfd|stride|stories|scope|versions` (or 1..5), `threats use <id>`, `threats edit`, `threats regen`, `threats apply`, `threats reject`, `threats ask <question>`".to_string(),
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

fn did_you_mean_command_message(trimmed: &str, verb: &str) -> Option<String> {
    if verb.is_empty() {
        return None;
    }
    let heads = command_heads();
    if heads.iter().any(|head| head == verb) {
        return None;
    }
    let matches = rank_fuzzy(heads, verb);
    let suggestion = matches.first()?;
    Some(format!(
        "unknown command {trimmed:?}. Did you mean `{suggestion}`? Next: `{suggestion}` or /help"
    ))
}

fn command_heads() -> Vec<String> {
    let mut heads = shell_command_specs()
        .flat_map(|spec| std::iter::once(spec.command).chain(spec.aliases.iter().copied()))
        .filter_map(command_head)
        .collect::<Vec<_>>();
    heads.sort();
    heads.dedup();
    heads
}

fn command_head(value: &str) -> Option<String> {
    let head = value
        .trim()
        .trim_start_matches('/')
        .split_whitespace()
        .next()?;
    (!head.is_empty() && !head.starts_with('<')).then(|| head.to_string())
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
