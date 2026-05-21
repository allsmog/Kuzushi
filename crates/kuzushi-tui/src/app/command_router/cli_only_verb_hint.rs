use super::*;

pub(crate) fn cli_only_verb_hint(verb: &str) -> Option<&'static str> {
    match verb {
        "doctor" => Some("exit and run `kuzushi doctor`, or try `auth` here"),
        "scan-ci" | "ci" => Some("run `kuzushi scan <target> --ci` from a shell"),
        "pr-comment" => Some("run `kuzushi pr-comment` from a shell"),
        "mcp" => Some("run `kuzushi mcp serve <backend>` from a shell"),
        "version" | "--version" | "-V" => Some("run `kuzushi --version` from a shell"),
        _ => None,
    }
}
