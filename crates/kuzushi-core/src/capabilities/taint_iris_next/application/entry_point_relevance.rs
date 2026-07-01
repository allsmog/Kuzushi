/// Relevance score for an entry-point name when no operator-supplied scoring
/// exists. Higher means more interesting.
pub(crate) fn entry_point_relevance_score(name: &str) -> i32 {
    let lower = name.to_ascii_lowercase();
    positive_entry_point_score(&lower).saturating_sub(negative_entry_point_penalty(&lower))
}

fn positive_entry_point_score(lower: &str) -> i32 {
    ENTRY_POINT_POSITIVE_TOKENS
        .iter()
        .filter(|token| lower.contains(**token))
        .fold(0_i32, |score, _| score.saturating_add(20))
}

fn negative_entry_point_penalty(lower: &str) -> i32 {
    ENTRY_POINT_NEGATIVE_SUFFIXES
        .iter()
        .filter(|suffix| lower.ends_with(**suffix))
        .fold(0_i32, |score, _| score.saturating_add(10))
}

const ENTRY_POINT_POSITIVE_TOKENS: &[&str] = &[
    "exec",
    "system",
    "shell",
    "command",
    "run_program",
    "popen",
    "spawn",
    "load_library",
    "load_file",
    "load_external",
    "load_module",
    "dlopen",
    "dlsym",
    "import",
    "read_file",
    "read_binary",
    "read_server",
    "read_text",
    "write_file",
    "stat_file",
    "ls_dir",
    "ls_log",
    "ls_wal",
    "signal_backend",
    "signal_proc",
    "kill_backend",
    "reload_conf",
    "reload_config",
    "alter_system",
    "promote",
    "terminate",
    "cancel_backend",
    "set_user",
    "setuid",
    "admin",
    "super",
    "sudo",
    "privesc",
    "set_session",
    "switch_user",
    "become",
    "upload",
    "download",
    "evaluate",
    "eval",
    "compile",
    "parse_script",
    "lo_import",
    "lo_export",
];

const ENTRY_POINT_NEGATIVE_SUFFIXES: &[&str] = &[
    "_joinsel", "_sel", "_cmp", "_hash", "_in", "_out", "_recv", "_send", "_eq", "_lt", "_gt",
    "_le", "_ge", "_ne",
];
