use super::*;

pub(crate) fn escape_md(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('@', "&#64;")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('!', "\\!")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

pub(crate) fn markdown_code_span(text: &str) -> String {
    let text = escape_md(text);
    let fence = "`".repeat(longest_backtick_run(&text) + 1);
    format!("{fence}{text}{fence}")
}

fn longest_backtick_run(value: &str) -> usize {
    value
        .split(|ch| ch != '`')
        .map(str::len)
        .max()
        .unwrap_or_default()
}

pub(crate) fn short(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

pub(crate) fn format_duration(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let m = secs / 60;
    let s = secs % 60;
    if s == 0 {
        format!("{m}m")
    } else {
        format!("{m}m {s}s")
    }
}
