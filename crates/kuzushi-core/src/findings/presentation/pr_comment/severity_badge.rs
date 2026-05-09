use super::*;

pub(crate) fn escape_md(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
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
