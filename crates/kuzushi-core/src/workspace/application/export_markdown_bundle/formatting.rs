pub(super) fn markdown_table_cell(value: &str) -> String {
    markdown_inline_text(value).replace('|', "\\|")
}

/// Finding-derived text placed on a single markdown line (headers, list
/// items). Newlines would let hostile capture content inject its own
/// markdown lines into the bundle.
pub(super) fn markdown_inline_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('@', "&#64;")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('!', "\\!")
        .replace(['\n', '\r'], " ")
}

pub(super) fn markdown_code_span(value: &str) -> String {
    let value = value.replace(['\n', '\r'], " ");
    let fence = "`".repeat(longest_backtick_run(&value) + 1);
    format!("{fence}{value}{fence}")
}

/// Wrap finding-derived text in a code fence longer than any backtick run
/// inside it, so snippet content (e.g. a captured HTTP body containing
/// ```` ``` ````) cannot close the fence and inject markdown.
pub(super) fn fenced_snippet_block(snippet: &str) -> String {
    let snippet = snippet.replace("\r\n", "\n").replace('\r', "\n");
    let fence = "`".repeat(longest_backtick_run(&snippet).max(2) + 1);
    format!("{fence}\n{snippet}\n{fence}\n\n")
}

fn longest_backtick_run(value: &str) -> usize {
    let mut longest = 0usize;
    let mut current = 0usize;
    for ch in value.chars() {
        current = if ch == '`' { current + 1 } else { 0 };
        longest = longest.max(current);
    }
    longest
}
