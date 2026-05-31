use super::{routing_mode, RoutingMode};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptModel {
    pub(crate) prefix: String,
    pub(crate) input: String,
    pub(crate) cursor: usize,
}

pub(crate) fn prompt_model(app: &ShellApp) -> PromptModel {
    if let Some(search) = app.history_search.as_ref() {
        return reverse_search_prompt(app, &search.query);
    }
    PromptModel {
        prefix: prompt_text(
            prompt_brand(),
            routing_mode(app),
            app.focused_module.as_deref(),
        ),
        input: app.input.clone(),
        cursor: app.cursor,
    }
}

fn reverse_search_prompt(app: &ShellApp, query: &str) -> PromptModel {
    let prefix = format!("(reverse-i-search)`{query}': ");
    let input = app.current_history_match().unwrap_or("").to_string();
    let cursor = input.chars().count();
    PromptModel {
        prefix,
        input,
        cursor,
    }
}

pub(crate) fn prompt_brand() -> &'static str {
    prompt_brand_from_sources(
        std::env::var("KUZUSHI_CLI_NAME").ok().as_deref(),
        std::env::args().next().as_deref(),
    )
}

pub(crate) fn prompt_text(brand: &str, mode: RoutingMode, focused_module: Option<&str>) -> String {
    match mode {
        RoutingMode::Run => focused_module
            .map(|module| format!("{brand}/{module}/run> "))
            .unwrap_or_else(|| format!("{brand}/run> ")),
        RoutingMode::Agent => format!("{brand}/agent> "),
        RoutingMode::Plan => format!("{brand}/plan> "),
        RoutingMode::Module => focused_module
            .map(|module| format!("{brand}/{module}> "))
            .unwrap_or_else(|| format!("{brand}/module> ")),
        RoutingMode::Shell => format!("{brand}> "),
    }
}

fn prompt_brand_from_sources(cli_name: Option<&str>, argv0: Option<&str>) -> &'static str {
    if let Some(brand) = argv0.and_then(binary_stem).and_then(public_prompt_brand) {
        return brand;
    }
    if cli_name == Some("kz") {
        "kz"
    } else {
        "kuzushi"
    }
}

fn public_prompt_brand(stem: &str) -> Option<&'static str> {
    if stem.eq_ignore_ascii_case("kz") {
        Some("kz")
    } else if stem.eq_ignore_ascii_case("kuzushi") {
        Some("kuzushi")
    } else {
        None
    }
}

fn binary_stem(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\']).next().map(strip_windows_exe)
}

fn strip_windows_exe(name: &str) -> &str {
    // `name.get(cut..)` returns None when `cut` is not a char boundary, so a
    // unicode binary name (e.g. "a€€", where len-4 lands mid-char) yields the
    // name unchanged instead of panicking on a byte-index slice.
    let cut = name.len().saturating_sub(4);
    match name.get(cut..) {
        Some(suffix) if suffix.eq_ignore_ascii_case(".exe") => &name[..cut],
        _ => name,
    }
}

#[cfg(test)]
mod tests;
