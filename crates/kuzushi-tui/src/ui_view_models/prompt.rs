use super::{routing_mode, RoutingMode};
use crate::{ShellApp, ShellView, WorkbenchPage};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptModel {
    pub(crate) prefix: String,
    pub(crate) input: String,
    pub(crate) cursor: usize,
    pub(crate) placeholder: Option<String>,
    pub(crate) workbench_mode: Option<WorkbenchPage>,
}

pub(crate) fn prompt_model(app: &ShellApp) -> PromptModel {
    if let Some(search) = app.history_search() {
        return reverse_search_prompt(app, &search.query);
    }
    let workbench_mode = workbench_prompt_mode(app);
    PromptModel {
        prefix: workbench_mode
            .map(workbench_prompt_token)
            .map(str::to_string)
            .unwrap_or_else(|| {
                prompt_text(prompt_brand(), routing_mode(app), app.focused_module())
            }),
        input: app.input().to_string(),
        cursor: app.cursor(),
        placeholder: prompt_placeholder(app, workbench_mode),
        workbench_mode,
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
        placeholder: None,
        workbench_mode: None,
    }
}

fn prompt_placeholder(app: &ShellApp, mode: Option<WorkbenchPage>) -> Option<String> {
    app.input().is_empty().then(|| {
        mode.map(workbench_prompt_placeholder)
            .unwrap_or("type help or press Tab")
            .to_string()
    })
}

pub(crate) fn workbench_prompt_mode(app: &ShellApp) -> Option<WorkbenchPage> {
    (app.shell_view() == ShellView::Workbench).then(|| super::active_workbench_page(app))
}

pub(crate) fn navigation_prompt_label(app: &ShellApp) -> String {
    let mut text = "NAVIGATE · Shift+Tab mode · Tab/[/] pane".to_string();
    let keys = app
        .ui()
        .keymap_binding_labels("composer", "prompt_mode", &["Esc"]);
    if !keys.is_empty() {
        text.push_str(" · ");
        text.push_str(&keys.join("/"));
        text.push_str(" prompt");
    }
    text
}

pub(crate) const fn workbench_prompt_token(page: WorkbenchPage) -> &'static str {
    match page {
        WorkbenchPage::Map => "◇ MAP › ",
        WorkbenchPage::Scan => "▦ SCAN › ",
        WorkbenchPage::Review => "▣ REVIEW › ",
        WorkbenchPage::Prove => "◎ PROVE › ",
        WorkbenchPage::Fix => "◆ FIX › ",
    }
}

const fn workbench_prompt_placeholder(page: WorkbenchPage) -> &'static str {
    match page {
        WorkbenchPage::Map => "describe what to map",
        WorkbenchPage::Scan => "describe what to scan",
        WorkbenchPage::Review => "describe what to review",
        WorkbenchPage::Prove => "describe what to verify",
        WorkbenchPage::Fix => "describe the patch to draft",
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
