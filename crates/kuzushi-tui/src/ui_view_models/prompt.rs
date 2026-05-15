use super::{routing_mode, RoutingMode};
use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromptModel {
    pub(crate) prefix: String,
    pub(crate) input: String,
    pub(crate) cursor: usize,
}

pub(crate) fn prompt_model(app: &ShellApp) -> PromptModel {
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
    if cli_name == Some("kz") {
        return "kz";
    }
    match argv0.and_then(binary_stem) {
        Some("kz") => "kz",
        _ => "kuzushi",
    }
}

fn binary_stem(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .next()
        .map(|name| name.strip_suffix(".exe").unwrap_or(name))
}

#[cfg(test)]
mod tests;
