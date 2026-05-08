use super::*;

pub(crate) fn model_auth_status(choice: &crate::app::ModelChoice) -> String {
    match choice.provider {
        "openai" => {
            if std::env::var_os("OPENAI_API_KEY").is_some() {
                "OPENAI_API_KEY set".to_string()
            } else {
                "OPENAI_API_KEY missing".to_string()
            }
        }
        "openai-codex" => {
            let status = crate::app::oauth_provider_status("openai-codex");
            if status.starts_with("stored") {
                "OAuth ready".to_string()
            } else {
                "OAuth missing".to_string()
            }
        }
        "anthropic" => {
            let env_ready = std::env::var_os("ANTHROPIC_API_KEY").is_some();
            let oauth_ready = crate::app::oauth_provider_status("anthropic").starts_with("stored");
            match (env_ready, oauth_ready) {
                (true, true) => "ANTHROPIC_API_KEY/OAuth ready".to_string(),
                (true, false) => "ANTHROPIC_API_KEY set".to_string(),
                (false, true) => "OAuth ready".to_string(),
                (false, false) => "ANTHROPIC auth missing".to_string(),
            }
        }
        _ => choice.auth.to_string(),
    }
}

pub(crate) fn tools_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("TOOLS", area.width));
    let widths = [28usize, 8, value_width(area, 38)];
    lines.push(aligned_header(
        &["tool", "headless", "description"],
        &widths,
    ));
    for tool in app.registry.tools() {
        lines.push(aligned_row(
            &[
                tool.name.clone(),
                tool.headless.to_string(),
                tool.description.clone(),
            ],
            &widths,
        ));
    }
    lines
}
