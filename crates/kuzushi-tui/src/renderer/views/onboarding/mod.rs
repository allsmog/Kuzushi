use super::*;

mod auth_method_picker;
mod file_picker;
mod model_picker;
mod planning_picker;
mod target_picker;

pub(crate) use auth_method_picker::auth_method_picker_lines;
pub(crate) use file_picker::file_picker_lines;
pub(crate) use model_picker::model_picker_lines;
pub(crate) use planning_picker::planning_picker_lines;
pub(crate) use target_picker::target_picker_lines;

fn target_identity_line(prefix: &str, path: &std::path::Path, width: usize) -> Line<'static> {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| path.display().to_string());
    let lead = format!(" {prefix}: {name} · ");
    let path_budget = width.saturating_sub(display_width(&lead));
    let path = fit_path(&path.display().to_string(), path_budget);
    Line::from(vec![
        Span::styled(lead, theme::muted()),
        Span::styled(path, theme::primary()),
    ])
}

fn confirmed_target_line(app: &ShellApp, width: usize) -> Option<Line<'static>> {
    app.target()
        .map(|path| target_identity_line("Target confirmed", path, width))
}
