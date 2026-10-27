//! Present only the models recorded in frozen work.
pub(super) fn model_overview(models: &[Option<&str>]) -> Vec<String> {
    let mut lines = Vec::new();
    for model in models {
        let line = execution_model_line(*model);
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    lines
}

pub(super) fn execution_model_line(model: Option<&str>) -> String {
    match model {
        Some(model) if !model.trim().is_empty() => {
            format!(
                "Execution model: {}",
                crate::app::display_model_selector(model)
            )
        }
        Some(_) => "Execution model: unrecorded; inspect the frozen plan before approval".into(),
        None => "Execution model: none; this frozen discovery uses native engines".into(),
    }
}
