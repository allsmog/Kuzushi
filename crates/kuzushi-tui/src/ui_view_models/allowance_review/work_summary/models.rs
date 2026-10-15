//! Present only the models recorded in frozen work.
pub(super) fn model_overview(models: &[Option<&str>]) -> Vec<String> {
    let mut lines = Vec::new();
    for model in models {
        let line = overview_model_line(*model);
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    lines
}

fn overview_model_line(model: Option<&str>) -> String {
    match model {
        Some(model) if !model.trim().is_empty() => format!("Model: {model}"),
        Some(_) => "Model: unrecorded; inspect plan details".into(),
        None => "Model: none (native engines)".into(),
    }
}

pub(super) fn execution_model_line(model: Option<&str>) -> String {
    match model {
        Some(model) if !model.trim().is_empty() => format!("Execution model: {model}"),
        Some(_) => "Execution model: unrecorded; inspect the frozen plan before approval".into(),
        None => "Execution model: none; this frozen discovery uses native engines".into(),
    }
}
