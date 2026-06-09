use super::*;

pub(crate) fn extract_codeql_location(result: &CodeqlSarifResult) -> Option<(String, u32)> {
    if let Some(location) = result.locations.first() {
        let physical = location.physical_location.as_ref()?;
        let uri = physical
            .artifact_location
            .as_ref()?
            .uri
            .as_deref()
            .and_then(non_empty_string)?;
        let file_path = normalize_artifact_uri(uri);
        let start_line = physical
            .region
            .as_ref()
            .and_then(|region| region.start_line)
            .filter(|line| *line > 0)
            .unwrap_or(1);
        return Some((file_path, start_line));
    }
    None
}

pub(crate) fn render_codeql_flow_evidence(result: &CodeqlSarifResult) -> Option<String> {
    let steps = extract_codeql_flow_steps(result);
    if steps.is_empty() {
        return None;
    }

    let mut segments = steps
        .iter()
        .take(16)
        .map(|step| match &step.message {
            Some(message) => format!("{}:{} ({message})", step.file_path, step.line),
            None => format!("{}:{}", step.file_path, step.line),
        })
        .collect::<Vec<_>>();
    if steps.len() > 16 {
        segments.push(format!("... {} more step(s)", steps.len() - 16));
    }
    Some(format!("Code flow: {}", segments.join(" -> ")))
}

pub(crate) fn extract_codeql_flow_steps(result: &CodeqlSarifResult) -> Vec<CodeqlFlowStep> {
    let mut steps: Vec<CodeqlFlowStep> = Vec::new();
    for code_flow in &result.code_flows {
        for thread_flow in &code_flow.thread_flows {
            for location in &thread_flow.locations {
                let Some(nested) = location.location.as_ref() else {
                    continue;
                };
                let Some(physical) = nested.physical_location.as_ref() else {
                    continue;
                };
                let Some(artifact_location) = physical.artifact_location.as_ref() else {
                    continue;
                };
                let Some(uri) = artifact_location.uri.as_deref().and_then(non_empty_string) else {
                    continue;
                };
                let file_path = normalize_artifact_uri(uri);
                let line = physical
                    .region
                    .as_ref()
                    .and_then(|region| region.start_line)
                    .filter(|line| *line > 0)
                    .unwrap_or(1);
                let message = nested
                    .message
                    .as_ref()
                    .and_then(|message| message.text.as_deref())
                    .and_then(non_empty_string)
                    .or_else(|| {
                        location
                            .message
                            .as_ref()
                            .and_then(|message| message.text.as_deref())
                            .and_then(non_empty_string)
                    })
                    .map(ToString::to_string);
                let snippet = physical
                    .region
                    .as_ref()
                    .and_then(|region| region.snippet.as_ref())
                    .and_then(|snippet| snippet.text.as_deref())
                    .and_then(non_empty_string)
                    .map(ToString::to_string);
                let step = CodeqlFlowStep {
                    file_path,
                    line,
                    message,
                    snippet,
                };
                if steps.last() != Some(&step) {
                    steps.push(step);
                }
            }
        }
    }
    steps
}
