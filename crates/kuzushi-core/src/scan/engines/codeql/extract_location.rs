use super::*;
use crate::findings::presentation::sarif_location::reported_path_from_sarif_uri;

pub(crate) fn extract_codeql_location(result: &CodeqlSarifResult) -> Option<(String, u32)> {
    // Skip locations missing a resolvable path instead of giving up on the
    // first malformed entry.
    result.locations.iter().find_map(location_path_and_line)
}

fn location_path_and_line(location: &CodeqlSarifLocation) -> Option<(String, u32)> {
    let physical = location.physical_location.as_ref()?;
    let file_path = reported_path_from_sarif_uri(physical_location_uri(physical)?)?;
    Some((file_path, physical_location_line(physical)))
}

/// The `artifactLocation.uri` a physical location reports, or `None` when it
/// reports none.
fn physical_location_uri(physical: &CodeqlPhysicalLocation) -> Option<&str> {
    physical
        .artifact_location
        .as_ref()?
        .uri
        .as_deref()
        .and_then(non_empty_string)
}

/// The line a physical location reports. A location without a positive
/// `region.startLine` is reported at line 1: CodeQL omits the region for a
/// whole-artifact result, and the reader has no finer place to put it.
fn physical_location_line(physical: &CodeqlPhysicalLocation) -> u32 {
    physical
        .region
        .as_ref()
        .and_then(|region| region.start_line)
        .filter(|line| *line > 0)
        .unwrap_or(1)
}

fn physical_location_snippet(physical: &CodeqlPhysicalLocation) -> Option<String> {
    physical
        .region
        .as_ref()
        .and_then(|region| region.snippet.as_ref())
        .and_then(|snippet| snippet.text.as_deref())
        .and_then(non_empty_string)
        .map(ToString::to_string)
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
    for step in thread_flow_steps(result) {
        if steps.last() != Some(&step) {
            steps.push(step);
        }
    }
    steps
}

/// Every step the result's code flows name, in document order, before
/// consecutive repeats of one step are folded.
fn thread_flow_steps(result: &CodeqlSarifResult) -> impl Iterator<Item = CodeqlFlowStep> + '_ {
    result
        .code_flows
        .iter()
        .flat_map(|code_flow| code_flow.thread_flows.iter())
        .flat_map(|thread_flow| thread_flow.locations.iter())
        .filter_map(thread_flow_step)
}

/// One step of a code flow, or `None` when the thread-flow location names no
/// path the reader can place the step at.
fn thread_flow_step(location: &CodeqlThreadFlowLocation) -> Option<CodeqlFlowStep> {
    let nested = location.location.as_ref()?;
    let physical = nested.physical_location.as_ref()?;
    Some(CodeqlFlowStep {
        file_path: reported_path_from_sarif_uri(physical_location_uri(physical)?)?,
        line: physical_location_line(physical),
        message: thread_flow_step_message(location, nested),
        snippet: physical_location_snippet(physical),
    })
}

/// The step's own message, falling back to the one the thread-flow location
/// carries beside it.
fn thread_flow_step_message(
    location: &CodeqlThreadFlowLocation,
    nested: &CodeqlNestedLocation,
) -> Option<String> {
    message_text(nested.message.as_ref()).or_else(|| message_text(location.message.as_ref()))
}

fn message_text(message: Option<&CodeqlSarifMessage>) -> Option<String> {
    message?
        .text
        .as_deref()
        .and_then(non_empty_string)
        .map(ToString::to_string)
}
