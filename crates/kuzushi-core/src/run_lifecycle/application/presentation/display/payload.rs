use super::super::*;
use super::health::cost_label;

pub(super) fn display_lines(payload: &RunPresentationPayloadV1) -> Vec<String> {
    match payload {
        RunPresentationPayloadV1::Plan(value) => plan_lines(value),
        RunPresentationPayloadV1::Task(value) => task_lines(value),
        RunPresentationPayloadV1::ToolCall(value) => tool_call_lines(value),
        RunPresentationPayloadV1::ModelCall(value) => model_call_lines(value),
        RunPresentationPayloadV1::Artifact(value) => artifact_lines(value),
        RunPresentationPayloadV1::ResultSummary(value) => result_lines(value),
        RunPresentationPayloadV1::ResultHydrationIssue(value) => {
            vec![format!("Result unavailable · {}", value.detail)]
        }
        RunPresentationPayloadV1::FindingDelta(value) => finding_delta_lines(value),
        RunPresentationPayloadV1::Question(value) => question_lines(value),
        RunPresentationPayloadV1::Decision(value) => decision_lines(value),
        RunPresentationPayloadV1::Progress(value) => progress_lines(value),
        RunPresentationPayloadV1::SafeReasoning(value) => {
            vec![format!("Reasoning: {}", value.text)]
        }
        RunPresentationPayloadV1::Diagnostic(value) => {
            vec![format!("{:?}: {}", value.level, value.message)]
        }
        RunPresentationPayloadV1::Terminal(value) => terminal_lines(value),
        RunPresentationPayloadV1::PhaseReceipt(value) => phase_receipt_lines(value),
        RunPresentationPayloadV1::ProgressDisclosure(value) => vec![format!(
            "Progress: {} update(s) omitted at source",
            value.omitted_count
        )],
    }
}

fn plan_lines(value: &PlanPresentationV1) -> Vec<String> {
    vec![format!(
        "Plan r{} · {} · {}",
        value.revision,
        value.status.label(),
        value.title
    )]
}

fn task_lines(value: &TaskPresentationV1) -> Vec<String> {
    let detail = value
        .detail
        .as_ref()
        .map(|detail| format!(" · {detail}"))
        .unwrap_or_default();
    vec![format!(
        "Task {} · {} · {}{detail}",
        value.task_id,
        value.status.label(),
        value.title
    )]
}

fn tool_call_lines(value: &ToolCallPresentationV1) -> Vec<String> {
    let mut lines = vec![tool_call_heading(value)];
    lines.extend(value.preview.iter().map(|line| format!("  | {line}")));
    append_issue_counts(&mut lines, value.warning_count, value.error_count);
    if let Some(artifact) = value.result_artifact.as_ref() {
        lines.push(format!("  result: {} · {}", artifact.path, artifact.digest));
    }
    if let Some(rejection) = value.rejection.as_ref() {
        lines.push(format!(
            "  rejected: {} · {}",
            rejection.reason_class, rejection.detail
        ));
    }
    lines
}

fn tool_call_heading(value: &ToolCallPresentationV1) -> String {
    let runtime = optional_pair("runtime", value.runtime.as_ref());
    let model = optional_pair("model", value.model.as_ref());
    format!(
        "Call {} · tool · {} · {} · {}{}{}",
        value.call_id,
        value.status.label(),
        value.label,
        cost_label(value.cost),
        runtime,
        model
    )
}

fn append_issue_counts(lines: &mut Vec<String>, warnings: u64, errors: u64) {
    if warnings > 0 || errors > 0 {
        lines.push(format!("  warnings={warnings} errors={errors}"));
    }
}

fn model_call_lines(value: &ModelCallPresentationV1) -> Vec<String> {
    let provider = value
        .provider
        .as_ref()
        .map_or("provider unavailable", SafeText::as_str);
    let latency = value
        .latency_ms
        .map(|latency| format!("{latency}ms"))
        .unwrap_or_else(|| "latency unavailable".to_string());
    let mut line = format!(
        "Call {} · model · {} · {provider}/{} · {latency} · {} · {}",
        value.call_id,
        value.status.label(),
        value.model,
        usage_label(value.usage.as_ref()),
        cost_label(value.cost)
    );
    if let Some(error) = value.error_class.as_ref() {
        line.push_str(&format!(" · error={error}"));
    }
    vec![line]
}

fn result_lines(value: &ResultSummaryPresentationV1) -> Vec<String> {
    let mut lines = vec![format!(
        "Result · {} · {} · {}",
        value.tool, value.status, value.summary
    )];
    lines.extend(value.output_lines.iter().map(|line| format!("  | {line}")));
    lines.extend(
        value
            .warnings
            .iter()
            .map(|message| format!("  ⚠ {message}")),
    );
    lines.extend(value.errors.iter().map(|message| format!("  ✗ {message}")));
    append_result_artifacts(&mut lines, &value.artifacts);
    lines
}

fn append_result_artifacts(lines: &mut Vec<String>, artifacts: &[ResultArtifactPresentationV1]) {
    if artifacts.is_empty() {
        return;
    }
    let labels = artifacts
        .iter()
        .map(|artifact| format!("{}={}", artifact.label, artifact.path))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("  artifacts: {labels}"));
}

fn question_lines(value: &QuestionPresentationV1) -> Vec<String> {
    if value.state == QuestionPresentationStateV1::Resolved {
        return vec![format!(
            "Question {} · resolved · scope={}",
            value.question_id, value.authorization_scope
        )];
    }
    let choices = value
        .choices
        .iter()
        .map(|choice| format!("{}={}", choice.id, choice.label))
        .collect::<Vec<_>>()
        .join(", ");
    vec![format!(
        "Question {} · {} · scope={} · choices=[{}]",
        value.question_id,
        value
            .prompt
            .as_ref()
            .map_or("prompt unavailable", SafeText::as_str),
        value.authorization_scope,
        choices
    )]
}

fn decision_lines(value: &DecisionPresentationV1) -> Vec<String> {
    vec![format!(
        "Decision {} · {:?} · scope={}",
        value.question_id, value.decision, value.authorization_scope
    )]
}

fn progress_lines(value: &ProgressPresentationV1) -> Vec<String> {
    let amount = match (value.completed, value.total) {
        (Some(completed), Some(total)) => format!(" {completed}/{total}"),
        (Some(completed), None) => format!(" {completed}"),
        _ => String::new(),
    };
    vec![format!("Progress{amount} · {}", value.message)]
}

fn terminal_lines(value: &TerminalPresentationV1) -> Vec<String> {
    vec![
        format!("Outcome · {} · {}", value.status.label(), value.summary),
        format!("Cost · {}", cost_label(value.cost)),
        format!("NEXT · {}", value.continuation.operator_label()),
    ]
}

fn phase_receipt_lines(value: &PhaseReceiptPresentationV1) -> Vec<String> {
    vec![
        format!(
            "Receipt · {} · runs={} · artifacts={} · interactions={} · {}",
            value.status.label(),
            value.run_ids.len(),
            value.artifact_ids.len(),
            value.interaction_count,
            cost_label(value.cost)
        ),
        format!("Receipt NEXT · {}", value.continuation.operator_label()),
    ]
}

fn artifact_lines(artifact: &ArtifactReference) -> Vec<String> {
    vec![format!(
        "Artifact · {} · {} · {}",
        artifact.label, artifact.path, artifact.digest
    )]
}

fn finding_delta_lines(delta: &FindingDeltaSummary) -> Vec<String> {
    vec![format!(
        "Findings · +{} ~{} -{} · {}",
        delta.added, delta.updated, delta.removed, delta.store_watermark
    )]
}

fn optional_pair(label: &str, value: Option<&SafeText>) -> String {
    value
        .map(|value| format!(" · {label}={value}"))
        .unwrap_or_default()
}

fn usage_label(usage: Option<&ModelUsage>) -> String {
    let Some(usage) = usage else {
        return "usage unavailable".to_string();
    };
    match (usage.input_tokens, usage.output_tokens) {
        (None, None) => "usage unavailable".to_string(),
        (Some(input), Some(output)) => format!("tokens={input}+{output}"),
        (input, output) => format!(
            "tokens={}+{} incomplete",
            optional_count(input),
            optional_count(output)
        ),
    }
}

fn optional_count(value: Option<u64>) -> String {
    value.map_or_else(|| "?".to_string(), |value| value.to_string())
}
