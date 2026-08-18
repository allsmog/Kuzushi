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
            vec![format!(
                "{}    ↳ {}",
                event_time(value.occurred_at_ms),
                value.text
            )]
        }
        RunPresentationPayloadV1::Diagnostic(value) => {
            vec![format!(
                "{}  {} {}",
                event_time(value.occurred_at_ms),
                diagnostic_glyph(&value.level),
                value.message
            )]
        }
        RunPresentationPayloadV1::Terminal(value) => terminal_lines(value),
        RunPresentationPayloadV1::PhaseReceipt(value) => phase_receipt_lines(value),
        RunPresentationPayloadV1::ProgressDisclosure(value) => vec![format!(
            "Progress: {} update(s) omitted at source",
            value.omitted_count
        )],
        RunPresentationPayloadV1::LifecycleEvent(value) => lifecycle_event_lines(value),
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
    append_model_failure(&mut line, value.failure.as_ref());
    let mut lines = vec![line];
    if let Some(detail) = value.failure.as_ref().and_then(|failure| failure.detail.as_deref()) {
        lines.push(format!("  detail: {detail}"));
    }
    lines
}

fn append_model_failure(
    line: &mut String,
    failure: Option<&crate::runtime::RuntimeFailureMetadata>,
) {
    let Some(failure) = failure else { return };
    if let Some(stage) = failure.stage.as_deref() {
        line.push_str(&format!(" · stage={stage}"));
    }
    if let Some(status) = failure.http_status {
        line.push_str(&format!(" · http={status}"));
    }
}

fn result_lines(value: &ResultSummaryPresentationV1) -> Vec<String> {
    // Keep the friendly name for scanability and the registry key for the
    // operator who wants to repeat this exact capability from the shell.
    let mut lines = vec![format!(
        "Result · {} ({}) · {} · {}",
        crate::modules::tool_display_name(value.tool.as_str()),
        value.tool,
        value.status,
        value.summary
    )];
    // Single-line tool outputs are routinely the summary restated; echoing
    // that line as a preview row directly under the heading is pure noise.
    let summary_text = value.summary.as_str().trim();
    lines.extend(
        value
            .output_lines
            .iter()
            .filter(|line| line.as_str().trim() != summary_text)
            .map(|line| format!("  | {line}")),
    );
    // The output preview frequently already ends with the operator-facing
    // warning/error text; repeating it verbatim reads as a rendering bug.
    let previewed = value
        .output_lines
        .iter()
        .map(|line| line.as_str().trim())
        .collect::<std::collections::BTreeSet<_>>();
    lines.extend(
        value
            .warnings
            .iter()
            .filter(|message| !previewed.contains(message.as_str().trim()))
            .map(|message| format!("  ⚠ {message}")),
    );
    lines.extend(
        value
            .errors
            .iter()
            .filter(|message| !previewed.contains(message.as_str().trim()))
            .map(|message| format!("  ✗ {message}")),
    );
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
        (Some(completed), Some(total)) => format!(" · {completed}/{total}"),
        _ => String::new(),
    };
    vec![format!(
        "{}  ⠹ {}{amount}",
        event_time(value.occurred_at_ms),
        value.message
    )]
}

fn lifecycle_event_lines(value: &LifecycleEventPresentationV1) -> Vec<String> {
    let action = lifecycle_event_action(value);
    let detail = value
        .detail
        .as_ref()
        .map(|detail| format!(" · {detail}"))
        .unwrap_or_default();
    let metrics = lifecycle_event_metrics(value);
    vec![format!(
        "{}  {} {action}{detail}{metrics}",
        event_time(value.occurred_at_ms),
        lifecycle_event_glyph(value)
    )]
}

fn lifecycle_event_action(value: &LifecycleEventPresentationV1) -> String {
    use LifecycleEventKindV1::*;
    match value.kind {
        Plan => work_action("Plan", value),
        Task => work_action("", value),
        ToolRequested => format!("Queued {}", tool_label(&value.subject)),
        ToolRejected => format!("Blocked {} before start", tool_label(&value.subject)),
        ToolStarted => format!("{} started", tool_label(&value.subject)),
        ToolFinished => format!(
            "{} {}",
            tool_label(&value.subject),
            terminal_verb(value.status)
        ),
        ModelStarted => format!("Calling {}", value.subject),
        ModelFinished => format!(
            "Model call {} · {}",
            terminal_verb(value.status),
            value.subject
        ),
        ArtifactProduced => format!("Produced {}", value.subject),
        FindingsChanged => format!("Findings changed · {}", value.subject),
        OperatorQuestion if value.status == Some(RunItemStatus::Completed) => {
            format!("Asked operator · {}", value.subject)
        }
        OperatorQuestion => format!("Waiting for operator input · {}", value.subject),
        OperatorDecision => format!("Operator decision recorded · {}", value.subject),
        TerminalOutcome => format!("Run {} · {}", terminal_verb(value.status), value.subject),
        PhaseReceipt => format!("Phase receipt {}", terminal_verb(value.status)),
    }
}

fn work_action(prefix: &str, value: &LifecycleEventPresentationV1) -> String {
    let name = if prefix.is_empty() {
        value.subject.to_string()
    } else {
        format!("{prefix} · {}", value.subject)
    };
    match value.status {
        Some(RunItemStatus::Pending) => format!("Queued {name}"),
        Some(RunItemStatus::Running) => format!("{name} started"),
        status => format!("{name} {}", terminal_verb(status)),
    }
}

fn lifecycle_event_glyph(value: &LifecycleEventPresentationV1) -> &'static str {
    use LifecycleEventKindV1::*;
    match value.kind {
        OperatorQuestion => "?",
        OperatorDecision | ArtifactProduced | FindingsChanged => "✓",
        ToolStarted | ModelStarted => "→",
        ToolRequested => "·",
        _ => status_glyph(value.status),
    }
}

fn status_glyph(status: Option<RunItemStatus>) -> &'static str {
    match status {
        Some(RunItemStatus::Completed) => "✓",
        Some(RunItemStatus::Partial) => "⚠",
        Some(RunItemStatus::Skipped) => "⊘",
        Some(RunItemStatus::Blocked) => "▣",
        Some(RunItemStatus::Failed | RunItemStatus::Interrupted) => "✗",
        Some(RunItemStatus::Canceled) => "×",
        Some(RunItemStatus::Running) => "→",
        Some(RunItemStatus::Pending) | None => "·",
    }
}

fn terminal_verb(status: Option<RunItemStatus>) -> &'static str {
    match status {
        Some(RunItemStatus::Completed) => "completed",
        Some(RunItemStatus::Partial) => "partial",
        Some(RunItemStatus::Skipped) => "skipped",
        Some(RunItemStatus::Blocked) => "blocked",
        Some(RunItemStatus::Failed) => "failed",
        Some(RunItemStatus::Canceled) => "canceled",
        Some(RunItemStatus::Interrupted) => "interrupted",
        Some(RunItemStatus::Pending) => "queued",
        Some(RunItemStatus::Running) => "running",
        None => "updated",
    }
}

fn tool_label(value: &SafeText) -> String {
    crate::modules::tool_display_name(value.as_str())
}

fn lifecycle_event_metrics(value: &LifecycleEventPresentationV1) -> String {
    let latency = value
        .latency_ms
        .map(|latency| format!(" · {}", duration_label(latency)))
        .unwrap_or_default();
    let cost = value.cost.map_or_else(String::new, |cost| {
        if cost.is_unavailable() && value.kind == LifecycleEventKindV1::ToolFinished {
            String::new()
        } else {
            format!(" · {}", cost_label(cost))
        }
    });
    format!("{latency}{cost}")
}

fn duration_label(milliseconds: u64) -> String {
    if milliseconds < 1_000 {
        return format!("{milliseconds}ms");
    }
    format!("{:.1}s", milliseconds as f64 / 1_000.0)
}

fn event_time(milliseconds: u64) -> String {
    let seconds = milliseconds / 1_000;
    let hours = (seconds / 3_600) % 24;
    let minutes = (seconds / 60) % 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn diagnostic_glyph(level: &DiagnosticLevel) -> &'static str {
    match level {
        DiagnosticLevel::Info => "·",
        DiagnosticLevel::Warning => "⚠",
        DiagnosticLevel::Error => "✗",
    }
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
