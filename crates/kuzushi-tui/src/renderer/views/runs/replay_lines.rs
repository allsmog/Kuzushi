use super::*;
use crate::ui_view_models::{replay_model, trace_model, RunArtifactDetail};

pub(crate) fn replay_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let model = replay_model(app, run_id);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPLAY", area.width));
    lines.push(detail("run", &model.run_id));
    append_run_artifacts(&mut lines, &model.artifacts);
    if model.metadata_missing {
        lines.push(blank());
        lines.push(muted(
            "(run artefacts not on disk; check `show runs` for valid runIds)",
        ));
    }
    lines.extend(alias_reference_lines(app, area));
    lines
}

pub(crate) fn trace_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let model = trace_model(app, run_id);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(&format!("TRACE · {}", model.run_id), area.width));
    lines.push(detail("run", &model.run_id));
    append_run_artifacts(&mut lines, &model.artifacts);

    // STEPS section per `design/mockups/trace.jsx::step` — one row per
    // agent step with kind-tinted column + label + latency + cost.
    if model.steps.is_empty() {
        lines.push(blank());
        if model.trace_exists {
            lines.push(muted("(trace.jsonl is empty)"));
        } else {
            lines.push(muted(
                "(no trace.jsonl on disk; trace artefacts ship with agentic / patch / verify runs)",
            ));
        }
    } else {
        lines.push(blank());
        lines.push(divider("STEPS", area.width));
        for step in &model.steps {
            lines.push(trace_step_line(step, area.width));
        }
    }
    lines.extend(alias_reference_lines(app, area));
    lines
}

fn append_run_artifacts(lines: &mut Vec<Line<'static>>, artifacts: &[RunArtifactDetail]) {
    for artifact in artifacts {
        lines.push(detail(artifact.label, &artifact.detail));
    }
}
