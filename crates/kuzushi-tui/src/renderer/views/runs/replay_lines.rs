use super::*;
use crate::ui_view_models::{replay_model, trace_model, RunArtifactDetail};

pub(crate) fn replay_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let model = replay_model(app, run_id);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("REPLAY", area.width));
    lines.push(detail("run", &model.run_id));
    let typed = model.presentation.as_ref().is_some_and(|presentation| {
        presentation.source == kuzushi_core::run_lifecycle::RunProjectionSource::TypedV1
    });
    if let Some(presentation) = model.presentation.as_ref() {
        append_run_presentation(&mut lines, presentation, area.width);
    } else if let Some(error) = model.projection_error.as_deref() {
        lines.push(muted(&format!("semantic replay unavailable: {error}")));
    } else {
        lines.push(muted("semantic replay loading…"));
    }
    if !typed {
        append_run_artifacts(&mut lines, &model.artifacts, area.width);
        append_recon_evidence(&mut lines, model.recon.as_ref(), area.width);
    }
    if model.metadata_missing {
        lines.push(blank());
        lines.push(muted(
            "(run artefacts not on disk; check `show runs` for valid runIds)",
        ));
    }
    lines.extend(alias_reference_lines(app, area));
    lines
}

fn append_run_presentation(
    lines: &mut Vec<Line<'static>>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: u16,
) {
    for overview in presentation.overview_lines().into_iter().skip(1) {
        lines.push(muted(&overview));
    }
    append_presentation_summary(lines, presentation, width);
    append_presentation_timeline(lines, presentation, width);
}

fn append_presentation_summary(
    lines: &mut Vec<Line<'static>>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: u16,
) {
    let mut active_section = None;
    for row in presentation.summary_text_rows() {
        if row.section != active_section {
            lines.push(blank());
            if let Some(section) = row.section.as_ref() {
                lines.push(divider(section.label(), width));
            }
            active_section = row.section.clone();
        }
        lines.push(presentation_row_line(row));
    }
}

fn append_presentation_timeline(
    lines: &mut Vec<Line<'static>>,
    presentation: &kuzushi_core::run_lifecycle::RunPresentationV1,
    width: u16,
) {
    let rows = presentation.timeline_text_rows();
    if rows.is_empty() {
        return;
    }
    lines.push(blank());
    lines.push(divider("TIMELINE", width));
    lines.extend(rows.into_iter().map(presentation_row_line));
}

fn presentation_row_line(
    row: kuzushi_core::run_lifecycle::RunPresentationTextRowV1,
) -> Line<'static> {
    use kuzushi_core::run_lifecycle::RunCellImportanceV1;
    let _source_key = row.key;
    match row.importance {
        RunCellImportanceV1::Essential => styled(&row.text, theme::primary()),
        RunCellImportanceV1::Detail | RunCellImportanceV1::Diagnostic => muted(&row.text),
    }
}

fn append_recon_evidence(
    lines: &mut Vec<Line<'static>>,
    snapshot: Option<&crate::ReconSnapshot>,
    width: u16,
) {
    let Some(snapshot) = snapshot else {
        return;
    };
    lines.push(blank());
    lines.push(divider("RECON EVIDENCE", width));
    lines.push(detail(
        "source",
        snapshot.last_tool.as_deref().unwrap_or("recon"),
    ));
    lines.push(detail(
        "counts",
        &format!(
            "{} hosts · {} services · {} notes",
            snapshot.hosts.len(),
            snapshot.services.len(),
            snapshot.notes.len()
        ),
    ));
    lines.extend(recon_snapshot_activity_lines(snapshot, 8));
    let overflow = replay_recon_row_count(snapshot).saturating_sub(8);
    if overflow > 0 {
        lines.push(muted(&format!("(+{overflow} more recon evidence rows)")));
    }
}

fn replay_recon_row_count(snapshot: &crate::ReconSnapshot) -> usize {
    let assets = if snapshot.services.is_empty() {
        snapshot.hosts.len()
    } else {
        snapshot.services.len()
    };
    assets + snapshot.notes.len()
}

pub(crate) fn trace_lines(app: &ShellApp, area: Rect, run_id: &str) -> Vec<Line<'static>> {
    let model = trace_model(app, run_id);
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider(&format!("TRACE · {}", model.run_id), area.width));
    lines.push(detail("run", &model.run_id));
    append_run_artifacts(&mut lines, &model.artifacts, area.width);
    // Keep copyable finding aliases above the potentially long step list so
    // compact Trace views preserve the operator's navigation references.
    lines.extend(alias_reference_lines(app, area));

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
    lines
}

fn append_run_artifacts(
    lines: &mut Vec<Line<'static>>,
    artifacts: &[RunArtifactDetail],
    width: u16,
) {
    for artifact in artifacts {
        lines.push(detail(artifact.label, &run_artifact_value(artifact, width)));
    }
}

fn run_artifact_value(artifact: &RunArtifactDetail, width: u16) -> String {
    const DETAIL_KEY_COLUMNS: usize = 19;
    let budget = (width as usize).saturating_sub(DETAIL_KEY_COLUMNS);
    let state = artifact
        .state_label()
        .map(|label| format!("{label} · "))
        .unwrap_or_default();
    let path_budget = budget.saturating_sub(display_width(&state));
    format!("{state}{}", fit_path(&artifact.detail, path_budget))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn missing_trace_artifact_rows_lead_with_state_and_preserve_path_tail() {
        let temp = tempfile::tempdir().expect("trace target");
        let target = temp
            .path()
            .join("very-long-workspace-segment-for-trace-rendering")
            .join("nested-target");
        std::fs::create_dir_all(&target).expect("nested trace target");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(target));
        app.open_trace_for_test("run-with-a-long-artifact-directory");
        app.hydrate_active_view_blocking();

        for width in [80, 110] {
            let lines = trace_lines(
                &app,
                Rect::new(0, 0, width, 30),
                "run-with-a-long-artifact-directory",
            );
            for leaf in ["triage.jsonl", "verify.jsonl", "patch.jsonl"] {
                let row = lines
                    .iter()
                    .map(rendered_line_text)
                    .find(|line| line.contains(leaf))
                    .unwrap_or_else(|| panic!("{width}-column row missing {leaf}"));
                assert!(row.contains("MISSING · "), "{width}: {row}");
                assert!(row.contains('…'), "{width}: {row}");
                assert!(row.trim_end().ends_with(leaf), "{width}: {row}");
            }
        }
    }

    #[test]
    fn replay_renders_structured_recon_result_evidence() {
        let temp = tempfile::tempdir().expect("replay target");
        let run_id = "run-recon-replay";
        let run_dir = kuzushi_core::run_dir(temp.path(), run_id);
        std::fs::create_dir_all(&run_dir).expect("run dir");
        std::fs::write(
            run_dir.join("result.json"),
            serde_json::to_vec_pretty(&recon_result()).expect("result json"),
        )
        .expect("write result");
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_target(Some(temp.path().to_path_buf()));
        app.open_replay_for_test(run_id);
        app.hydrate_active_view_blocking();

        let rendered = replay_lines(&app, Rect::new(0, 0, 120, 40), run_id)
            .iter()
            .map(rendered_line_text)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("RECON EVIDENCE"), "{rendered}");
        assert!(rendered.contains("acme.example"), "{rendered}");
        assert!(rendered.contains("443"), "{rendered}");
        assert!(rendered.contains("status-code"), "{rendered}");
    }

    fn recon_result() -> serde_json::Value {
        serde_json::json!({
            "ok": true,
            "data": {
                "tool": "recon:import", "target": "httpx.json",
                "hosts": [{
                    "id": "h1", "workspaceId": "ws", "address": "192.0.2.10",
                    "hostname": "acme.example", "state": "alive"
                }],
                "services": [{
                    "id": "s1", "hostId": "h1", "port": 443, "proto": "tcp",
                    "name": "https", "state": "open"
                }],
                "notes": [{
                    "id": "n1", "workspaceId": "ws", "hostId": "h1",
                    "serviceId": "s1", "ntype": "httpx", "data": { "status-code": 200 }
                }]
            }
        })
    }

    fn rendered_line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }
}
