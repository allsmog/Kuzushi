use super::{
    active_stage_label, compact_target_path, context_snapshot_state,
    findings_count_summary_with_total, format_session_cost, journey_footer_segment,
    routing_mode_segment, scoped_target_path_label, view_status_segment, ShellApp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextStripModel {
    pub(crate) mode: String,
    pub(crate) target: String,
    pub(crate) context_present: bool,
    pub(crate) context_state: &'static str,
    pub(crate) model: String,
    pub(crate) findings: String,
    pub(crate) view: String,
    pub(crate) phase: Option<String>,
    pub(crate) compact_activity: Option<String>,
    pub(crate) activity: Option<ContextStripSegment>,
    pub(crate) run: Option<ContextStripSegment>,
    pub(crate) stage: Option<ContextStripSegment>,
    pub(crate) cost: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextStripSegment {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

pub(crate) fn context_strip_model(app: &ShellApp) -> ContextStripModel {
    ContextStripModel {
        mode: routing_mode_segment(app),
        target: target_segment_value(app),
        context_present: app.domain().context_view().exists,
        context_state: context_snapshot_state(app),
        model: model_segment_value(app),
        findings: findings_count_summary_with_total(app.findings(), app.findings_total_count()),
        view: view_status_segment(app),
        phase: journey_footer_segment(app),
        compact_activity: compact_activity_segment(app),
        activity: live_activity_segment(app),
        run: run_tool_segment(app),
        stage: stage_segment(app),
        cost: cost_segment_value(app),
    }
}

impl ContextStripModel {
    pub(crate) fn compact_segments(&self) -> Vec<String> {
        let mut segments = vec![self.mode.clone(), format!("view:{}", self.view)];
        segments.extend(self.phase.iter().map(|phase| format!("phase:{phase}")));
        segments.extend([
            format!("target:{}", self.target),
            format!("model:{}", self.model),
            self.context_state_segment(),
        ]);
        segments.extend(
            self.compact_activity
                .iter()
                .map(|activity| format!("activity:{activity}")),
        );
        segments.extend(
            self.stage
                .iter()
                .map(|stage| format!("{}:{}", stage.label, stage.value)),
        );
        segments.extend(self.cost.iter().map(|cost| format!("cost:{cost}")));
        segments
    }

    pub(super) fn context_state_segment(&self) -> String {
        // The context snapshot is an optional repo index. Word the empty state
        // as an action ("not built") rather than an alarm ("missing") — scans
        // run fine without it; `context build` creates it.
        if self.context_state == "malformed" {
            "ctx:malformed".to_string()
        } else if self.context_present {
            "ctx:✓ built".to_string()
        } else {
            "ctx:not built".to_string()
        }
    }
}

fn target_segment_value(app: &ShellApp) -> String {
    if app.target().is_some() {
        scoped_target_path_label(app)
    } else {
        "none".to_string()
    }
}

fn model_segment_value(app: &ShellApp) -> String {
    app.config()
        .model
        .as_deref()
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string())
}

fn live_activity_segment(app: &ShellApp) -> Option<ContextStripSegment> {
    let activity = app.live_activity()?;
    activity.phase.active().then(|| ContextStripSegment {
        label: "activity",
        value: format!("{} {}", app.spinner_glyph(), activity.short_label()),
    })
}

fn compact_activity_segment(app: &ShellApp) -> Option<String> {
    app.live_activity().map(|activity| activity.short_label())
}

fn run_tool_segment(app: &ShellApp) -> Option<ContextStripSegment> {
    let tool_name = app.running_tool_name()?;
    Some(ContextStripSegment {
        label: "run",
        value: format!("{} {tool_name}", app.spinner_glyph()),
    })
}

fn stage_segment(app: &ShellApp) -> Option<ContextStripSegment> {
    let label = active_stage_label(app)?;
    Some(ContextStripSegment {
        label: "stage",
        value: format!("{} {label}", stage_spinner(app.ui().spinner_phase())),
    })
}

fn stage_spinner(phase: u8) -> &'static str {
    const FRAMES: &[&str] = &["⠿", "⠾", "⠷", "⠯", "⠟", "⠻"];
    FRAMES[(phase as usize) % FRAMES.len()]
}

fn cost_segment_value(app: &ShellApp) -> Option<String> {
    let cost = app.session().session_cost_usd();
    Some(format_session_cost(cost))
}

#[cfg(test)]
mod tests;
