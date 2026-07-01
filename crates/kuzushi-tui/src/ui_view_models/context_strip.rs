use super::{
    active_stage_label, compact_target_path, context_snapshot_state, findings_count_summary,
    format_session_cost, routing_mode_segment, scoped_target_path_label, view_status_segment,
    ShellApp,
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
        context_present: app.context_view.exists,
        context_state: context_snapshot_state(app),
        model: model_segment_value(app),
        findings: findings_count_summary(&app.findings),
        view: view_status_segment(app),
        compact_activity: compact_activity_segment(app),
        activity: live_activity_segment(app),
        run: run_tool_segment(app),
        stage: stage_segment(app),
        cost: cost_segment_value(app),
    }
}

impl ContextStripModel {
    pub(crate) fn compact_segments(&self) -> Vec<String> {
        // Order by decision-relevance, not layout: on a narrow terminal the
        // strip is `fit()`-truncated from the right, so the model (the
        // no-silent-fallback safety fact) must precede the lower-stakes
        // target/ctx — which are also surfaced on the Home cockpit.
        let mut segments = vec![
            self.mode.clone(),
            format!("model:{}", self.model),
            format!("target:{}", self.target),
            self.context_state_segment(),
        ];
        if let Some(activity) = &self.compact_activity {
            segments.push(format!("activity:{activity}"));
        }
        if let Some(stage) = &self.stage {
            segments.push(format!("{}:{}", stage.label, stage.value));
        }
        if let Some(cost) = &self.cost {
            segments.push(format!("cost:{cost}"));
        }
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
    if app.target.is_some() {
        scoped_target_path_label(app)
    } else {
        "none".to_string()
    }
}

fn model_segment_value(app: &ShellApp) -> String {
    app.config
        .model
        .as_deref()
        .map(crate::app::display_model_selector)
        .unwrap_or_else(|| "unconfigured".to_string())
}

fn live_activity_segment(app: &ShellApp) -> Option<ContextStripSegment> {
    let activity = app.live_activity.as_ref()?;
    activity.phase.active().then(|| ContextStripSegment {
        label: "activity",
        value: format!("{} {}", app.spinner_glyph(), activity.short_label()),
    })
}

fn compact_activity_segment(app: &ShellApp) -> Option<String> {
    app.live_activity
        .as_ref()
        .map(|activity| activity.short_label())
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
        value: format!("{} {label}", stage_spinner(app.spinner_phase)),
    })
}

fn stage_spinner(phase: u8) -> &'static str {
    const FRAMES: &[&str] = &["⠿", "⠾", "⠷", "⠯", "⠟", "⠻"];
    FRAMES[(phase as usize) % FRAMES.len()]
}

fn cost_segment_value(app: &ShellApp) -> Option<String> {
    (app.session_cost_usd > 0.0).then(|| format_session_cost(app.session_cost_usd))
}

#[cfg(test)]
mod tests;
