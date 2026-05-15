use super::{
    active_stage_label, catalog_model, compact_target_path, findings_count_summary,
    format_session_cost, routing_mode_segment, view_status_segment, ShellApp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextStripModel {
    pub(crate) mode: String,
    pub(crate) target: String,
    pub(crate) context_present: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlainContextStripModel {
    pub(crate) rows: Vec<String>,
}

pub(crate) fn context_strip_model(app: &ShellApp) -> ContextStripModel {
    ContextStripModel {
        mode: routing_mode_segment(app),
        target: target_segment_value(app),
        context_present: app.context_view.exists,
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

pub(crate) fn plain_context_strip_model(app: &ShellApp, width: usize) -> PlainContextStripModel {
    let strip = context_strip_model(app);
    let module_count = catalog_model(app).module_count;
    PlainContextStripModel {
        rows: vec![plain_context_strip_line(&strip, module_count, width)],
    }
}

fn plain_context_strip_line(
    strip: &ContextStripModel,
    module_count: usize,
    width: usize,
) -> String {
    fit_plain_text(
        &format!(
            "{} | target:{} | {} | {} | {} mods",
            strip.mode, strip.target, strip.view, strip.findings, module_count
        ),
        width,
    )
}

fn fit_plain_text(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

impl ContextStripModel {
    pub(crate) fn compact_segments(&self) -> Vec<String> {
        let mut segments = vec![
            self.mode.clone(),
            format!("target {}", self.target),
            self.context_state(),
            format!("model {}", self.model),
            self.findings.clone(),
            format!("view {}", self.view),
        ];
        if let Some(activity) = &self.compact_activity {
            segments.push(format!("activity {activity}"));
        }
        if let Some(stage) = &self.stage {
            segments.push(format!("{} {}", stage.label, stage.value));
        }
        if let Some(cost) = &self.cost {
            segments.push(format!("cost {cost}"));
        }
        segments
    }

    fn context_state(&self) -> String {
        if self.context_present {
            "ctx ✓ present".to_string()
        } else {
            "ctx missing".to_string()
        }
    }
}

fn target_segment_value(app: &ShellApp) -> String {
    app.target
        .as_ref()
        .map(|path| compact_target_path(&path.display().to_string()))
        .unwrap_or_else(|| "none".to_string())
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
