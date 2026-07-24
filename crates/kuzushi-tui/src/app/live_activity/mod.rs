use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveActivityPhase {
    CallingModel,
    Reading,
    Searching,
    RunningTool,
    WritingArtifact,
    Waiting,
    Paused,
    Partial,
    Skipped,
    Failed,
    Refused,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveActivity {
    pub phase: LiveActivityPhase,
    pub subject: String,
    pub detail: String,
}

impl LiveActivity {
    pub fn new(
        phase: LiveActivityPhase,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    pub fn transcript_line(&self) -> String {
        format!("{}: {} - {}", self.phase.label(), self.subject, self.detail)
    }

    pub fn short_label(&self) -> String {
        format!("{} {}", self.phase.label(), self.subject)
    }
}

impl LiveActivityPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::CallingModel => "calling model",
            Self::Reading => "reading",
            Self::Searching => "searching",
            Self::RunningTool => "running tool",
            Self::WritingArtifact => "writing artifact",
            Self::Waiting => "waiting",
            Self::Paused => "paused",
            Self::Partial => "partial",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::Refused => "refused",
            Self::Completed => "completed",
        }
    }

    pub fn active(self) -> bool {
        !matches!(
            self,
            Self::Completed | Self::Partial | Self::Skipped | Self::Failed | Self::Refused
        )
    }
}

impl ShellApp {
    pub(crate) fn set_live_activity(&mut self, activity: LiveActivity) {
        let line = activity.transcript_line();
        self.set_live_activity_state(Some(activity));
        self.log("activity", line);
    }

    pub(crate) fn set_waiting_activity(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Waiting,
            subject,
            detail,
        ));
    }

    pub(crate) fn set_paused_activity(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Paused,
            subject,
            detail,
        ));
    }

    pub(crate) fn set_completed_activity(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.mark_activity_session_terminal();
        // Clear the live strip indicator, but don't echo a low-value
        // "activity completed" line into the transcript — the DAG ✓ and the
        // tool's own `result` line already convey completion.
        self.set_live_activity_state(Some(LiveActivity::new(
            LiveActivityPhase::Completed,
            subject,
            detail,
        )));
    }

    pub(crate) fn set_refused_activity(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.mark_activity_session_terminal();
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Refused,
            subject,
            detail,
        ));
    }

    pub(crate) fn set_partial_activity(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.mark_activity_session_terminal();
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Partial,
            subject,
            detail,
        ));
    }

    pub(crate) fn set_skipped_activity(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.mark_activity_session_terminal();
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Skipped,
            subject,
            detail,
        ));
    }

    pub(crate) fn set_failed_activity(
        &mut self,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.mark_activity_session_terminal();
        self.set_live_activity(LiveActivity::new(
            LiveActivityPhase::Failed,
            subject,
            detail,
        ));
    }

    fn mark_activity_session_terminal(&mut self) {
        if let Some(session) = self.activity_mut() {
            session.mark_terminal();
        }
    }
}

pub(crate) fn live_activity_for_tool(tool_name: &str, status: &str) -> LiveActivity {
    LiveActivity::new(
        live_activity_phase_for_tool(tool_name),
        tool_name,
        status.to_string(),
    )
}

pub(crate) fn live_activity_for_prereq_step(step: &PrereqStep, final_tool: &str) -> LiveActivity {
    let writes = step
        .writes
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    LiveActivity::new(
        LiveActivityPhase::WritingArtifact,
        step.tool.clone(),
        format!("approved prerequisite for {final_tool}; writes {writes}"),
    )
}

fn live_activity_phase_for_tool(tool_name: &str) -> LiveActivityPhase {
    if model_backed_tool(tool_name) {
        return LiveActivityPhase::CallingModel;
    }
    if reading_tool(tool_name) {
        return LiveActivityPhase::Reading;
    }
    if searching_tool(tool_name) {
        return LiveActivityPhase::Searching;
    }
    LiveActivityPhase::RunningTool
}

fn model_backed_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "triage:run"
            | "verify:finding"
            | "patch:finding"
            | "agentic-sast:scan"
            | "carlini-threat-hunt:run"
            | "offense-review:threat-hunt"
            | "threat-model:build"
            | "vendor-assessment:assess"
            | "systems-hunt:systems-invariant-extract"
            | "systems-hunt:systems-trigger-synth"
            | "systems-hunt:systems-hunt"
            | "systems-hunt:deep-semantic-cwe-select"
            | "systems-hunt:deep-semantic-hunt"
            | "taint-iris:hunt"
            | "taint-iris-next:finding-review"
            | "taint-iris-next:hunt"
            | "randori:pasta"
            | "x-ray:run"
            | "x-ray:x-ray"
    )
}

fn reading_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "context:build" | "context-lite:index" | "findings:list"
    )
}

fn searching_tool(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "sast:scan"
            | "semgrep:scan"
            | "codeql:scan"
            | "iac-scan:scan"
            | "license-scan:scan"
            | "cargo-audit:scan"
            | "govulncheck:scan"
            | "secret-scan:scan"
            | "recon:http-fingerprint"
            | "recon:nmap"
    )
}
