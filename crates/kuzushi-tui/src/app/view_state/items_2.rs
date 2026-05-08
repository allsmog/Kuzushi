use super::prelude::*;
use super::*;

impl TuneAction {
    pub const ORDER: &'static [TuneAction] = &[
        TuneAction::ShowHouseRules,
        TuneAction::EditHouseRules,
        TuneAction::ResetHouseRules,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TuneAction::ShowHouseRules => "show house rules",
            TuneAction::EditHouseRules => "edit house rules (set \"...\")",
            TuneAction::ResetHouseRules => "reset house rules",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            TuneAction::ShowHouseRules => "log the current house-rules text into the transcript",
            TuneAction::EditHouseRules => {
                "prefill the prompt with `set \"\"` so you can type a value"
            }
            TuneAction::ResetHouseRules => "delete the house-rules file and revert to defaults",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActorDetailFilter {
    #[default]
    All,
    Findings,
    Errors,
    Tools,
}

impl ActorDetailFilter {
    pub fn label(self) -> &'static str {
        match self {
            ActorDetailFilter::All => "all",
            ActorDetailFilter::Findings => "findings",
            ActorDetailFilter::Errors => "errors",
            ActorDetailFilter::Tools => "tools",
        }
    }

    pub fn keeps(self, prefix: &str) -> bool {
        match self {
            ActorDetailFilter::All => true,
            ActorDetailFilter::Findings => prefix == "finding" || prefix == "title",
            ActorDetailFilter::Errors => prefix == "error",
            ActorDetailFilter::Tools => matches!(
                prefix,
                "scan" | "tool" | "agent" | "answer" | "plan" | "tune" | "prompt"
            ),
        }
    }

    pub fn next(self) -> Self {
        match self {
            ActorDetailFilter::All => ActorDetailFilter::Findings,
            ActorDetailFilter::Findings => ActorDetailFilter::Errors,
            ActorDetailFilter::Errors => ActorDetailFilter::Tools,
            ActorDetailFilter::Tools => ActorDetailFilter::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptsAction {
    Show,
    Edit,
    Diff,
    Reset,
    Set,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThreatPatch {
    pub goal: String,
    pub summary: String,
    pub patch: serde_json::Value,
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanPanelState {
    pub run_id: Option<String>,
    pub target: PathBuf,
    pub stage: String,
    pub findings_count: usize,
    pub running: bool,
    pub abort_requested: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionsView {
    pub tool_name: String,
    pub filter: OptionsFilter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionsFilter {
    Standard,
    Advanced,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SastTaskMode {
    Auto,
    Manual,
}
