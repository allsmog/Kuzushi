use super::*;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct LessonsRouteState {
    pub(crate) target: Option<PathBuf>,
    pub(crate) finding_id: Option<i64>,
    pub(crate) cursor: usize,
    pub(crate) pinned_id: Option<String>,
    pub(crate) offset: usize,
    pub(crate) selected: Vec<LessonRef>,
    pub(crate) form: Option<LessonForm>,
    pub(crate) form_visible: bool,
    pub(crate) notice: Option<String>,
    pub(crate) context_cursor: usize,
    pub(crate) context_selecting: bool,
    pub(crate) context_confirm: Option<kuzushi_core::ThreatModelRef>,
    pub(crate) saved_context: Option<kuzushi_core::ThreatModelRef>,
    pub(crate) generation_study: Option<Box<crate::app::BatchScanConfig>>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LessonForm {
    pub(crate) target: PathBuf,
    pub(crate) action: LessonFormAction,
    pub(crate) fields: [FieldEditor; 4],
    pub(crate) focused: usize,
    pub(crate) confirming: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LessonFormAction {
    Draft {
        finding_id: Option<i64>,
        reference: Option<LessonRef>,
    },
    Review {
        record: FindingLesson,
        state: LessonState,
    },
}

pub(crate) struct LessonWrite {
    pub(crate) target: PathBuf,
    pub(crate) action: &'static str,
    pub(crate) handle: std::thread::JoinHandle<Result<serde_json::Value, String>>,
}

impl std::fmt::Debug for LessonWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LessonWrite")
            .field("target", &self.target)
            .field("action", &self.action)
            .finish()
    }
}
