use super::*;

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct LessonsRouteState {
    pub(crate) target: Option<PathBuf>,
    pub(crate) finding_id: Option<i64>,
    pub(crate) cursor: usize,
    pub(crate) pinned_id: Option<String>,
    pub(crate) offset: usize,
    pub(crate) selected: Vec<SelectedLesson>,
    pub(crate) form: Option<LessonForm>,
    pub(crate) replacement_form: Option<LessonForm>,
    pub(crate) form_visible: bool,
    pub(crate) notice: Option<String>,
    pub(crate) context_cursor: usize,
    pub(crate) context_selecting: bool,
    pub(crate) context_confirm: Option<LessonContextBase>,
    pub(crate) saved_context: Option<kuzushi_core::ThreatModelRef>,
    pub(crate) generation_study: Option<Box<crate::app::BatchScanConfig>>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SelectedLesson {
    pub(crate) reference: LessonRef,
    pub(crate) title: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LessonContextBase {
    pub(crate) reference: kuzushi_core::ThreatModelRef,
    pub(crate) label: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct LessonForm {
    pub(crate) target: PathBuf,
    pub(crate) action: LessonFormAction,
    pub(crate) fields: [FieldEditor; 4],
    initial_text: [String; 4],
    pub(crate) focused: usize,
    pub(crate) confirming: bool,
}

impl LessonForm {
    pub(super) fn new(target: PathBuf, action: LessonFormAction, fields: [FieldEditor; 4]) -> Self {
        let initial_text = std::array::from_fn(|index| fields[index].text().to_owned());
        Self {
            target,
            action,
            fields,
            initial_text,
            focused: 0,
            confirming: false,
        }
    }

    pub(super) fn has_unsaved_changes(&self) -> bool {
        self.fields
            .iter()
            .zip(&self.initial_text)
            .any(|(field, original)| field.text() != original)
    }
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
