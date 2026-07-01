use kuzushi_core::RunTargetGitMetadata;
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenContext {
    pub(crate) view: String,
    pub(crate) focused_pane: Option<String>,
    pub(crate) selected_item: Option<ScreenSelectedItem>,
    pub(crate) selected_run: Option<String>,
    pub(crate) selected_revision: Option<ScreenRevision>,
    pub(crate) active_phase: Option<String>,
    pub(crate) active_filters: Vec<String>,
    pub(crate) selected_scope: Option<String>,
    pub(crate) visible_rows: Vec<String>,
    pub(crate) cursor: ScreenCursor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenSelectedItem {
    pub(crate) alias: Option<String>,
    pub(crate) fingerprint: String,
    pub(crate) title: String,
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) rank: String,
    pub(crate) state: String,
    pub(crate) confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenRevision {
    pub(crate) sha: String,
    pub(crate) branch: Option<String>,
    pub(crate) dirty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScreenCursor {
    pub(crate) row: usize,
    pub(crate) col: usize,
}

impl ScreenContext {
    pub(crate) fn to_prompt_json(&self) -> String {
        serde_json::to_string_pretty(&self.as_json_value()).unwrap_or_else(|_| "{}".to_string())
    }

    fn as_json_value(&self) -> Value {
        json!({
            "view": self.view,
            "focusedPane": self.focused_pane,
            "selectedItem": self.selected_item.as_ref().map(ScreenSelectedItem::as_json_value),
            "selectedRun": self.selected_run,
            "selectedRevision": self.selected_revision.as_ref().map(ScreenRevision::as_json_value),
            "activePhase": self.active_phase,
            "activeFilters": self.active_filters,
            "selectedScope": self.selected_scope,
            "visibleRows": self.visible_rows,
            "cursor": {
                "row": self.cursor.row,
                "col": self.cursor.col,
            },
        })
    }
}

impl ScreenSelectedItem {
    fn as_json_value(&self) -> Value {
        json!({
            "alias": self.alias,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "rank": self.rank,
            "state": self.state,
            "confirmation": self.confirmation,
        })
    }
}

impl ScreenRevision {
    fn as_json_value(&self) -> Value {
        json!({
            "sha": self.sha,
            "branch": self.branch,
            "dirty": self.dirty,
        })
    }
}

impl From<RunTargetGitMetadata> for ScreenRevision {
    fn from(metadata: RunTargetGitMetadata) -> Self {
        Self {
            sha: metadata.sha,
            branch: metadata.branch,
            dirty: metadata.dirty,
        }
    }
}
