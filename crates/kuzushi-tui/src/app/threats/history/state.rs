use crate::app::ShellView;
use kuzushi_core::ThreatModelRef;
use serde_json::Value;
use std::{path::PathBuf, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContextHistoryRequest {
    Read(ThreatModelRef),
    Compare {
        baseline: ThreatModelRef,
        candidate: ThreatModelRef,
    },
}

impl ContextHistoryRequest {
    pub(crate) fn tool(&self) -> &'static str {
        match self {
            Self::Read(_) => "threat-model:read",
            Self::Compare { .. } => "threat-model:diff",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextHistoryState {
    pub(crate) target: PathBuf,
    pub(crate) receipt_target: PathBuf,
    pub(crate) origin: ShellView,
    pub(crate) origin_threat_view: crate::app::ThreatView,
    pub(crate) origin_scroll: u16,
    pub(crate) open: bool,
    pub(crate) selected: Option<ThreatModelRef>,
    pub(crate) selected_label: Option<String>,
    pub(crate) baseline: Option<ThreatModelRef>,
    pub(crate) baseline_label: Option<String>,
    pub(crate) request: Option<ContextHistoryRequest>,
    pub(crate) data: Option<Arc<Value>>,
    pub(crate) error: Option<String>,
    pub(crate) scroll: usize,
    pub(crate) list_scroll: usize,
    pub(crate) pending_write: Option<(String, ThreatModelRef, String)>,
    pub(crate) notice: Option<String>,
    pub(crate) document_raw: bool,
    pub(crate) summary_scroll: usize,
    pub(crate) document_scroll: usize,
}

impl ContextHistoryState {
    pub(crate) fn new(target: PathBuf, origin: ShellView) -> Self {
        Self {
            receipt_target: target.clone(),
            target,
            origin,
            origin_threat_view: crate::app::ThreatView::Summary,
            origin_scroll: 0,
            open: true,
            selected: None,
            selected_label: None,
            baseline: None,
            baseline_label: None,
            request: None,
            data: None,
            error: None,
            scroll: 0,
            list_scroll: 0,
            pending_write: None,
            notice: None,
            document_raw: false,
            summary_scroll: 0,
            document_scroll: 0,
        }
    }

    pub(crate) fn begin(&mut self, request: ContextHistoryRequest) {
        self.request = Some(request);
        self.data = None;
        self.error = None;
        self.scroll = 0;
        self.document_raw = false;
        self.summary_scroll = 0;
        self.document_scroll = 0;
    }

    pub(crate) fn back_to_list(&mut self) {
        self.request = None;
        self.data = None;
        self.error = None;
        self.scroll = self.list_scroll;
    }
}
