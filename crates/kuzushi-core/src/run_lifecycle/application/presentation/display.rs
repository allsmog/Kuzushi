use super::*;

mod health;
mod payload;

pub use health::cost_label;

impl RunPresentationV1 {
    pub fn semantic_keys(&self) -> BTreeSet<RunCellKey> {
        self.summary
            .iter()
            .flat_map(|section| section.cells.iter())
            .chain(self.timeline.iter())
            .map(|cell| cell.key.clone())
            .collect()
    }

    pub fn overview_lines(&self) -> Vec<String> {
        let run_id = self
            .run_id
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        let mut lines = vec![format!("Run {run_id} · {}", source_label(&self.source))];
        lines.extend(health::health_lines(&self.health));
        lines
    }

    pub fn summary_text_rows(&self) -> Vec<RunPresentationTextRowV1> {
        self.summary
            .iter()
            .flat_map(|section| {
                section
                    .cells
                    .iter()
                    .flat_map(|cell| text_rows_for_cell(cell, Some(section.kind.clone())))
            })
            .collect()
    }

    pub fn timeline_text_rows(&self) -> Vec<RunPresentationTextRowV1> {
        self.timeline
            .iter()
            .flat_map(|cell| text_rows_for_cell(cell, None))
            .collect()
    }
}

impl RunPresentationCellV1 {
    pub fn display_lines(&self) -> Vec<String> {
        let mut lines = self.payload.display_lines();
        if let Some(disclosure) = self.disclosure.as_ref() {
            lines.push(disclosure_line(disclosure));
        }
        lines
    }
}

impl RunPresentationPayloadV1 {
    pub fn display_lines(&self) -> Vec<String> {
        payload::display_lines(self)
    }

    fn status(&self) -> Option<RunItemStatus> {
        match self {
            Self::Plan(value) => Some(value.status),
            Self::Task(value) => Some(value.status),
            Self::ToolCall(value) => Some(value.status),
            Self::ModelCall(value) => Some(value.status),
            Self::Terminal(value) => Some(value.status),
            Self::PhaseReceipt(value) => Some(value.status),
            _ => None,
        }
    }

    fn diagnostic_level(&self) -> Option<DiagnosticLevel> {
        match self {
            Self::Diagnostic(value) => Some(value.level.clone()),
            Self::ResultHydrationIssue(_) => Some(DiagnosticLevel::Error),
            _ => None,
        }
    }
}

fn text_rows_for_cell(
    cell: &RunPresentationCellV1,
    section: Option<RunPresentationSectionKindV1>,
) -> Vec<RunPresentationTextRowV1> {
    cell.display_lines()
        .into_iter()
        .map(|text| RunPresentationTextRowV1 {
            key: cell.key.clone(),
            section: section.clone(),
            importance: cell.importance,
            status: cell.payload.status(),
            diagnostic_level: cell.payload.diagnostic_level(),
            text,
        })
        .collect()
}

fn source_label(source: &RunProjectionSource) -> &'static str {
    match source {
        RunProjectionSource::TypedV1 => "typed v1",
        RunProjectionSource::Legacy => "legacy lossy",
    }
}

fn disclosure_line(disclosure: &RunCellDisclosureV1) -> String {
    let count = disclosure
        .omitted_count
        .map(|count| format!(" · omitted={count}"))
        .unwrap_or_default();
    let action = disclosure
        .inspect_action
        .as_ref()
        .map(|action| format!(" · {}", action.operator_label()))
        .unwrap_or_default();
    format!("Disclosure · {}{count}{action}", disclosure.reason)
}
