//! The same text explains goal relevance in terminal and plain output.
use crate::app::goal_review::{GoalReviewState, GOAL_FILTERS};

pub(crate) fn heading(state: &GoalReviewState) -> String {
    if let Some(form) = state.form.as_ref().filter(|_| state.editing) {
        return format!(
            "GOAL RELEVANCE · assessment\n{} v{} · {}",
            form.brief.reference.brief_id,
            form.brief.reference.revision,
            form.relevance.label()
        );
    }
    let Some(Ok(page)) = &state.page else {
        return "GOAL RELEVANCE · workspace".into();
    };
    let brief = page
        .brief
        .as_ref()
        .map(|brief| format!("{} v{}", brief.reference.brief_id, brief.reference.revision))
        .unwrap_or_else(|| "No saved brief".into());
    format!(
        "GOAL RELEVANCE · workspace\nRows {}-{} / {} · {} · {brief}",
        page.offset + usize::from(!page.rows.is_empty()),
        page.offset + page.rows.len(),
        page.total,
        GOAL_FILTERS[state.filter]
    )
}

pub(crate) fn controls(state: &GoalReviewState) -> &'static str {
    if state.show_history {
        return "h or Esc return · PgUp/PgDn read";
    }
    if state.discarding {
        return "Enter discard draft · Esc keep draft";
    }
    if state.editing {
        return if state.form.as_ref().is_some_and(|form| form.confirming) {
            "Enter save · Esc edit · PgUp/PgDn read"
        } else {
            "Ctrl+S review · Enter new line · Esc retain draft"
        };
    }
    "1 direct · 2 related · 3 outside\n4 uncertain · u clear · ? keys\nj/k select · PgUp/PgDn read\nf filter · Esc return"
}

pub(crate) fn reason_heading(
    state: &GoalReviewState,
    form: &crate::app::goal_review::GoalAssessmentForm,
) -> String {
    safe(&state.notice.clone().unwrap_or_else(|| {
        format!(
            "{} · {}:{}\n{}",
            form.relevance.label(),
            form.row.finding.file_path,
            form.row.finding.start_line,
            form.row.finding.title
        )
    }))
}

pub(crate) fn detail(state: &GoalReviewState) -> Vec<String> {
    detail_text(state)
        .into_iter()
        .map(|line| safe(&line))
        .collect()
}

fn detail_text(state: &GoalReviewState) -> Vec<String> {
    if state.discarding {
        return vec![
            "DISCARD UNSAVED GOAL ASSESSMENT?".into(),
            "Only this draft is discarded. Recorded assessments and findings stay intact.".into(),
        ];
    }
    if state.show_keys {
        return vec!["GOAL REVIEW CONTROLS".into(), controls_full().into()];
    }
    if state.editing {
        return form_lines(state);
    }
    history_or_page(state)
}

fn history_or_page(state: &GoalReviewState) -> Vec<String> {
    if !state.show_history {
        return page_or_error(state);
    }
    let mut lines = vec![format!(
        "GOAL ASSESSMENT HISTORY · generation #{}",
        state.history_id.unwrap_or_default()
    )];
    match &state.history {
        None => lines.push("Reading recorded assessment revisions...".into()),
        Some(Err(error)) => lines.push(format!("History unavailable: {error}")),
        Some(Ok(rows)) => lines.extend(history_rows(rows)),
    }
    lines
}

fn history_rows(rows: &[kuzushi_core::findings::FindingGoalAssessment]) -> Vec<String> {
    if rows.is_empty() {
        return vec!["No recorded goal assessments for this generation.".into()];
    }
    rows.iter().map(|record| format!("{} v{} · {} · assessment v{}\nReason: {}\nObserved run: {} · source snapshot {}\nReviewed goal: {}\n", record.brief_ref.brief_id, record.brief_ref.revision, record.relevance.label(), record.revision, record.reason, record.basis.run_id, record.basis.snapshot_hash, record.brief_text)).collect()
}

fn page_or_error(state: &GoalReviewState) -> Vec<String> {
    match &state.page {
        Some(Ok(page)) => page_detail(state, page),
        Some(Err(error)) => vec![format!("Goal review unavailable: {error}. r retries.")],
        None => vec!["Reading saved goal and findings...".into()],
    }
}

fn page_detail(
    state: &GoalReviewState,
    page: &kuzushi_core::findings::FindingGoalPage,
) -> Vec<String> {
    let Some(brief) = &page.brief else {
        return vec!["No saved investigation brief.".into(), "Use scan batch, then Goal and priorities to write and save a brief. Saving goals starts no work.".into()];
    };
    if state.show_brief {
        return vec![
            "EXACT SAVED BRIEF".into(),
            brief.document.text.clone(),
            format!(
                "Brief revision {}. R explicitly opens the latest saved revision.",
                brief.reference.revision
            ),
        ];
    }
    let Some(row) = state.selected() else {
        return vec![if page.rows.is_empty() {
            "No findings in this goal view. f changes the filter.".into()
        } else {
            "Selected finding left this page. j/k explicitly selects a visible row before assessment.".into()
        }];
    };
    let mut lines = finding_detail(row);
    if state.show_receipt {
        lines.extend(receipt(&brief.reference, row));
    }
    lines
}

fn finding_detail(row: &kuzushi_core::findings::FindingGoalRow) -> Vec<String> {
    let mut lines = vec![
        row.finding.title.clone(),
        format!(
            "{}:{} · {}",
            row.finding.file_path,
            row.finding.start_line,
            row.finding.severity.as_str()
        ),
        format!("Relevance: {}", row.label()),
        "Priority only. Severity, confidence and finding verdicts are unchanged.".into(),
    ];
    if let Some(record) = &row.assessment {
        lines.push(format!("Reason: {}", record.reason));
        lines.push(format!(
            "Operator assessment v{} · {}",
            record.revision,
            super::recorded_timestamp_label(&record.recorded_at)
        ));
    }
    lines.push("Based on a recorded observation. The current checkout has not been reassessed by this action.".into());
    lines.push(row.finding.message.clone());
    lines
}

pub(crate) fn controls_full() -> &'static str {
    "1 direct: answers the reviewed goal\n2 related: relevant supporting work\n3 outside: outside this goal, no verdict change\n4 uncertain: relevance needs investigation\nu clear: remove current assessment with a reason\nj/k select · PgUp/PgDn read · Home/End reading limits\n[ previous page · ] next page · f filter\nb exact brief · i source/brief receipt · h assessment history\nr refresh same brief · R open latest saved brief\nd resume draft · x review discarding draft\n? close controls · Esc return"
}

fn form_lines(state: &GoalReviewState) -> Vec<String> {
    let Some(form) = &state.form else {
        return Vec::new();
    };
    let mut lines = vec![
        if form.confirming {
            "REVIEW GOAL ASSESSMENT"
        } else {
            "REASON FOR GOAL RELEVANCE"
        }
        .into(),
        form.row.finding.title.clone(),
        format!(
            "{}:{}",
            form.row.finding.file_path, form.row.finding.start_line
        ),
        format!("Relevance: {}", form.relevance.label()),
        format!(
            "Brief: {} v{}",
            form.brief.reference.brief_id, form.brief.reference.revision
        ),
    ];
    lines.push(format!("Reason: {}", form.reason.text()));
    if form.confirming {
        if let Some(previous) = &form.row.assessment {
            lines.push(format!(
                "Replacing assessment v{}: {}. Previous reason: {}",
                previous.revision,
                previous.relevance.label(),
                previous.reason
            ));
        }
        lines.extend(receipt(&form.brief.reference, &form.row));
        lines.push(
            "Save one operator assessment. No model calls, new jobs or finding verdict changes."
                .into(),
        );
    }
    lines.into_iter().map(|line| safe(&line)).collect()
}

fn receipt(
    brief: &kuzushi_core::capabilities::campaign::BriefReference,
    row: &kuzushi_core::findings::FindingGoalRow,
) -> Vec<String> {
    vec![format!("Finding generation #{} · event {}", row.basis.finding_id, row.basis.observation_seq),
        format!("Observed run: {}", row.basis.run_id), format!("Source snapshot: {}", row.basis.snapshot_hash),
        row.source_git.as_ref().map(|git| format!("Observed commit: {} · {}", git.sha, if git.dirty { "dirty" } else { "clean" })).unwrap_or_else(|| "Observed commit: unrecorded or unavailable; snapshot identity remains explicit".into()),
        format!("Brief object: {}", brief.object.hash),
        "This assessment belongs to that recorded observation. Other source revisions need independent review; a missing later observation is not a fix.".into()]
}

pub(crate) fn plain_lines(state: &GoalReviewState) -> Vec<String> {
    let mut lines = vec![heading(state)];
    if !state.editing && !state.discarding {
        if let Some(Ok(page)) = &state.page {
            lines.extend(page.rows.iter().map(|row| {
                format!(
                    "#{} · {} · {} · {}:{}",
                    row.basis.finding_id,
                    row.label(),
                    row.finding.title,
                    row.finding.file_path,
                    row.finding.start_line
                )
            }));
        }
    }
    lines.extend(detail(state));
    if let Some(notice) = &state.notice {
        lines.push(notice.clone());
    }
    lines.push(controls(state).into());
    lines.into_iter().map(|line| safe(&line)).collect()
}

fn safe(text: &str) -> String {
    text.split('\n')
        .map(|line| kuzushi_core::run_lifecycle::SafeText::operator_visible(line).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}
