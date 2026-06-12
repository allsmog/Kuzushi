use super::*;
use crate::ui_view_models::{threat_model_relative_path, ThreatSummaryReview};

pub(super) fn append_summary_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let review = crate::ui_view_models::threat_summary_review(app);

    lines.push(section_header_line("THREAT MODEL REVIEW", area.width));
    append_review_summary(lines, &review, area.width);
    lines.push(blank());

    lines.push(section_header_line("SURFACE", area.width));
    append_surface_rows(lines, &review);
    lines.push(blank());

    lines.push(section_header_line(
        "ASSUMPTIONS / MISSING INPUTS",
        area.width,
    ));
    append_review_list(lines, "assumption", &review.assumptions);
    append_review_list(lines, "missing", &review.missing_inputs);
    lines.push(blank());

    lines.push(section_header_line("PROPOSED CHANGES", area.width));
    append_review_list(lines, "change", &review.proposed_changes);
    lines.push(blank());

    lines.push(section_header_line("ACTIONS", area.width));
    lines.push(detail("approve", "/threats apply"));
    lines.push(detail("regenerate", "/threats regen"));
    lines.push(detail("edit", "/threats edit"));
    lines.push(detail("export", &threat_model_relative_path()));
    lines.push(blank());

    lines.push(section_header_line("EVIDENCE / PROOF LIMITS", area.width));
    append_review_list(lines, "limit", &review.limitations);
}

fn append_review_summary(lines: &mut Vec<Line<'static>>, review: &ThreatSummaryReview, width: u16) {
    lines.push(detail("status", &review.status));
    lines.extend(detail_wrapped("summary", &review.summary, width));
    lines.push(detail("threats", &review.threats));
}

fn append_surface_rows(lines: &mut Vec<Line<'static>>, review: &ThreatSummaryReview) {
    lines.push(detail("assets", &review.assets));
    lines.push(detail("actors", &review.actors));
    lines.push(detail("data flows", &review.flows));
    lines.push(detail("trust boundaries", &review.trust_boundaries));
}

fn append_review_list(lines: &mut Vec<Line<'static>>, label: &str, values: &[String]) {
    if values.is_empty() {
        lines.push(detail(label, "—"));
        return;
    }
    for value in values {
        lines.push(detail(label, value));
    }
}
