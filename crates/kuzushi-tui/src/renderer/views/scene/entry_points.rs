use crate::theme;
use crate::ui_view_models::{EntryPointBreakdown, EntryPointItem};
use ratatui::prelude::{Line, Span};

mod browser;
pub(crate) use browser::EntryPointBrowser;

pub(super) fn entry_point_lines(width: usize, model: &EntryPointBreakdown) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return crate::renderer::empty_state_panel(
            "no entry points",
            &[hint],
            &[
                ("entry-points:extract", "extract concrete ingress surfaces"),
                ("threat-model:build", "model extracted surfaces"),
            ],
        );
    }
    let mut lines = summary_lines(width, model);
    for disposition in &model.dispositions {
        lines.push(Line::from(String::new()));
        lines.push(Line::styled(
            fit(
                &format!(
                    "{} · {}",
                    disposition.name.to_uppercase(),
                    disposition.count
                ),
                width,
            ),
            theme::label(),
        ));
        for (index, entry) in model
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.disposition.label() == disposition.name)
        {
            append_entry(&mut lines, width, index, entry);
        }
    }
    lines
}

fn breakdown_label(model: &EntryPointBreakdown) -> String {
    format!(
        "ENTRY POINTS · {} extracted · {} modeled · {} overlap · {} union",
        model.counts.extracted, model.counts.modeled, model.counts.overlap, model.counts.union,
    )
}

fn responsive_summary(width: usize, model: &EntryPointBreakdown) -> String {
    let full = breakdown_label(model);
    let medium = format!(
        "E {} · M {} · overlap {} · union {}",
        model.counts.extracted, model.counts.modeled, model.counts.overlap, model.counts.union
    );
    let narrow = format!(
        "E{} M{} O{} U{}",
        model.counts.extracted, model.counts.modeled, model.counts.overlap, model.counts.union
    );
    let value = if full.chars().count() <= width {
        full
    } else if medium.chars().count() <= width {
        medium
    } else {
        narrow
    };
    fit(&value, width)
}

fn summary_lines(width: usize, model: &EntryPointBreakdown) -> Vec<Line<'static>> {
    browser_summary_text(width, model)
        .into_iter()
        .enumerate()
        .map(|(index, text)| {
            let style = if index == 0 {
                theme::accent()
            } else {
                theme::muted()
            };
            Line::styled(text, style)
        })
        .collect()
}

fn browser_summary_text(width: usize, model: &EntryPointBreakdown) -> Vec<String> {
    let mut lines = vec![
        responsive_summary(width, model),
        disposition_summary(width, model),
        provenance_summary(width, model),
        receipt_count_summary(width, model),
        revision_summary(width, model),
        digest_summary(width, "C SHA256", model.receipt.catalog_digest.as_deref()),
        digest_summary(
            width,
            "M SHA256",
            model.receipt.model_catalog_digest.as_deref(),
        ),
        paired_digest_summary(
            width,
            "CONTEXT",
            model.receipt.context_digest.as_deref(),
            model.receipt.model_context_digest.as_deref(),
        ),
        paired_digest_summary(
            width,
            "TREE",
            model.receipt.tree_hash.as_deref(),
            model.receipt.model_tree_hash.as_deref(),
        ),
        timestamp_summary(width, model),
    ];
    if !model.receipt.warnings.is_empty() {
        lines.push(fit(
            &format!("WARNING · {}", model.receipt.warnings.join(" · ")),
            width,
        ));
    }
    lines
}

fn disposition_summary(width: usize, model: &EntryPointBreakdown) -> String {
    let full = format!(
        "COVERAGE · modeled {} · deprioritized {} · extracted only {} · model only {}",
        model.counts.overlap,
        model.counts.deprioritized,
        model.counts.unrepresented,
        model.counts.model_only
    );
    let narrow = format!(
        "M{} D{} X{} MO{}",
        model.counts.overlap,
        model.counts.deprioritized,
        model.counts.unrepresented,
        model.counts.model_only
    );
    responsive_value(width, full, narrow)
}

fn provenance_summary(width: usize, model: &EntryPointBreakdown) -> String {
    let full = format!(
        "SOURCE RECEIPT · {} · {} · catalog {} · model {}",
        model.receipt.composition.label(),
        model.receipt.freshness.label(),
        model.receipt.catalog_artifact.label(),
        model.receipt.model_artifact.label()
    );
    let narrow = format!(
        "{} · {} · C:{} M:{}",
        model.receipt.composition.label(),
        model.receipt.freshness.label(),
        model.receipt.catalog_artifact.label(),
        model.receipt.model_artifact.label()
    );
    responsive_value(width, full, narrow)
}

fn receipt_count_summary(width: usize, model: &EntryPointBreakdown) -> String {
    let counts = format!(
        "catalog {} · grounding {}/{} limit · modeled {} · linked {}",
        optional_count(model.receipt.records),
        optional_count(model.receipt.grounding_records_selected),
        optional_count(model.receipt.grounding_limit),
        optional_count(model.receipt.records_selected),
        optional_count(model.receipt.records_linked)
    );
    let status = model.receipt.catalog_status.as_deref().unwrap_or("unknown");
    let policy = model
        .receipt
        .selection_policy
        .as_deref()
        .unwrap_or("unknown");
    responsive_value(
        width,
        format!("RECEIPT · {counts} · status {status} · policy {policy}"),
        format!("{counts} · {status} · {policy}"),
    )
}

fn revision_summary(width: usize, model: &EntryPointBreakdown) -> String {
    let revision = model.receipt.revision.as_deref().unwrap_or("?");
    let dirty = if model.receipt.revision_dirty == Some(true) {
        "+dirty"
    } else {
        ""
    };
    fit(&format!("REVISION · {revision}{dirty}"), width)
}

fn digest_summary(width: usize, label: &str, digest: Option<&str>) -> String {
    let digest = digest.map_or("?", |value| value.trim_start_matches("sha256:"));
    fit(&format!("{label} · {digest}"), width)
}

fn paired_digest_summary(
    width: usize,
    label: &str,
    catalog: Option<&str>,
    model: Option<&str>,
) -> String {
    let catalog = short_digest(catalog);
    let model = short_digest(model);
    fit(&format!("{label} · C {catalog} · M {model}"), width)
}

fn short_digest(digest: Option<&str>) -> &str {
    digest.map_or("?", |value| value.trim_start_matches("sha256:"))
}

fn timestamp_summary(width: usize, model: &EntryPointBreakdown) -> String {
    let snapshot = optional_timestamp(model.receipt.snapshot_timestamp_ms);
    let catalog = optional_timestamp(model.receipt.catalog_timestamp_ms);
    let modeled = optional_timestamp(model.receipt.model_built_at_ms);
    responsive_value(
        width,
        format!("TIMESTAMPS MS · snapshot {snapshot} · catalog {catalog} · model {modeled}"),
        format!("T(ms) S:{snapshot} C:{catalog} M:{modeled}"),
    )
}

fn responsive_value(width: usize, full: String, narrow: String) -> String {
    if full.chars().count() <= width {
        full
    } else {
        fit(&narrow, width)
    }
}

fn optional_count(value: Option<usize>) -> String {
    value.map_or_else(|| "?".to_string(), |value| value.to_string())
}

fn optional_timestamp(value: Option<u64>) -> String {
    value.map_or_else(|| "?".to_string(), |value| value.to_string())
}

fn append_entry(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    index: usize,
    entry: &EntryPointItem,
) {
    lines.push(Line::from(String::new()));
    lines.push(Line::styled(
        fit(
            &format!(
                "{}. [{}] {}",
                index + 1,
                entry.kind.replace('_', " "),
                entry.name
            ),
            width,
        ),
        theme::heading(),
    ));
    lines.extend(entry_detail_lines(width, entry).into_iter().skip(1));
}

fn entry_detail_lines(width: usize, entry: &EntryPointItem) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(fit(&entry.name, width), theme::heading())];
    append_field(&mut lines, width, "kind", &entry.kind.replace('_', " "));
    append_field(&mut lines, width, "state", entry.disposition.label());
    append_optional_field(&mut lines, width, "decision", &entry.disposition_note, "");
    append_field(
        &mut lines,
        width,
        "zone",
        &entry.trust_zone.replace('_', " "),
    );
    append_optional_field(
        &mut lines,
        width,
        "ingress",
        &entry.ingress,
        "not specified",
    );
    append_optional_field(&mut lines, width, "summary", &entry.description, "");
    if let Some(source) = entry.recorded_source() {
        append_field(&mut lines, width, "source", source);
    }
    append_optional_field(&mut lines, width, "risk", &entry.risk, "");
    append_targets(&mut lines, width, entry);
    append_optional_field(&mut lines, width, "evidence", &entry.evidence, "");
    append_field(&mut lines, width, "id", &entry.id);
    lines
}

fn append_targets(lines: &mut Vec<Line<'static>>, width: usize, entry: &EntryPointItem) {
    let mut targets = entry
        .targets
        .iter()
        .map(|target| target.label.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    if entry.unresolved_target_count > 0 {
        let separator = if targets.is_empty() { "" } else { "; " };
        targets.push_str(&format!(
            "{separator}+{} unresolved",
            entry.unresolved_target_count
        ));
    }
    append_optional_field(lines, width, "targets", &targets, "");
}

fn append_optional_field(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    key: &str,
    value: &str,
    omitted_value: &str,
) {
    if value.is_empty() || value == omitted_value {
        return;
    }
    append_field(lines, width, key, value);
}

fn append_field(lines: &mut Vec<Line<'static>>, width: usize, key: &str, value: &str) {
    let key_width = width.saturating_sub(1).min(11);
    let value_width = width.saturating_sub(key_width).max(1);
    for (index, chunk) in crate::renderer::shared::text::wrap_text(value, value_width)
        .into_iter()
        .enumerate()
    {
        let label = if index == 0 {
            format!("{key:<key_width$}")
        } else {
            " ".repeat(key_width)
        };
        lines.push(Line::from(vec![
            Span::styled(label, theme::muted()),
            Span::styled(chunk, theme::primary()),
        ]));
    }
}

fn fit(value: &str, width: usize) -> String {
    crate::renderer::shared::text::fit(value, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{
        EntryPointArtifactStatus, EntryPointComposition, EntryPointCounts, EntryPointDisposition,
        EntryPointFreshness, EntryPointGroup, EntryPointReceipt, EntryPointTarget,
    };

    #[test]
    fn entry_point_plain_breakdown_stays_within_narrow_width() {
        let model = sample_model();

        let lines = entry_point_lines(32, &model);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("E 1 · M 1 · overlap 1 · union 1"), "{text}");
        assert!(text.contains("MODELED"), "{text}");
        assert!(text.contains("http route"), "{text}");
        assert!(text.contains("Share API"), "{text}");
        assert!(lines.iter().all(|line| line.width() <= 32));
    }

    #[test]
    fn receipt_summary_separates_grounding_from_modeled_coverage() {
        let mut model = sample_model();
        model.receipt.records = Some(519);
        model.receipt.grounding_records_selected = Some(100);
        model.receipt.grounding_limit = Some(100);
        model.receipt.records_selected = Some(16);
        model.receipt.records_linked = Some(7);

        let summary = receipt_count_summary(160, &model);

        assert!(summary.contains("catalog 519"), "{summary}");
        assert!(summary.contains("grounding 100/100 limit"), "{summary}");
        assert!(summary.contains("modeled 16"), "{summary}");
        assert!(summary.contains("linked 7"), "{summary}");
    }

    fn sample_model() -> EntryPointBreakdown {
        EntryPointBreakdown {
            entries: vec![EntryPointItem {
                id: "EP-1".into(),
                name: "POST /admin".into(),
                kind: "http_route".into(),
                trust_zone: "internet".into(),
                description: "Administrative route".into(),
                ingress: "POST /admin".into(),
                source: "src/routes.rs:42".into(),
                evidence: "route registration with authorization middleware".into(),
                risk: "high · score 78".into(),
                disposition: EntryPointDisposition::Modeled,
                disposition_note: "catalog row linked to current threat-model context".into(),
                targets: vec![EntryPointTarget {
                    id: "N1".into(),
                    label: "N1 Share API · cloud_function".into(),
                }],
                unresolved_target_count: 0,
            }],
            kinds: vec![EntryPointGroup {
                name: "http_route".into(),
                count: 1,
            }],
            zones: vec![EntryPointGroup {
                name: "internet".into(),
                count: 1,
            }],
            dispositions: vec![EntryPointGroup {
                name: "modeled".into(),
                count: 1,
            }],
            counts: EntryPointCounts {
                extracted: 1,
                modeled: 1,
                overlap: 1,
                union: 1,
                ..Default::default()
            },
            receipt: EntryPointReceipt {
                catalog_artifact: EntryPointArtifactStatus::Ready,
                model_artifact: EntryPointArtifactStatus::Ready,
                composition: EntryPointComposition::Current,
                freshness: EntryPointFreshness::Current,
                ..Default::default()
            },
            linked_target_count: 1,
            target_count: 1,
            empty_hint: None,
        }
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }
}
