use super::*;

pub(in crate::renderer) fn threat_lines(
    app: &ShellApp,
    area: Rect,
    view: ThreatView,
) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(threat_nav(view));
    lines.push(blank());

    match view {
        ThreatView::Dfd => {
            lines.push(section_header_line("DFD · acme-checkout", area.width));
            lines.extend(dfd_canonical_lines());
            if let Some(doc) = current_threat_model_doc(app) {
                if let Some(nodes) = dfd_nodes_from_doc(&doc) {
                    lines.push(blank());
                    lines.push(section_header_line(
                        &format!("NODES FROM threat-model.json · {}", nodes.len()),
                        area.width,
                    ));
                    for (id, node_type, zone) in nodes.into_iter().take(8) {
                        lines.push(Line::from(vec![
                            Span::raw("   "),
                            Span::styled(pad(&id, 24), theme::accent()),
                            Span::styled(pad(&node_type, 16), theme::muted()),
                            Span::styled(zone, theme::subtle()),
                        ]));
                    }
                }
            }
        }
        ThreatView::Stride => {
            let doc = current_threat_model_doc(app);
            let rollup = doc
                .as_ref()
                .and_then(stride_rollup_from_doc)
                .unwrap_or_else(stride_rollup_rows);
            let total_issues: usize = rollup.iter().map(|r| r.3).sum();
            lines.push(section_header_line(
                &format!("STRIDE ROLLUP · {total_issues} issues"),
                area.width,
            ));
            for (letter, sev, category, count, description) in &rollup {
                lines.push(stride_row(
                    letter,
                    *sev,
                    category,
                    *count,
                    description,
                    area.width,
                ));
            }
        }
        ThreatView::Stories => {
            let doc = current_threat_model_doc(app);
            let stories = doc
                .as_ref()
                .and_then(stories_from_doc)
                .unwrap_or_else(canonical_stories_fixture);
            lines.push(section_header_line(
                &format!("ATTACKER STORIES · {}", stories.len()),
                area.width,
            ));
            for (id, severity, title, attack, location) in stories.into_iter().take(8) {
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled("▸ ", theme::warn()),
                    Span::styled(pad(&id, 8), theme::accent()),
                    Span::styled(
                        pad(&severity.as_str().to_uppercase(), 9),
                        theme::severity(severity),
                    ),
                    Span::styled(title, theme::primary()),
                ]));
                if !attack.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("              "),
                        Span::styled("attack ", theme::subtle()),
                        Span::styled(attack, theme::muted()),
                    ]));
                }
                if !location.is_empty() {
                    lines.push(Line::from(vec![
                        Span::raw("              "),
                        Span::styled("loc    ", theme::subtle()),
                        Span::styled(location, theme::muted()),
                    ]));
                }
            }
        }
        ThreatView::Scope => {
            let doc = current_threat_model_doc(app);
            let buckets = doc
                .as_ref()
                .and_then(scope_buckets_from_doc)
                .unwrap_or_else(canonical_scope_buckets);
            let total: usize = buckets.iter().map(|(_, _, items)| items.len()).sum();
            lines.push(section_header_line(
                &format!("SCOPE · {total} issues"),
                area.width,
            ));
            for (severity, label, items) in &buckets {
                if items.is_empty() {
                    continue;
                }
                lines.push(Line::from(vec![
                    Span::raw("   "),
                    Span::styled(
                        format!("{} · {}", label.to_uppercase(), items.len()),
                        theme::severity(*severity),
                    ),
                ]));
                for item in items.iter().take(4) {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled("• ", theme::subtle()),
                        Span::styled(item.clone(), theme::muted()),
                    ]));
                }
                if items.len() > 4 {
                    lines.push(Line::from(vec![
                        Span::raw("      "),
                        Span::styled(format!("… {} more", items.len() - 4), theme::subtle()),
                    ]));
                }
            }
            lines.push(blank());
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled("OUT OF SCOPE", theme::muted()),
            ]));
            lines.push(Line::from(vec![
                Span::raw("      "),
                Span::styled("• ", theme::subtle()),
                Span::styled("generated caches, vendored fixtures", theme::muted()),
            ]));
        }
        ThreatView::Summary => {
            let doc = current_threat_model_doc(app);
            let rollup = doc
                .as_ref()
                .and_then(stride_rollup_from_doc)
                .unwrap_or_else(stride_rollup_rows);
            let total_issues: usize = rollup.iter().map(|r| r.3).sum();
            lines.push(section_header_line(
                &format!("THREAT MODEL · {total_issues} issues"),
                area.width,
            ));
            for (letter, sev, category, count, description) in &rollup {
                lines.push(stride_row(
                    letter,
                    *sev,
                    category,
                    *count,
                    description,
                    area.width,
                ));
            }
            lines.push(blank());
            lines.push(transcript_line(
                "agent",
                "biggest delta from last model: admin.acme-checkout.com shares the jwt secret.",
                false,
            ));
            lines.push(transcript_line(
                "flow",
                "recommend split signing keys + audience claim",
                false,
            ));
            lines.push(transcript_line(
                "log",
                "artifact .kuzushi/threat-model.json (proposed v4 · +12 −3)",
                false,
            ));
        }
    }

    lines
}

pub(in crate::renderer) fn threat_editor_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("THREAT MODEL EDIT", area.width));
    lines.push(detail("artifact", ".kuzushi/threat-model.json"));
    lines.push(detail("mode", "operator edits"));
    lines.push(detail("sections", "elements, boundaries, stories, scope"));
    lines
}
